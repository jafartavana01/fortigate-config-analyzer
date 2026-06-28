#!/usr/bin/env python3
"""
fortigate_Analyzer.py — FortiGate Configuration Security Analyzer
Usage: python fortigate_Analyzer.py <config_file.conf>

Analyzes a FortiGate configuration export and produces four output files:
  <name>_tree.txt       — Visual config tree of every block
  <name>_firewall.txt   — Firewall rules in hierarchical detail
  <name>_analysis.txt   — Full per-subsystem security analysis
  <name>_summary.txt    — Executive summary with overall risk score
"""

import sys
import os
import re
import json
from datetime import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — PARSER
# Generic FortiGate config block parser. Handles nested config/edit/next/end.
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ConfigBlock:
    """A single parsed config block: either a 'config path' section or an 'edit name' entry."""
    block_type: str          # 'config' | 'edit' | 'root'
    name: str                # path (for config) or quoted name (for edit)
    settings: dict           # {key: value} from 'set' lines
    children: list           # list[ConfigBlock] — nested config/edit blocks
    raw_lines: list          # raw text lines exactly as they appeared
    parent_path: str = ""    # dotted path like "firewall.policy"
    line_start: int = 0
    line_end: int = 0

    def get(self, key: str, default: str = "") -> str:
        return self.settings.get(key.lower(), default)

    def has(self, key: str) -> bool:
        return key.lower() in self.settings

    def get_child_block(self, name: str) -> "ConfigBlock | None":
        for c in self.children:
            if c.name.lower() == name.lower():
                return c
        return None

    def get_edit_entries(self) -> list:
        return [c for c in self.children if c.block_type == "edit"]

    def get_config_children(self) -> list:
        return [c for c in self.children if c.block_type == "config"]


def _strip_quotes(value: str) -> str:
    v = value.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v


def _parse_set_line(line: str) -> tuple[str, str] | None:
    m = re.match(r'^\s*set\s+(\S+)\s*(.*)', line)
    if not m:
        return None
    key = m.group(1).lower()
    val = m.group(2).strip()
    return (key, _strip_quotes(val))


def parse_config(text: str) -> ConfigBlock:
    """
    Parse raw FortiGate config text into a tree of ConfigBlock objects.
    Returns a synthetic root block whose children are the top-level config sections.
    """
    lines = text.splitlines()
    root = ConfigBlock("root", "root", {}, [], lines[:], "", 0, len(lines))

    def parse_block(idx: int, parent_path: str) -> tuple[ConfigBlock | None, int]:
        """Recursively parse one config or edit block starting at idx."""
        if idx >= len(lines):
            return None, idx

        line = lines[idx].strip()

        # config <path...>
        m_config = re.match(r'^config\s+(.*)', line)
        # edit "<name>" or edit <num>
        m_edit = re.match(r'^edit\s+(.*)', line)

        if m_config:
            path = m_config.group(1).strip()
            full_path = (parent_path + "." + path).lstrip(".")
            block = ConfigBlock("config", path, {}, [], [], full_path, idx + 1, 0)
            block.raw_lines = [lines[idx]]
            idx += 1
            depth = 1
            while idx < len(lines) and depth > 0:
                raw = lines[idx]
                t = raw.strip()
                block.raw_lines.append(raw)
                if t.startswith("config ") or t.startswith("edit "):
                    # recurse into child
                    child, idx = parse_block(idx, full_path)
                    if child:
                        block.children.append(child)
                    depth_change = 0
                    # depth only changes for config/end pairs at this level
                    # actual depth tracking is inside recurse; re-check after
                    continue
                elif t.startswith("end"):
                    depth -= 1
                elif t.startswith("set "):
                    kv = _parse_set_line(raw)
                    if kv:
                        block.settings[kv[0]] = kv[1]
                idx += 1
            block.line_end = idx
            return block, idx

        elif m_edit:
            name = _strip_quotes(m_edit.group(1).strip())
            full_path = (parent_path + ".edit." + name).lstrip(".")
            block = ConfigBlock("edit", name, {}, [], [], full_path, idx + 1, 0)
            block.raw_lines = [lines[idx]]
            idx += 1
            while idx < len(lines):
                raw = lines[idx]
                t = raw.strip()
                block.raw_lines.append(raw)
                if t == "next":
                    idx += 1
                    break
                elif t.startswith("config "):
                    child, idx = parse_block(idx, full_path)
                    if child:
                        block.children.append(child)
                    continue
                elif t.startswith("set "):
                    kv = _parse_set_line(raw)
                    if kv:
                        block.settings[kv[0]] = kv[1]
                idx += 1
            block.line_end = idx
            return block, idx

        return None, idx + 1

    idx = 0
    while idx < len(lines):
        t = lines[idx].strip()
        if t.startswith("config "):
            block, idx = parse_block(idx, "")
            if block:
                root.children.append(block)
        else:
            idx += 1

    return root


def find_blocks(root: ConfigBlock, path_prefix: str) -> list:
    """Find all config blocks whose name starts with path_prefix (case-insensitive)."""
    results = []
    target = path_prefix.lower()

    def walk(block: ConfigBlock):
        if block.block_type == "config" and block.name.lower().startswith(target):
            results.append(block)
        for child in block.children:
            walk(child)

    walk(root)
    return results


def find_block(root: ConfigBlock, exact_path: str) -> ConfigBlock | None:
    """Find the first config block with exactly this name (case-insensitive)."""
    target = exact_path.lower()

    def walk(block: ConfigBlock) -> ConfigBlock | None:
        if block.block_type == "config" and block.name.lower() == target:
            return block
        for child in block.children:
            r = walk(child)
            if r:
                return r
        return None

    return walk(root)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — FINDING MODEL
# ═══════════════════════════════════════════════════════════════════════════════

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH     = "HIGH"
SEVERITY_MEDIUM   = "MEDIUM"
SEVERITY_LOW      = "LOW"
SEVERITY_INFO     = "INFO"

SEVERITY_ORDER = {SEVERITY_CRITICAL: 0, SEVERITY_HIGH: 1,
                  SEVERITY_MEDIUM: 2, SEVERITY_LOW: 3, SEVERITY_INFO: 4}
SEVERITY_ICONS = {SEVERITY_CRITICAL: "✖", SEVERITY_HIGH: "⚠",
                  SEVERITY_MEDIUM: "◆", SEVERITY_LOW: "●", SEVERITY_INFO: "ℹ"}


@dataclass
class Finding:
    subsystem: str
    severity: str
    title: str
    detail: str
    remediation: str
    context: str = ""       # e.g. policy id or profile name
    cve_refs: list = field(default_factory=list)


@dataclass
class SubsystemReport:
    name: str
    display_name: str
    present: bool
    findings: list = field(default_factory=list)
    info_items: list = field(default_factory=list)  # purely informational, no severity
    score: float = 10.0     # starts at 10, deductions applied per finding


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — SUBSYSTEM ANALYZERS
# Each analyzer takes the parsed root and returns a SubsystemReport.
# ═══════════════════════════════════════════════════════════════════════════════

def _f(subsystem: str, severity: str, title: str, detail: str,
        remediation: str, context: str = "") -> Finding:
    return Finding(subsystem, severity, title, detail, remediation, context)


# ── 3.1 System Global ───────────────────────────────────────────────────────

def analyze_system_global(root: ConfigBlock) -> SubsystemReport:
    r = SubsystemReport("system_global", "System › Global Settings", False, [], [])
    b = find_block(root, "system global")
    if not b:
        return r
    r.present = True
    s = b.settings
    sid = "system_global"

    hostname = s.get("hostname", "(not set)")
    r.info_items.append(f"Hostname: {hostname}")

    # Admin timeout
    timeout = int(s.get("admintimeout", "0") or 0)
    if timeout == 0:
        r.findings.append(_f(sid, SEVERITY_HIGH, "Admin timeout not set",
            "No admin session timeout configured. Unattended admin sessions remain active indefinitely.",
            "config system global\n    set admintimeout 15\nend"))
    elif timeout > 60:
        r.findings.append(_f(sid, SEVERITY_MEDIUM, f"Admin timeout too long ({timeout} min)",
            f"Admin session timeout is {timeout} minutes. Recommend ≤15 minutes for non-jump-server access.",
            f"config system global\n    set admintimeout 15\nend"))
    else:
        r.info_items.append(f"Admin timeout: {timeout} min (OK)")

    # Strong crypto
    if s.get("strong-crypto", "disable") != "enable":
        r.findings.append(_f(sid, SEVERITY_HIGH, "Strong crypto not enforced",
            "strong-crypto is not enabled. Weak cipher suites may be available for admin TLS sessions.",
            "config system global\n    set strong-crypto enable\nend"))

    # SSH CBC cipher
    if s.get("ssh-cbc-cipher", "enable") != "disable":
        r.findings.append(_f(sid, SEVERITY_MEDIUM, "SSH CBC ciphers not disabled",
            "CBC-mode SSH ciphers are permitted for admin SSH access. CBC mode is vulnerable to "
            "certain plaintext-recovery attacks.",
            "config system global\n    set ssh-cbc-cipher disable\nend"))

    # SSH HMAC-MD5
    if s.get("ssh-hmac-md5", "enable") != "disable":
        r.findings.append(_f(sid, SEVERITY_MEDIUM, "SSH HMAC-MD5 not disabled",
            "HMAC-MD5 is permitted for admin SSH sessions. MD5 is cryptographically broken.",
            "config system global\n    set ssh-hmac-md5 disable\nend"))

    # Admin HTTPS TLS version
    ssl_vers = s.get("admin-https-ssl-versions", "")
    if "tlsv1-0" in ssl_vers or "tlsv1-1" in ssl_vers:
        r.findings.append(_f(sid, SEVERITY_HIGH, "Admin HTTPS allows legacy TLS",
            f"Admin HTTPS is configured to allow TLS 1.0 or 1.1 ({ssl_vers}). These versions "
            "have known weaknesses (BEAST, POODLE).",
            "config system global\n    set admin-https-ssl-versions tlsv1-2 tlsv1-3\nend"))
    elif not ssl_vers:
        r.findings.append(_f(sid, SEVERITY_MEDIUM, "Admin HTTPS TLS versions not explicitly set",
            "Admin HTTPS TLS versions are not explicitly constrained. Default may allow legacy versions.",
            "config system global\n    set admin-https-ssl-versions tlsv1-2 tlsv1-3\nend"))
    else:
        r.info_items.append(f"Admin HTTPS TLS: {ssl_vers}")

    # Lockout policy
    threshold = int(s.get("admin-lockout-threshold", "5") or 5)
    duration  = int(s.get("admin-lockout-duration",  "0") or 0)
    if threshold > 5:
        r.findings.append(_f(sid, SEVERITY_MEDIUM, f"Admin lockout threshold too high ({threshold})",
            f"Account lockout triggers after {threshold} failed attempts. Recommend ≤5.",
            "config system global\n    set admin-lockout-threshold 3\nend"))
    if duration < 60:
        r.findings.append(_f(sid, SEVERITY_LOW,
            f"Admin lockout duration too short ({duration}s)",
            f"Lockout lasts only {duration} seconds. Recommend ≥300 seconds to slow brute-force.",
            "config system global\n    set admin-lockout-duration 300\nend"))
    else:
        r.info_items.append(f"Admin lockout: {threshold} attempts / {duration}s")

    # Alias / banner
    if not s.get("alias", ""):
        r.findings.append(_f(sid, SEVERITY_INFO, "No device alias configured",
            "Setting an alias helps identify this device in management dashboards and logs.",
            "config system global\n    set alias \"SITE-FW-01\"\nend"))

    return r


# ── 3.2 System Interface ────────────────────────────────────────────────────

def analyze_system_interface(root: ConfigBlock) -> SubsystemReport:
    r = SubsystemReport("system_interface", "System › Interfaces", False, [], [])
    b = find_block(root, "system interface")
    if not b:
        return r
    r.present = True
    sid = "system_interface"

    INSECURE_ACCESS = {"http", "telnet", "ftp", "snmp"}
    WAN_DANGEROUS   = {"http", "telnet", "ssh", "ftp", "ping", "snmp"}

    for entry in b.get_edit_entries():
        iface = entry.name
        role  = entry.get("role", "undefined")
        aa    = entry.get("allowaccess", "").lower()
        access_set = set(aa.split()) if aa else set()
        ip    = entry.get("ip", "")

        r.info_items.append(f"Interface {iface}: role={role} ip={ip} allowaccess={aa or '(none)'}")

        # Insecure protocols on any interface
        insecure = access_set & INSECURE_ACCESS
        if insecure:
            r.findings.append(_f(sid, SEVERITY_HIGH,
                f"Interface {iface}: insecure management protocols enabled",
                f"The protocols {sorted(insecure)} are enabled on {iface}. These transmit "
                "credentials in cleartext (HTTP, Telnet) or have known weaknesses (FTP).",
                f"config system interface\n    edit \"{iface}\"\n"
                f"        set allowaccess {' '.join(sorted(access_set - INSECURE_ACCESS)) or 'ping'}\n"
                f"    next\nend",
                context=iface))

        # WAN interface with SSH/ping exposed
        if role == "wan":
            dangerous = access_set & WAN_DANGEROUS
            if dangerous:
                r.findings.append(_f(sid, SEVERITY_HIGH,
                    f"WAN interface {iface} exposes management services to the internet",
                    f"The following services are accessible directly from the WAN: "
                    f"{sorted(dangerous)}. This dramatically increases attack surface.",
                    f"config system interface\n    edit \"{iface}\"\n"
                    f"        set allowaccess ping\n    next\nend — "
                    f"then restrict management via local-in policy to trusted source IPs.",
                    context=iface))

        # No access restriction at all on physical interface
        if not aa and entry.get("type", "") == "physical":
            r.findings.append(_f(sid, SEVERITY_LOW,
                f"Interface {iface}: no allowaccess set",
                "No management access configured. Confirm this is intentional.",
                f"config system interface\n    edit \"{iface}\"\n"
                f"        set allowaccess ping\n    next\nend",
                context=iface))

    return r


# ── 3.3 System Admin ────────────────────────────────────────────────────────

def analyze_system_admin(root: ConfigBlock) -> SubsystemReport:
    r = SubsystemReport("system_admin", "System › Admin Accounts", False, [], [])
    b = find_block(root, "system admin")
    if not b:
        return r
    r.present = True
    sid = "system_admin"

    entries = b.get_edit_entries()
    r.info_items.append(f"Admin accounts defined: {len(entries)}")

    has_default_admin = False
    for entry in entries:
        name    = entry.name
        profile = entry.get("accprofile", "")
        twofac  = entry.get("two-factor", "disable")
        vdom    = entry.get("vdom", "")

        r.info_items.append(f"  Account: {name!r}  profile={profile}  2FA={twofac}  vdom={vdom}")

        if name.lower() == "admin":
            has_default_admin = True
            r.findings.append(_f(sid, SEVERITY_HIGH,
                "Default 'admin' account exists",
                "The factory-default 'admin' account is a known target for credential attacks. "
                "Rename or disable it and create a named account instead.",
                "config system admin\n    edit \"admin\"\n        set accprofile \"no_access\"\n"
                "    next\nend  — then create a renamed super-admin account.",
                context="admin"))

        if profile == "super_admin" and twofac in ("disable", ""):
            r.findings.append(_f(sid, SEVERITY_CRITICAL,
                f"Super-admin account '{name}' has no 2FA",
                f"The account '{name}' has super_admin privileges without two-factor authentication. "
                "A compromised password would give full firewall control.",
                f"config system admin\n    edit \"{name}\"\n"
                f"        set two-factor email\n        set email-to \"admin@example.com\"\n"
                f"    next\nend",
                context=name))

        if twofac in ("disable", "") and profile not in ("readonly", "no_access"):
            if name.lower() != "admin":  # already reported above
                r.findings.append(_f(sid, SEVERITY_HIGH,
                    f"Admin account '{name}' has no 2FA",
                    f"Account '{name}' (profile: {profile}) does not require two-factor authentication.",
                    f"config system admin\n    edit \"{name}\"\n"
                    f"        set two-factor email\n    next\nend",
                    context=name))

    return r


# ── 3.4 Password Policy ─────────────────────────────────────────────────────

def analyze_password_policy(root: ConfigBlock) -> SubsystemReport:
    r = SubsystemReport("password_policy", "System › Password Policy", False, [], [])
    b = find_block(root, "system password-policy")
    if not b:
        r.findings.append(_f("password_policy", SEVERITY_HIGH,
            "No password policy configured",
            "No system password-policy block found. Default FortiGate behavior requires no minimum "
            "password complexity or expiry.",
            "config system password-policy\n    set status enable\n    set minimum-length 12\n"
            "    set min-lower-case-letter 1\n    set min-upper-case-letter 1\n"
            "    set min-non-alphanumeric 1\n    set expire-day 90\nend"))
        return r
    r.present = True
    sid = "password_policy"
    s = b.settings

    if s.get("status", "disable") != "enable":
        r.findings.append(_f(sid, SEVERITY_HIGH, "Password policy is disabled",
            "The password policy block exists but is disabled.",
            "config system password-policy\n    set status enable\nend"))
        return r

    min_len = int(s.get("minimum-length", "0") or 0)
    if min_len < 12:
        r.findings.append(_f(sid, SEVERITY_MEDIUM,
            f"Password minimum length too short ({min_len})",
            f"Minimum password length is {min_len}. NIST SP 800-63B recommends ≥12 characters "
            "for user-chosen secrets.",
            "config system password-policy\n    set minimum-length 12\nend"))
    else:
        r.info_items.append(f"Min length: {min_len} (OK)")

    if int(s.get("min-upper-case-letter", "0") or 0) == 0:
        r.findings.append(_f(sid, SEVERITY_LOW, "No uppercase letter requirement",
            "Password policy does not require uppercase letters.",
            "config system password-policy\n    set min-upper-case-letter 1\nend"))
    if int(s.get("min-non-alphanumeric", "0") or 0) == 0:
        r.findings.append(_f(sid, SEVERITY_LOW, "No special character requirement",
            "Password policy does not require special characters.",
            "config system password-policy\n    set min-non-alphanumeric 1\nend"))

    expire = int(s.get("expire-day", "0") or 0)
    if expire == 0:
        r.findings.append(_f(sid, SEVERITY_MEDIUM, "Password expiry not configured",
            "Passwords never expire. Recommend 90-day rotation for admin accounts.",
            "config system password-policy\n    set expire-day 90\nend"))
    elif expire > 180:
        r.findings.append(_f(sid, SEVERITY_LOW,
            f"Password expiry too long ({expire} days)",
            f"Passwords expire after {expire} days. Recommend ≤90 days.",
            "config system password-policy\n    set expire-day 90\nend"))
    else:
        r.info_items.append(f"Password expiry: {expire} days")

    return r


# ── 3.5 DNS ─────────────────────────────────────────────────────────────────

def analyze_dns(root: ConfigBlock) -> SubsystemReport:
    r = SubsystemReport("dns", "System › DNS", False, [], [])
    b = find_block(root, "system dns")
    if not b:
        return r
    r.present = True
    sid = "dns"
    s = b.settings

    PUBLIC_DNS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222"}
    primary   = s.get("primary", "")
    secondary = s.get("secondary", "")
    r.info_items.append(f"Primary DNS: {primary}  Secondary: {secondary}")

    if primary in PUBLIC_DNS or secondary in PUBLIC_DNS:
        r.findings.append(_f(sid, SEVERITY_LOW,
            "Using public DNS resolvers",
            f"DNS is configured to use public resolvers ({primary}, {secondary}). "
            "Public resolvers may log queries and are outside your security perimeter. "
            "Consider an internal resolver with DNS filtering and logging.",
            "config system dns\n    set primary <internal-dns-ip>\n    set secondary <secondary-dns-ip>\nend"))

    if not primary:
        r.findings.append(_f(sid, SEVERITY_MEDIUM, "No primary DNS configured",
            "No DNS primary server configured. Name resolution will fail.",
            "config system dns\n    set primary <dns-server-ip>\nend"))

    return r


# ── 3.6 NTP ─────────────────────────────────────────────────────────────────

def analyze_ntp(root: ConfigBlock) -> SubsystemReport:
    r = SubsystemReport("ntp", "System › NTP", False, [], [])
    b = find_block(root, "system ntp")
    if not b:
        r.findings.append(_f("ntp", SEVERITY_MEDIUM, "NTP not configured",
            "No NTP configuration found. Accurate time is required for log correlation, "
            "certificate validation, and security event forensics.",
            "config system ntp\n    set ntpsync enable\n    set type custom\n"
            "    config ntpserver\n        edit 1\n            set server \"pool.ntp.org\"\n"
            "        next\n    end\nend"))
        return r
    r.present = True
    sid = "ntp"
    s = b.settings

    if s.get("ntpsync", "disable") != "enable":
        r.findings.append(_f(sid, SEVERITY_MEDIUM, "NTP synchronization is disabled",
            "NTP is configured but ntpsync is disabled. Clock drift will occur.",
            "config system ntp\n    set ntpsync enable\nend"))
    else:
        r.info_items.append("NTP sync: enabled")

    servers = b.get_child_block("ntpserver")
    if not servers or not servers.get_edit_entries():
        r.findings.append(_f(sid, SEVERITY_LOW, "No NTP servers defined",
            "NTP sync is enabled but no server addresses are configured.",
            "config system ntp\n    config ntpserver\n        edit 1\n"
            "            set server \"pool.ntp.org\"\n        next\n    end\nend"))

    return r


# ── 3.7 SNMP ────────────────────────────────────────────────────────────────

def analyze_snmp(root: ConfigBlock) -> SubsystemReport:
    r = SubsystemReport("snmp", "System › SNMP", False, [], [])
    b = find_block(root, "system snmp community")
    if not b:
        r.info_items.append("SNMP community strings: none configured")
        return r
    r.present = True
    sid = "snmp"

    WEAK_COMMUNITY = {"public", "private", "community", "snmp", "default", "test"}

    for entry in b.get_edit_entries():
        name   = entry.get("name", "(empty)")
        status = entry.get("status", "disable")
        hosts  = entry.get_child_block("hosts")

        r.info_items.append(f"SNMP community: {name!r}  status={status}")

        if name.lower() in WEAK_COMMUNITY:
            r.findings.append(_f(sid, SEVERITY_CRITICAL,
                f"Weak/default SNMP community string: '{name}'",
                f"Community string '{name}' is a well-known default. Attackers routinely "
                "scan for these and can extract device configuration and routing tables via SNMP.",
                f"config system snmp community\n    edit <id>\n"
                f"        set name \"<strong-random-string>\"\n    next\nend",
                context=name))

        if status == "enable" and (not hosts or not hosts.get_edit_entries()):
            r.findings.append(_f(sid, SEVERITY_HIGH,
                f"SNMP community '{name}' has no host restrictions",
                "SNMP is enabled with no source IP restrictions. Any host can query this device.",
                f"config system snmp community\n    edit <id>\n"
                f"        config hosts\n            edit 1\n"
                f"                set ip <mgmt-host-ip> 255.255.255.255\n"
                f"            next\n        end\n    next\nend",
                context=name))

    return r


# ── 3.8 High Availability ───────────────────────────────────────────────────

def analyze_ha(root: ConfigBlock) -> SubsystemReport:
    r = SubsystemReport("ha", "System › High Availability", False, [], [])
    b = find_block(root, "system ha")
    if not b:
        r.info_items.append("HA: not configured (standalone mode)")
        return r
    r.present = True
    sid = "ha"
    s = b.settings

    mode = s.get("mode", "standalone")
    r.info_items.append(f"HA mode: {mode}  group: {s.get('group-name', '?')}")

    if mode == "standalone":
        r.findings.append(_f(sid, SEVERITY_LOW, "Device is in standalone mode (no HA)",
            "No high-availability configured. A hardware or software failure will cause a "
            "complete outage with no automatic failover.",
            "Consider configuring active-passive HA with a secondary unit:\n"
            "config system ha\n    set mode a-p\n    set group-name \"FW-CLUSTER\"\n"
            "    set password <ha-password>\n    set hbdev \"ha1\" 100\nend"))

    if mode in ("a-p", "a-a") and not s.get("password", ""):
        r.findings.append(_f(sid, SEVERITY_HIGH, "HA cluster has no password",
            "HA heartbeat is not protected by a password. An attacker on the same segment "
            "could inject false HA packets.",
            "config system ha\n    set password <strong-password>\nend"))

    return r


# ── 3.9 Firewall Policy ─────────────────────────────────────────────────────

def analyze_firewall_policy(root: ConfigBlock) -> SubsystemReport:
    r = SubsystemReport("firewall_policy", "Firewall › Policy Rules", False, [], [])
    b = find_block(root, "firewall policy")
    if not b:
        return r
    r.present = True
    sid = "firewall_policy"

    entries = b.get_edit_entries()
    r.info_items.append(f"Firewall policies defined: {len(entries)}")

    any_addrs = {"all", "any", "0.0.0.0", "0.0.0.0/0"}

    for entry in entries:
        pid  = entry.name
        name = entry.get("name", f"policy-{pid}")
        srcaddr  = entry.get("srcaddr", "").lower()
        dstaddr  = entry.get("dstaddr", "").lower()
        srcintf  = entry.get("srcintf", "")
        dstintf  = entry.get("dstintf", "")
        action   = entry.get("action", "deny")
        service  = entry.get("service", "").lower()
        log      = entry.get("logtraffic", "disable")
        utm      = entry.get("utm-status", "disable")
        av       = entry.get("av-profile", "")
        ips_s    = entry.get("ips-sensor", "")
        nat      = entry.get("nat", "disable")
        ctx      = f"Policy {pid} ({name!r})"

        r.info_items.append(f"  Policy {pid}: {name!r}  {srcintf}→{dstintf}  "
                            f"src={srcaddr} dst={dstaddr}  action={action}  log={log}")

        if action != "accept":
            continue  # deny rules are fine, skip further checks

        # No logging
        if log == "disable":
            r.findings.append(_f(sid, SEVERITY_HIGH,
                f"Policy {pid} ({name!r}): logging disabled",
                f"Accepted traffic through policy {pid} is not logged. This creates a blind spot "
                "in your security monitoring and makes incident investigation impossible.",
                f"config firewall policy\n    edit {pid}\n"
                f"        set logtraffic all\n    next\nend",
                context=ctx))

        # Any-to-Any overly broad rules
        if srcaddr in any_addrs and dstaddr in any_addrs and service in ("all", "any"):
            r.findings.append(_f(sid, SEVERITY_CRITICAL,
                f"Policy {pid} ({name!r}): overly broad ANY-ANY-ANY rule",
                f"Policy {pid} permits any source, any destination, any service. "
                "This is functionally a firewall bypass for all traffic matching the interface pair.",
                f"config firewall policy\n    edit {pid}\n"
                f"        set srcaddr <specific-source-object>\n"
                f"        set dstaddr <specific-destination-object>\n"
                f"        set service <specific-services>\n    next\nend",
                context=ctx))

        # Any source address
        elif srcaddr in any_addrs:
            r.findings.append(_f(sid, SEVERITY_HIGH,
                f"Policy {pid} ({name!r}): source address is ANY",
                f"Policy {pid} accepts traffic from any source address. Use specific address objects.",
                f"config firewall policy\n    edit {pid}\n"
                f"        set srcaddr <specific-source-object>\n    next\nend",
                context=ctx))

        # Any service
        if service in ("all", "any") and utm != "enable":
            r.findings.append(_f(sid, SEVERITY_MEDIUM,
                f"Policy {pid} ({name!r}): service is ALL without UTM",
                f"Policy {pid} allows all services without UTM profiles. Restrict services "
                "or enable at minimum IPS inspection.",
                f"config firewall policy\n    edit {pid}\n"
                f"        set service <specific-services>\n"
                f"        set utm-status enable\n"
                f"        set ips-sensor \"default\"\n    next\nend",
                context=ctx))

        # No UTM on accept policies (that aren't deny)
        if utm != "enable":
            r.findings.append(_f(sid, SEVERITY_MEDIUM,
                f"Policy {pid} ({name!r}): no UTM profiles enabled",
                f"Accepted traffic in policy {pid} has no UTM inspection (AV, IPS, web filter). "
                "Threats can pass through uninspected.",
                f"config firewall policy\n    edit {pid}\n"
                f"        set utm-status enable\n"
                f"        set av-profile \"default\"\n"
                f"        set ips-sensor \"default\"\n    next\nend",
                context=ctx))
        else:
            if not av:
                r.findings.append(_f(sid, SEVERITY_MEDIUM,
                    f"Policy {pid} ({name!r}): UTM enabled but no AV profile",
                    "UTM is enabled but no antivirus profile is applied.",
                    f"config firewall policy\n    edit {pid}\n"
                    f"        set av-profile \"default\"\n    next\nend",
                    context=ctx))
            if not ips_s:
                r.findings.append(_f(sid, SEVERITY_MEDIUM,
                    f"Policy {pid} ({name!r}): UTM enabled but no IPS sensor",
                    "UTM is enabled but no IPS sensor is applied.",
                    f"config firewall policy\n    edit {pid}\n"
                    f"        set ips-sensor \"default\"\n    next\nend",
                    context=ctx))

    return r


# ── 3.10 SSL-SSH Profile ────────────────────────────────────────────────────

def analyze_ssl_profile(root: ConfigBlock) -> SubsystemReport:
    r = SubsystemReport("ssl_profile", "Firewall › SSL/SSH Inspection Profiles", False, [], [])
    b = find_block(root, "firewall ssl-ssh-profile")
    if not b:
        r.findings.append(_f("ssl_profile", SEVERITY_HIGH, "No SSL inspection profiles defined",
            "No firewall ssl-ssh-profile blocks found. Encrypted traffic cannot be inspected.",
            "config firewall ssl-ssh-profile\n    edit \"deep-inspection\"\n"
            "        set server-cert-mode replace\n        set caname \"Fortinet_CA_SSL\"\n"
            "        config https\n            set status deep-inspection\n"
            "            set min-allowed-ssl-version tls-1.2\n        end\n    next\nend"))
        return r
    r.present = True
    sid = "ssl_profile"

    HTTPS_RULES = [
        ("status", "deep-inspection", SEVERITY_CRITICAL, "HTTPS deep-inspection not enabled",
         "Without deep-inspection mode, encrypted HTTPS traffic is not inspected for threats."),
        ("min-allowed-ssl-version", "tls-1.2", SEVERITY_HIGH, "HTTPS minimum TLS version below 1.2",
         "Legacy TLS versions (1.0, 1.1) have known vulnerabilities (BEAST, POODLE)."),
        ("unsupported-ssl-version", "block", SEVERITY_HIGH, "HTTPS unsupported SSL versions not blocked",
         "Unsupported SSL versions should be blocked to prevent inspection bypass."),
        ("expired-server-cert", "block", SEVERITY_HIGH, "HTTPS expired certs not blocked",
         "Expired certificates should be blocked; they indicate misconfiguration or interception."),
        ("revoked-server-cert", "block", SEVERITY_HIGH, "HTTPS revoked certs not blocked",
         "Revoked certificates indicate compromised keys and should be blocked."),
        ("untrusted-server-cert", "block", SEVERITY_HIGH, "HTTPS untrusted certs not blocked",
         "Untrusted certificates are a primary indicator of spoofing or MITM attacks."),
        ("cert-validation-failure", "block", SEVERITY_HIGH, "HTTPS cert validation failure not blocked",
         "Failing open on cert validation failures allows connections to invalid endpoints."),
        ("sni-server-cert-check", "enable", SEVERITY_MEDIUM, "HTTPS SNI/cert check not enabled",
         "Without SNI matching, domain-fronting attacks may go undetected."),
    ]
    SSH_RULES = [
        ("status", "deep-inspection", SEVERITY_HIGH, "SSH inspection not enabled",
         "SSH is commonly used to tunnel arbitrary traffic if not inspected."),
        ("inspect-all", "enable", SEVERITY_MEDIUM, "SSH inspect-all not enabled",
         "Not all SSH sub-channels are inspected, leaving exec and port-forward channels unmonitored."),
        ("unsupported-version", "block", SEVERITY_HIGH, "SSH unsupported versions not blocked",
         "Legacy SSH versions have known cryptographic weaknesses."),
    ]
    GLOBAL_RULES = [
        ("server-cert-mode", "replace", SEVERITY_CRITICAL, "server-cert-mode not set to replace",
         "Without replace mode, deep-inspection may not function correctly."),
        ("ssl-anomalies-log", "enable", SEVERITY_HIGH, "SSL anomaly logging disabled",
         "SSL anomalies (evasion attempts, malformed TLS) will not be logged for incident response."),
        ("ssl-exemptions-log", "enable", SEVERITY_MEDIUM, "SSL exemption logging disabled",
         "No audit trail of which traffic is bypassing inspection."),
    ]

    for profile_entry in b.get_edit_entries():
        pname = profile_entry.name
        ctx   = f"Profile: {pname!r}"
        ps    = profile_entry.settings

        r.info_items.append(f"SSL/SSH profile: {pname!r}")

        # Check caname presence
        if not ps.get("caname", ""):
            r.findings.append(_f(sid, SEVERITY_CRITICAL,
                f"Profile {pname!r}: no inspection CA configured",
                "Deep-inspection requires a CA certificate to re-sign server certificates. "
                "Without caname, deep-inspection will fail or fall back to cert-inspection.",
                f"config firewall ssl-ssh-profile\n    edit \"{pname}\"\n"
                f"        set caname \"Fortinet_CA_SSL\"\n    next\nend",
                context=ctx))

        # Global top-level settings
        for key, expected, sev, title, detail in GLOBAL_RULES:
            actual = ps.get(key, "")
            if actual.lower() != expected.lower():
                r.findings.append(_f(sid, sev,
                    f"Profile {pname!r}: {title}",
                    detail,
                    f"config firewall ssl-ssh-profile\n    edit \"{pname}\"\n"
                    f"        set {key} {expected}\n    next\nend",
                    context=ctx))

        # Per-sub-section rules
        for section_name, rules in [("https", HTTPS_RULES), ("ssh", SSH_RULES)]:
            section = profile_entry.get_child_block(section_name)
            if not section:
                if section_name == "https":
                    r.findings.append(_f(sid, SEVERITY_HIGH,
                        f"Profile {pname!r}: no HTTPS inspection block",
                        "No HTTPS inspection sub-section configured in this profile.",
                        f"config firewall ssl-ssh-profile\n    edit \"{pname}\"\n"
                        f"        config https\n            set status deep-inspection\n"
                        f"            set min-allowed-ssl-version tls-1.2\n        end\n    next\nend",
                        context=ctx))
                continue

            for key, expected, sev, title, detail in rules:
                actual = section.get(key, "")
                if actual.lower() != expected.lower():
                    r.findings.append(_f(sid, sev,
                        f"Profile {pname!r} [{section_name.upper()}]: {title}",
                        detail,
                        f"config firewall ssl-ssh-profile\n    edit \"{pname}\"\n"
                        f"        config {section_name}\n            set {key} {expected}\n"
                        f"        end\n    next\nend",
                        context=ctx))

    return r


# ── 3.11 Antivirus ──────────────────────────────────────────────────────────

def analyze_antivirus(root: ConfigBlock) -> SubsystemReport:
    r = SubsystemReport("antivirus", "Security › Antivirus Profiles", False, [], [])
    b = find_block(root, "antivirus profile")
    if not b:
        r.findings.append(_f("antivirus", SEVERITY_HIGH, "No antivirus profiles configured",
            "No antivirus profiles defined. Malware in allowed traffic will not be detected.",
            "config antivirus profile\n    edit \"default\"\n        config http\n"
            "            set av-scan enable\n            set outbreak-prevention enable\n"
            "        end\n    next\nend"))
        return r
    r.present = True
    sid = "antivirus"

    for entry in b.get_edit_entries():
        pname = entry.name
        r.info_items.append(f"AV profile: {pname!r}")

        for proto in ["http", "ftp", "imap", "smtp", "pop3", "mapi"]:
            section = entry.get_child_block(proto)
            if section:
                av_scan = section.get("av-scan", "disable")
                outbreak = section.get("outbreak-prevention", "disable")

                if av_scan != "enable":
                    r.findings.append(_f(sid, SEVERITY_HIGH,
                        f"AV profile {pname!r}: {proto.upper()} scanning disabled",
                        f"Antivirus scanning for {proto.upper()} traffic is disabled in profile {pname!r}.",
                        f"config antivirus profile\n    edit \"{pname}\"\n"
                        f"        config {proto}\n            set av-scan enable\n        end\n    next\nend",
                        context=pname))

                if outbreak != "enable":
                    r.findings.append(_f(sid, SEVERITY_MEDIUM,
                        f"AV profile {pname!r}: {proto.upper()} outbreak prevention disabled",
                        f"Outbreak prevention (cloud-based zero-day detection) is disabled for "
                        f"{proto.upper()} in profile {pname!r}.",
                        f"config antivirus profile\n    edit \"{pname}\"\n"
                        f"        config {proto}\n            set outbreak-prevention enable\n"
                        f"        end\n    next\nend",
                        context=pname))

    return r


# ── 3.12 IPS ────────────────────────────────────────────────────────────────

def analyze_ips(root: ConfigBlock) -> SubsystemReport:
    r = SubsystemReport("ips", "Security › IPS Sensors", False, [], [])
    b = find_block(root, "ips sensor")
    if not b:
        r.findings.append(_f("ips", SEVERITY_HIGH, "No IPS sensors configured",
            "No IPS sensors defined. Intrusion attempts in allowed traffic will not be detected.",
            "config ips sensor\n    edit \"default\"\n        config entries\n"
            "            edit 1\n                set severity high critical\n"
            "                set action block\n            next\n        end\n    next\nend"))
        return r
    r.present = True
    sid = "ips"

    for entry in b.get_edit_entries():
        pname = entry.name
        r.info_items.append(f"IPS sensor: {pname!r}")
        entries_block = entry.get_child_block("entries")
        if not entries_block:
            r.findings.append(_f(sid, SEVERITY_MEDIUM,
                f"IPS sensor {pname!r}: no detection entries configured",
                "The IPS sensor has no rule entries. It will not detect any attacks.",
                f"config ips sensor\n    edit \"{pname}\"\n        config entries\n"
                f"            edit 1\n                set severity high critical\n"
                f"                set action block\n            next\n        end\n    next\nend",
                context=pname))
            continue

        has_block_high = False
        for e in entries_block.get_edit_entries():
            action   = e.get("action", "default")
            severity = e.get("severity", "")
            if action == "block" and ("high" in severity or "critical" in severity):
                has_block_high = True

        if not has_block_high:
            r.findings.append(_f(sid, SEVERITY_HIGH,
                f"IPS sensor {pname!r}: no block action for high/critical severity",
                f"IPS sensor {pname!r} does not block high or critical severity signatures. "
                "Attacks will be detected but not prevented.",
                f"config ips sensor\n    edit \"{pname}\"\n        config entries\n"
                f"            edit 1\n                set severity high critical\n"
                f"                set action block\n            next\n        end\n    next\nend",
                context=pname))

    return r


# ── 3.13 Web Filter ─────────────────────────────────────────────────────────

def analyze_webfilter(root: ConfigBlock) -> SubsystemReport:
    r = SubsystemReport("webfilter", "Security › Web Filter Profiles", False, [], [])
    b = find_block(root, "webfilter profile")
    if not b:
        r.findings.append(_f("webfilter", SEVERITY_MEDIUM, "No web filter profiles configured",
            "No web filter profiles defined. Malicious or policy-violating websites are not blocked.",
            "config webfilter profile\n    edit \"default\"\n        set options https-scan\n"
            "        config ftgd-wf\n            config filters\n"
            "                edit 1\n                    set category 26\n"
            "                    set action block\n                next\n"
            "            end\n        end\n    next\nend"))
        return r
    r.present = True
    sid = "webfilter"

    for entry in b.get_edit_entries():
        pname = entry.name
        opts  = entry.get("options", "")
        r.info_items.append(f"Web filter profile: {pname!r}  options: {opts}")

        if "https-scan" not in opts and "https" not in opts.lower():
            r.findings.append(_f(sid, SEVERITY_HIGH,
                f"Web filter profile {pname!r}: HTTPS scanning not enabled",
                "Web filtering cannot inspect HTTPS URLs without https-scan enabled. "
                "Category-based blocking will be bypassed for HTTPS sites.",
                f"config webfilter profile\n    edit \"{pname}\"\n"
                f"        set options https-scan\n    next\nend",
                context=pname))

        ftgd = entry.get_child_block("ftgd-wf")
        if ftgd:
            ftgd_opts = ftgd.get("options", "")
            if "error-allow" in ftgd_opts:
                r.findings.append(_f(sid, SEVERITY_LOW,
                    f"Web filter profile {pname!r}: error-allow set (fail-open)",
                    "When FortiGuard categorization fails, traffic is allowed through (fail-open). "
                    "Consider error-block to fail closed.",
                    f"config webfilter profile\n    edit \"{pname}\"\n"
                    f"        config ftgd-wf\n            set options error-block\n"
                    f"        end\n    next\nend",
                    context=pname))
        else:
            r.findings.append(_f(sid, SEVERITY_MEDIUM,
                f"Web filter profile {pname!r}: no FortiGuard category filtering",
                "No ftgd-wf block found. URL category filtering is not configured.",
                f"config webfilter profile\n    edit \"{pname}\"\n"
                f"        config ftgd-wf\n            set options category-override\n"
                f"        end\n    next\nend",
                context=pname))

    return r


# ── 3.14 Application Control ────────────────────────────────────────────────

def analyze_appcontrol(root: ConfigBlock) -> SubsystemReport:
    r = SubsystemReport("appcontrol", "Security › Application Control", False, [], [])
    b = find_block(root, "application list")
    if not b:
        r.findings.append(_f("appcontrol", SEVERITY_MEDIUM, "No application control lists configured",
            "No application control lists defined. P2P, anonymizers, and other risky applications "
            "are not identified or controlled.",
            "config application list\n    edit \"default\"\n        config entries\n"
            "            edit 1\n                set category 2\n"
            "                set action block\n            next\n        end\n    next\nend"))
        return r
    r.present = True
    sid = "appcontrol"

    for entry in b.get_edit_entries():
        pname = entry.name
        r.info_items.append(f"Application control list: {pname!r}")
        ent = entry.get_child_block("entries")
        if not ent or not ent.get_edit_entries():
            r.findings.append(_f(sid, SEVERITY_MEDIUM,
                f"App control list {pname!r}: no entries configured",
                "The application control list has no entries. No applications will be blocked.",
                f"config application list\n    edit \"{pname}\"\n"
                f"        config entries\n            edit 1\n"
                f"                set category 2\n                set action block\n"
                f"            next\n        end\n    next\nend",
                context=pname))

    return r


# ── 3.15 VPN IPsec ──────────────────────────────────────────────────────────

def analyze_vpn(root: ConfigBlock) -> SubsystemReport:
    r = SubsystemReport("vpn", "VPN › IPsec", False, [], [])
    b1 = find_block(root, "vpn ipsec phase1-interface")
    if not b1:
        r.info_items.append("IPsec VPN phase1: not configured")
        return r
    r.present = True
    sid = "vpn"

    WEAK_PROPOSALS  = {"des", "3des", "md5", "sha1", "aes128"}
    WEAK_DH_GROUPS  = {"1", "2", "5"}  # DH < 2048-bit
    STRONG_DH       = {"14", "15", "16", "19", "20", "21"}

    for entry in b1.get_edit_entries():
        tname    = entry.name
        proposal = entry.get("proposal", "").lower()
        dhgrp    = entry.get("dhgrp", "").lower()
        ike_ver  = entry.get("ike-version", "1")
        dpd      = entry.get("dpd", "disable")
        keylife  = int(entry.get("keylife", "86400") or 86400)
        ctx      = f"Phase1: {tname!r}"

        r.info_items.append(f"IPsec phase1: {tname!r}  IKE={ike_ver}  proposal={proposal}  "
                            f"dhgrp={dhgrp}  keylife={keylife}")

        if ike_ver == "1":
            r.findings.append(_f(sid, SEVERITY_HIGH,
                f"VPN {tname!r}: IKEv1 in use",
                "IKEv1 lacks features of IKEv2 (MOBIKE, built-in NAT-T, better DoS resistance). "
                "All new tunnels should use IKEv2.",
                f"config vpn ipsec phase1-interface\n    edit \"{tname}\"\n"
                f"        set ike-version 2\n    next\nend",
                context=ctx))

        weak_algos = [p for p in re.split(r'[\s-]', proposal) if p in WEAK_PROPOSALS]
        if weak_algos:
            r.findings.append(_f(sid, SEVERITY_HIGH,
                f"VPN {tname!r}: weak encryption/integrity algorithms",
                f"Proposal '{proposal}' includes weak algorithms: {weak_algos}. "
                "DES, 3DES, MD5, and SHA-1 are cryptographically broken or weak.",
                f"config vpn ipsec phase1-interface\n    edit \"{tname}\"\n"
                f"        set proposal aes256-sha256\n    next\nend",
                context=ctx))

        dh_groups = set(re.split(r'\s+', dhgrp.strip()))
        weak_dh = dh_groups & WEAK_DH_GROUPS
        if weak_dh:
            r.findings.append(_f(sid, SEVERITY_CRITICAL,
                f"VPN {tname!r}: weak Diffie-Hellman groups",
                f"DH groups {weak_dh} use keys smaller than 2048 bits. These are vulnerable "
                "to Logjam and similar attacks.",
                f"config vpn ipsec phase1-interface\n    edit \"{tname}\"\n"
                f"        set dhgrp 14 19 20\n    next\nend",
                context=ctx))

        if not dh_groups & STRONG_DH and not weak_dh:
            r.findings.append(_f(sid, SEVERITY_MEDIUM,
                f"VPN {tname!r}: DH group not explicitly set to strong group",
                "Recommend explicitly setting DH group 14 or higher.",
                f"config vpn ipsec phase1-interface\n    edit \"{tname}\"\n"
                f"        set dhgrp 14\n    next\nend",
                context=ctx))

        if dpd == "disable":
            r.findings.append(_f(sid, SEVERITY_LOW,
                f"VPN {tname!r}: Dead Peer Detection disabled",
                "Without DPD, dead VPN tunnels will not be detected and torn down, wasting resources.",
                f"config vpn ipsec phase1-interface\n    edit \"{tname}\"\n"
                f"        set dpd on-idle\n        set dpd-retryinterval 60\n    next\nend",
                context=ctx))

        if keylife > 86400:
            r.findings.append(_f(sid, SEVERITY_LOW,
                f"VPN {tname!r}: phase1 keylife too long ({keylife}s)",
                f"Key lifetime of {keylife}s ({keylife//3600}h) is long. Recommend ≤28800s (8h).",
                f"config vpn ipsec phase1-interface\n    edit \"{tname}\"\n"
                f"        set keylife 28800\n    next\nend",
                context=ctx))

    # Phase 2 PFS check
    b2 = find_block(root, "vpn ipsec phase2-interface")
    if b2:
        for entry in b2.get_edit_entries():
            tname  = entry.name
            dhgrp  = entry.get("dhgrp", "")
            p1name = entry.get("phase1name", "")
            ctx    = f"Phase2: {tname!r}"

            if not dhgrp:
                r.findings.append(_f(sid, SEVERITY_HIGH,
                    f"VPN phase2 {tname!r}: no PFS (Perfect Forward Secrecy)",
                    f"Phase 2 tunnel '{tname}' (under phase1 '{p1name}') has no DH group set, "
                    "disabling PFS. A compromised phase1 key would expose all past sessions.",
                    f"config vpn ipsec phase2-interface\n    edit \"{tname}\"\n"
                    f"        set dhgrp 14\n    next\nend",
                    context=ctx))

            kl2 = int(entry.get("keylifeseconds", "43200") or 43200)
            if kl2 > 3600:
                r.findings.append(_f(sid, SEVERITY_LOW,
                    f"VPN phase2 {tname!r}: keylife too long ({kl2}s)",
                    f"Phase2 key lifetime of {kl2}s should be ≤3600s (1h) for better forward secrecy.",
                    f"config vpn ipsec phase2-interface\n    edit \"{tname}\"\n"
                    f"        set keylifeseconds 3600\n    next\nend",
                    context=ctx))

    return r


# ── 3.16 Users ──────────────────────────────────────────────────────────────

def analyze_users(root: ConfigBlock) -> SubsystemReport:
    r = SubsystemReport("users", "Identity › Local Users & Groups", False, [], [])
    b = find_block(root, "user local")
    if not b:
        r.info_items.append("Local users: none defined")
        return r
    r.present = True
    sid = "users"

    entries = b.get_edit_entries()
    r.info_items.append(f"Local users: {len(entries)}")

    for entry in entries:
        uname   = entry.name
        utype   = entry.get("type", "password")
        twofac  = entry.get("two-factor", "disable")
        email   = entry.get("email-to", "")

        r.info_items.append(f"  User: {uname!r}  type={utype}  2FA={twofac}  email={email}")

        if twofac in ("disable", ""):
            r.findings.append(_f(sid, SEVERITY_MEDIUM,
                f"User {uname!r}: no two-factor authentication",
                f"Local user '{uname}' does not require two-factor authentication. "
                "If this account is used for VPN or admin access, MFA is strongly recommended.",
                f"config user local\n    edit \"{uname}\"\n"
                f"        set two-factor email\n        set email-to \"{email or 'user@example.com'}\"\n"
                f"    next\nend",
                context=uname))

    # Groups
    gb = find_block(root, "user group")
    if gb:
        for g in gb.get_edit_entries():
            members = g.get("member", "")
            r.info_items.append(f"User group: {g.name!r}  members: {members}")

    return r


# ── 3.17 Logging ────────────────────────────────────────────────────────────

def analyze_logging(root: ConfigBlock) -> SubsystemReport:
    r = SubsystemReport("logging", "System › Logging", False, [], [])
    sid = "logging"

    # Syslog
    syslog = find_block(root, "log syslog setting")
    if not syslog:
        r.findings.append(_f(sid, SEVERITY_HIGH, "No syslog server configured",
            "No log syslog setting block found. Security events are not forwarded to a SIEM "
            "or central log server, making incident detection and forensics extremely difficult.",
            "config log syslog setting\n    set status enable\n"
            "    set server \"<siem-ip>\"\n    set port 514\n"
            "    set facility local7\n    set format default\nend"))
    else:
        r.present = True
        ss = syslog.settings
        status = ss.get("status", "disable")
        server = ss.get("server", "")
        r.info_items.append(f"Syslog: status={status}  server={server}  "
                            f"port={ss.get('port','514')}  format={ss.get('format','default')}")
        if status != "enable":
            r.findings.append(_f(sid, SEVERITY_HIGH, "Syslog is configured but disabled",
                "Syslog server is defined but forwarding is disabled.",
                "config log syslog setting\n    set status enable\nend"))
        if not server:
            r.findings.append(_f(sid, SEVERITY_HIGH, "Syslog server IP not set",
                "Syslog status is enabled but no server address is configured.",
                "config log syslog setting\n    set server \"<siem-ip>\"\nend"))

    # Log settings
    ls = find_block(root, "log setting")
    if ls:
        r.present = True
        lss = ls.settings
        if lss.get("fwpolicy-implicit-log", "disable") != "enable":
            r.findings.append(_f(sid, SEVERITY_MEDIUM, "Implicit deny logging disabled",
                "Traffic blocked by the implicit deny policy is not logged. "
                "Blocked connection attempts are valuable for threat detection.",
                "config log setting\n    set fwpolicy-implicit-log enable\nend"))
        else:
            r.info_items.append("Implicit deny logging: enabled")
    else:
        r.findings.append(_f(sid, SEVERITY_LOW, "No log setting block found",
            "Log settings are not explicitly configured. Ensure implicit-deny logging is enabled.",
            "config log setting\n    set fwpolicy-implicit-log enable\n    set extended-log enable\nend"))

    return r


# ── 3.18 Routing ────────────────────────────────────────────────────────────

def analyze_routing(root: ConfigBlock) -> SubsystemReport:
    r = SubsystemReport("routing", "Network › Routing", False, [], [])
    sid = "routing"

    static = find_block(root, "router static")
    if static:
        r.present = True
        entries = static.get_edit_entries()
        r.info_items.append(f"Static routes: {len(entries)}")
        for e in entries:
            gw  = e.get("gateway", "?")
            dev = e.get("device", "?")
            dst = e.get("dst", "0.0.0.0 0.0.0.0")
            r.info_items.append(f"  Route: {dst} via {gw} dev {dev}")

    ospf = find_block(root, "router ospf")
    if ospf:
        r.present = True
        rid = ospf.get("router-id", "(not set)")
        r.info_items.append(f"OSPF router-id: {rid}")
        if rid in ("0.0.0.0", "", "(not set)"):
            r.findings.append(_f(sid, SEVERITY_MEDIUM, "OSPF router-id not explicitly set",
                "OSPF router-id defaults to an interface IP if not set, which can cause instability "
                "if that interface flaps.",
                "config router ospf\n    set router-id <unique-router-id>\nend"))

        # Check for authentication on OSPF areas
        areas = ospf.get_child_block("area")
        if areas:
            for area in areas.get_edit_entries():
                auth = area.get("authentication", "none")
                aid  = area.name
                if auth in ("none", ""):
                    r.findings.append(_f(sid, SEVERITY_MEDIUM,
                        f"OSPF area {aid}: no authentication configured",
                        "OSPF without authentication allows any router to inject routes into your network.",
                        f"config router ospf\n    config area\n        edit {aid}\n"
                        f"            set authentication md5\n        next\n    end\nend",
                        context=f"OSPF area {aid}"))

    bgp = find_block(root, "router bgp")
    if bgp:
        r.present = True
        asn = bgp.get("as", "?")
        r.info_items.append(f"BGP AS: {asn}")

    if not r.present:
        r.info_items.append("Routing: no dynamic routing protocols configured")

    return r


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — TREE RENDERER
# Produces the visual config tree output file.
# ═══════════════════════════════════════════════════════════════════════════════

def render_tree(root: ConfigBlock) -> str:
    lines = []
    lines.append("FortiGate Configuration Tree")
    lines.append("=" * 60)

    def render_block(block: ConfigBlock, prefix: str, is_last: bool, depth: int):
        connector = "└── " if is_last else "├── "
        child_prefix = prefix + ("    " if is_last else "│   ")

        if block.block_type == "config":
            lines.append(f"{prefix}{connector}[config {block.name}]")
        elif block.block_type == "edit":
            lines.append(f"{prefix}{connector}edit \"{block.name}\"")
        else:
            return

        # Settings
        settings_list = list(block.settings.items())
        child_blocks  = block.children

        total_items = len(settings_list) + len(child_blocks)
        idx = 0
        for key, val in settings_list:
            idx += 1
            is_last_item = (idx == total_items)
            sc = "└── " if is_last_item else "├── "
            # Mask sensitive values
            display_val = "<masked>" if key in ("password", "passwd", "psksecret", "secret") else val
            lines.append(f"{child_prefix}{sc}set {key} = {display_val}")

        for i, child in enumerate(child_blocks):
            idx += 1
            is_last_child = (i == len(child_blocks) - 1)
            render_block(child, child_prefix, is_last_child, depth + 1)

    for i, child in enumerate(root.children):
        render_block(child, "", i == len(root.children) - 1, 0)

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — FIREWALL RULE REPORTER
# Produces the detailed hierarchical firewall policy file.
# ═══════════════════════════════════════════════════════════════════════════════

def render_firewall_report(root: ConfigBlock) -> str:
    lines = []
    W = 78

    def hdr(text: str, char: str = "═"):
        lines.append(char * W)
        lines.append(f"  {text}")
        lines.append(char * W)

    def subhdr(text: str):
        lines.append(f"  {'─' * (W - 4)}")
        lines.append(f"  {text}")
        lines.append(f"  {'─' * (W - 4)}")

    def kv(key: str, val: str, indent: int = 4):
        if not val:
            return
        lines.append(f"{' ' * indent}{'·'} {key:<28} {val}")

    def masked(key: str, val: str) -> str:
        return "<configured>" if val and key.lower() in ("password", "passwd", "psksecret") else val

    hdr("FortiGate Firewall Rule & Profile Hierarchy Report")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    # ── Address Objects ──────────────────────────────────────────────────────
    addr = find_block(root, "firewall address")
    addrgrp = find_block(root, "firewall addrgrp")

    hdr("ADDRESS OBJECTS", "═")
    lines.append("")

    if addr:
        for e in addr.get_edit_entries():
            lines.append(f"  ┌─ Address: {e.name!r}")
            kv("Type",    e.get("type", "ipmask"),    6)
            kv("Subnet",  e.get("subnet", ""),         6)
            kv("FQDN",    e.get("fqdn", ""),           6)
            kv("Comment", e.get("comment", ""),        6)
            lines.append("")

    if addrgrp:
        lines.append("  Address Groups:")
        for e in addrgrp.get_edit_entries():
            lines.append(f"  ┌─ Group: {e.name!r}")
            kv("Members", e.get("member", ""), 6)
            lines.append("")

    # ── Service Objects ──────────────────────────────────────────────────────
    svc = find_block(root, "firewall service custom")
    if svc and svc.get_edit_entries():
        hdr("CUSTOM SERVICE OBJECTS", "═")
        lines.append("")
        for e in svc.get_edit_entries():
            lines.append(f"  ┌─ Service: {e.name!r}")
            kv("Protocol",      e.get("protocol", "TCP"),         6)
            kv("TCP Ports",     e.get("tcp-portrange", ""),       6)
            kv("UDP Ports",     e.get("udp-portrange", ""),       6)
            kv("Comment",       e.get("comment", ""),             6)
            lines.append("")

    # ── AV Profiles ─────────────────────────────────────────────────────────
    av = find_block(root, "antivirus profile")
    if av and av.get_edit_entries():
        hdr("ANTIVIRUS PROFILES", "═")
        lines.append("")
        for e in av.get_edit_entries():
            lines.append(f"  ┌─ AV Profile: {e.name!r}")
            kv("Comment", e.get("comment", ""), 6)
            for proto in ["http", "ftp", "imap", "smtp", "pop3", "mapi"]:
                sec = e.get_child_block(proto)
                if sec:
                    lines.append(f"        ├── {proto.upper()}")
                    kv("AV Scan",          sec.get("av-scan",          ""), 10)
                    kv("Outbreak Prevent", sec.get("outbreak-prevention", ""), 10)
                    kv("Executables",      sec.get("executables",       ""), 10)
            lines.append("")

    # ── IPS Sensors ─────────────────────────────────────────────────────────
    ips = find_block(root, "ips sensor")
    if ips and ips.get_edit_entries():
        hdr("IPS SENSORS", "═")
        lines.append("")
        for e in ips.get_edit_entries():
            lines.append(f"  ┌─ IPS Sensor: {e.name!r}")
            kv("Comment", e.get("comment", ""), 6)
            ents = e.get_child_block("entries")
            if ents:
                for ent in ents.get_edit_entries():
                    lines.append(f"        ├── Entry {ent.name}")
                    kv("Action",   ent.get("action",   ""), 12)
                    kv("Severity", ent.get("severity", ""), 12)
                    kv("Rules",    ent.get("rule",     ""), 12)
                    kv("Status",   ent.get("status",   ""), 12)
            lines.append("")

    # ── Web Filter Profiles ──────────────────────────────────────────────────
    wf = find_block(root, "webfilter profile")
    if wf and wf.get_edit_entries():
        hdr("WEB FILTER PROFILES", "═")
        lines.append("")
        for e in wf.get_edit_entries():
            lines.append(f"  ┌─ Web Filter Profile: {e.name!r}")
            kv("Comment", e.get("comment", ""), 6)
            kv("Options",  e.get("options",  ""), 6)
            ftgd = e.get_child_block("ftgd-wf")
            if ftgd:
                kv("FTGD Options", ftgd.get("options", ""), 6)
                filters = ftgd.get_child_block("filters")
                if filters:
                    for f in filters.get_edit_entries():
                        cat = f.get("category", "?")
                        act = f.get("action",   "?")
                        lines.append(f"        ├── Category {cat}: {act}")
            lines.append("")

    # ── SSL/SSH Profiles ────────────────────────────────────────────────────
    ssl = find_block(root, "firewall ssl-ssh-profile")
    if ssl and ssl.get_edit_entries():
        hdr("SSL/SSH INSPECTION PROFILES", "═")
        lines.append("")
        for e in ssl.get_edit_entries():
            lines.append(f"  ┌─ SSL/SSH Profile: {e.name!r}")
            kv("Server Cert Mode", e.get("server-cert-mode", ""), 6)
            kv("CA Name",          e.get("caname",            ""), 6)
            kv("Untrusted CA",     e.get("untrusted-caname",  ""), 6)
            kv("SSL Anomalies Log",e.get("ssl-anomalies-log", ""), 6)
            kv("SSL Exempt Log",   e.get("ssl-exemptions-log",""), 6)
            kv("RPC over HTTPS",   e.get("rpc-over-https",    ""), 6)
            kv("MAPI over HTTPS",  e.get("mapi-over-https",   ""), 6)
            for section in ["https", "ftps", "imaps", "pop3s", "smtps", "ssh", "dot"]:
                sec = e.get_child_block(section)
                if sec:
                    lines.append(f"        ├── {section.upper()}")
                    for k, v in sec.settings.items():
                        kv(k, v, 12)
            lines.append("")

    # ── Application Control ──────────────────────────────────────────────────
    app = find_block(root, "application list")
    if app and app.get_edit_entries():
        hdr("APPLICATION CONTROL LISTS", "═")
        lines.append("")
        for e in app.get_edit_entries():
            lines.append(f"  ┌─ App Control List: {e.name!r}")
            kv("Comment", e.get("comment", ""), 6)
            ents = e.get_child_block("entries")
            if ents:
                for ent in ents.get_edit_entries():
                    lines.append(f"        ├── Entry {ent.name}")
                    kv("Category",    ent.get("category",    ""), 12)
                    kv("Application", ent.get("application", ""), 12)
                    kv("Action",      ent.get("action",      ""), 12)
            lines.append("")

    # ══════════════════════════════════════════════════════════════════════════
    # ── FIREWALL POLICIES (main section) ────────────────────────────────────
    # ══════════════════════════════════════════════════════════════════════════
    pol = find_block(root, "firewall policy")
    if not pol:
        lines.append("(no firewall policy block found)")
        return "\n".join(lines)

    hdr("FIREWALL POLICIES", "═")
    lines.append("")

    av_map   = {}
    ips_map  = {}
    wf_map   = {}
    ssl_map  = {}
    app_map  = {}

    if av:
        for e in av.get_edit_entries():   av_map[e.name]   = e
    if ips:
        for e in ips.get_edit_entries():  ips_map[e.name]  = e
    if wf:
        for e in wf.get_edit_entries():   wf_map[e.name]   = e
    if ssl:
        for e in ssl.get_edit_entries():  ssl_map[e.name]  = e
    if app:
        for e in app.get_edit_entries():  app_map[e.name]  = e

    for policy in pol.get_edit_entries():
        pid     = policy.name
        pname   = policy.get("name", f"policy-{pid}")
        action  = policy.get("action",   "deny")
        srcintf = policy.get("srcintf",  "?")
        dstintf = policy.get("dstintf",  "?")
        srcaddr = policy.get("srcaddr",  "?")
        dstaddr = policy.get("dstaddr",  "?")
        service = policy.get("service",  "ALL")
        sched   = policy.get("schedule", "always")
        log     = policy.get("logtraffic","disable")
        nat     = policy.get("nat",      "disable")
        utm     = policy.get("utm-status","disable")
        av_p    = policy.get("av-profile",      "")
        ips_p   = policy.get("ips-sensor",      "")
        wf_p    = policy.get("webfilter-profile","")
        ssl_p   = policy.get("ssl-ssh-profile", "")
        app_p   = policy.get("application-list","")
        comment = policy.get("comments", "")

        action_sym = "✔ ACCEPT" if action == "accept" else ("✖ DENY" if action == "deny" else action.upper())

        lines.append("┌" + "─" * (W - 1))
        lines.append(f"│  Rule ID: {pid}   Name: {pname!r}   Action: {action_sym}")
        lines.append("│" + "─" * (W - 1))

        if comment:
            lines.append(f"│  Description:  {comment}")
            lines.append("│")

        lines.append(f"│  Traffic Flow:")
        lines.append(f"│      Source Interface  : {srcintf}")
        lines.append(f"│      Source Address    : {srcaddr}")
        lines.append(f"│      Destination Intf  : {dstintf}")
        lines.append(f"│      Destination Addr  : {dstaddr}")
        lines.append(f"│      Service           : {service}")
        lines.append(f"│      Schedule          : {sched}")
        lines.append(f"│      NAT               : {nat}")
        lines.append(f"│      Log Traffic       : {log}")
        lines.append("│")

        lines.append(f"│  UTM / Security Profiles  [{('ENABLED' if utm == 'enable' else 'DISABLED')}]")

        def profile_detail(label: str, pname: str, pmap: dict, detail_fn):
            if not pname:
                return
            lines.append(f"│      ├─ {label}: {pname!r}")
            entry = pmap.get(pname)
            if entry:
                detail_fn(entry)
            else:
                lines.append(f"│      │   (profile definition not found in config)")

        def av_detail(e):
            lines.append(f"│      │   Comment : {e.get('comment','')}")
            for proto in ["http", "ftp", "imap", "smtp"]:
                sec = e.get_child_block(proto)
                if sec:
                    lines.append(f"│      │   {proto.upper()}: av-scan={sec.get('av-scan','?')}  "
                                 f"outbreak-prevention={sec.get('outbreak-prevention','?')}")

        def ips_detail(e):
            lines.append(f"│      │   Comment : {e.get('comment','')}")
            ents = e.get_child_block("entries")
            if ents:
                for en in ents.get_edit_entries():
                    lines.append(f"│      │   Entry {en.name}: severity={en.get('severity','?')}  "
                                 f"action={en.get('action','?')}")

        def wf_detail(e):
            lines.append(f"│      │   Comment : {e.get('comment','')}")
            lines.append(f"│      │   Options  : {e.get('options','')}")
            ftgd = e.get_child_block("ftgd-wf")
            if ftgd:
                filters = ftgd.get_child_block("filters")
                if filters:
                    for f in filters.get_edit_entries():
                        lines.append(f"│      │   Category {f.get('category','?')}: "
                                     f"{f.get('action','?')}")

        def ssl_detail(e):
            lines.append(f"│      │   Mode     : {e.get('server-cert-mode','?')}")
            lines.append(f"│      │   CA       : {e.get('caname','?')}")
            https = e.get_child_block("https")
            if https:
                lines.append(f"│      │   HTTPS    : status={https.get('status','?')}  "
                             f"min-tls={https.get('min-allowed-ssl-version','?')}")

        def app_detail(e):
            lines.append(f"│      │   Comment : {e.get('comment','')}")
            ents = e.get_child_block("entries")
            if ents:
                for en in ents.get_edit_entries():
                    lines.append(f"│      │   Entry {en.name}: cat={en.get('category','?')}  "
                                 f"action={en.get('action','?')}")

        profile_detail("AV Profile",     av_p,  av_map,  av_detail)
        profile_detail("IPS Sensor",     ips_p, ips_map, ips_detail)
        profile_detail("Web Filter",     wf_p,  wf_map,  wf_detail)
        profile_detail("SSL/SSH Profile",ssl_p, ssl_map, ssl_detail)
        profile_detail("App Control",    app_p, app_map, app_detail)

        if not any([av_p, ips_p, wf_p, ssl_p, app_p]):
            lines.append(f"│      └─ (no UTM profiles assigned to this rule)")

        lines.append("└" + "─" * (W - 1))
        lines.append("")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — FULL ANALYSIS REPORTER
# ═══════════════════════════════════════════════════════════════════════════════

DEDUCTIONS = {
    SEVERITY_CRITICAL: 3.0,
    SEVERITY_HIGH:     2.0,
    SEVERITY_MEDIUM:   1.0,
    SEVERITY_LOW:      0.5,
    SEVERITY_INFO:     0.0,
}


def compute_score(findings: list) -> float:
    score = 10.0
    for f in findings:
        score -= DEDUCTIONS.get(f.severity, 0)
    return max(0.0, round(score, 1))


def render_analysis(reports: list[SubsystemReport], filename: str) -> str:
    W = 78
    lines = []

    def hdr(text: str, char: str = "═"):
        lines.append(char * W)
        lines.append(f"  {text}")
        lines.append(char * W)

    hdr("FortiGate Security Configuration Analysis Report")
    lines.append(f"  File      : {filename}")
    lines.append(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    all_findings = []
    for rep in reports:
        all_findings.extend(rep.findings)

    by_sev = defaultdict(int)
    for f in all_findings:
        by_sev[f.severity] += 1

    lines.append("  OVERALL FINDING COUNTS")
    lines.append("  " + "─" * 40)
    for sev in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]:
        icon = SEVERITY_ICONS[sev]
        count = by_sev.get(sev, 0)
        lines.append(f"  {icon} {sev:<10}  {count:>3} finding{'s' if count != 1 else ''}")
    lines.append("")
    lines.append(f"  Total findings: {len(all_findings)}")
    overall_score = max(0.0, round(10.0 - sum(DEDUCTIONS.get(f.severity,0) for f in all_findings), 1))
    lines.append(f"  Overall security score: {overall_score:.1f} / 10")
    lines.append("")

    for rep in reports:
        if not rep.findings and not rep.info_items:
            continue

        lines.append("═" * W)
        score = compute_score(rep.findings)
        status = ("✔ PASS" if not rep.findings else
                  ("✖ CRITICAL ISSUES" if any(f.severity == SEVERITY_CRITICAL for f in rep.findings) else
                   ("⚠ HIGH RISK" if any(f.severity == SEVERITY_HIGH for f in rep.findings) else
                    "◆ MODERATE RISK")))
        lines.append(f"  SUBSYSTEM: {rep.display_name}")
        lines.append(f"  Status  : {status}   Score: {score:.1f}/10")
        lines.append("═" * W)
        lines.append("")

        if not rep.present and rep.findings:
            lines.append("  ⚠ This subsystem is not configured in the analyzed file.")
            lines.append("")

        if rep.info_items:
            lines.append("  Configuration Summary:")
            for item in rep.info_items:
                lines.append(f"    {item}")
            lines.append("")

        if rep.findings:
            sorted_findings = sorted(rep.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
            lines.append(f"  Findings ({len(rep.findings)}):")
            for i, f in enumerate(sorted_findings, 1):
                icon = SEVERITY_ICONS[f.severity]
                ctx  = f"  [{f.context}]" if f.context else ""
                lines.append("")
                lines.append(f"  {icon} [{f.severity}] {f.title}{ctx}")
                lines.append("  " + "─" * (W - 2))

                # Word-wrap detail
                words = f.detail.split()
                line_buf = "    Detail: "
                for w in words:
                    if len(line_buf) + len(w) + 1 > W:
                        lines.append(line_buf)
                        line_buf = "            " + w + " "
                    else:
                        line_buf += w + " "
                if line_buf.strip():
                    lines.append(line_buf)

                lines.append("")
                lines.append("    Remediation:")
                for rline in f.remediation.splitlines():
                    lines.append(f"      {rline}")
        else:
            lines.append("  ✔ No security findings for this subsystem.")

        lines.append("")

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — EXECUTIVE SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════

def render_summary(reports: list[SubsystemReport], filename: str) -> str:
    W = 78
    lines = []

    lines.append("=" * W)
    lines.append(" " * 15 + "FORTIGATE SECURITY ANALYSIS — EXECUTIVE SUMMARY")
    lines.append("=" * W)
    lines.append(f"  File      : {filename}")
    lines.append(f"  Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    all_findings = []
    for rep in reports:
        all_findings.extend(rep.findings)

    overall_score = max(0.0, round(10.0 - sum(DEDUCTIONS.get(f.severity, 0) for f in all_findings), 1))
    risk_label = ("CRITICAL RISK" if overall_score < 3 else
                  "HIGH RISK"     if overall_score < 5 else
                  "MODERATE RISK" if overall_score < 7 else
                  "LOW RISK"      if overall_score < 9 else "SECURE")

    lines.append(f"  OVERALL SECURITY SCORE : {overall_score:.1f} / 10   [{risk_label}]")
    lines.append("")

    # Score bar
    filled = int(overall_score)
    bar = "█" * filled + "░" * (10 - filled)
    lines.append(f"  [{bar}]  {overall_score:.1f}/10")
    lines.append("")

    by_sev: dict[str, list[Finding]] = defaultdict(list)
    for f in all_findings:
        by_sev[f.severity].append(f)

    lines.append("  FINDING BREAKDOWN")
    lines.append("  " + "─" * 50)
    for sev in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW]:
        flist = by_sev.get(sev, [])
        icon  = SEVERITY_ICONS[sev]
        lines.append(f"  {icon} {sev:<10} : {len(flist):>3} finding{'s' if len(flist) != 1 else ''}")
    lines.append("")

    # Critical and High findings listed explicitly
    for sev, label in [(SEVERITY_CRITICAL, "CRITICAL"), (SEVERITY_HIGH, "HIGH")]:
        flist = by_sev.get(sev, [])
        if flist:
            lines.append(f"  {SEVERITY_ICONS[sev]} {label} FINDINGS — Immediate Action Required:")
            for f in flist:
                ctx = f" [{f.context}]" if f.context else ""
                lines.append(f"    • {f.subsystem:<20} {f.title}{ctx}")
            lines.append("")

    # Per-subsystem risk table
    lines.append("  SUBSYSTEM RISK SUMMARY")
    lines.append("  " + "─" * 60)
    lines.append(f"  {'Subsystem':<35} {'Score':>6}  {'Status'}")
    lines.append("  " + "─" * 60)
    for rep in reports:
        score  = compute_score(rep.findings)
        status = ("✔ OK"      if not rep.findings else
                  "✖ CRITICAL" if any(f.severity == SEVERITY_CRITICAL for f in rep.findings) else
                  "⚠ HIGH"    if any(f.severity == SEVERITY_HIGH      for f in rep.findings) else
                  "◆ MEDIUM"  if any(f.severity == SEVERITY_MEDIUM    for f in rep.findings) else
                  "● LOW")
        lines.append(f"  {rep.display_name:<35} {score:>5.1f}  {status}")
    lines.append("")

    # Top 5 recommendations
    lines.append("  TOP PRIORITY RECOMMENDATIONS")
    lines.append("  " + "─" * 50)
    priority_findings = sorted(all_findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    for i, f in enumerate(priority_findings[:8], 1):
        icon = SEVERITY_ICONS[f.severity]
        lines.append(f"  {i}. {icon} {f.title}")
    lines.append("")

    lines.append("=" * W)
    lines.append("  Refer to the full analysis report for detailed remediation commands.")
    lines.append("=" * W)

    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — CONSOLE OUTPUT (tree printed to screen, condensed)
# ═══════════════════════════════════════════════════════════════════════════════

def print_console_tree(root: ConfigBlock, summary: str):
    """Print a condensed version to the terminal."""
    print()
    print("╔" + "═" * 68 + "╗")
    print("║" + " FortiGate Configuration Analyzer".center(68) + "║")
    print("╚" + "═" * 68 + "╝")
    print()

    print("  Config sections found:")
    for i, child in enumerate(root.children):
        connector = "└─" if i == len(root.children) - 1 else "├─"
        entries   = child.get_edit_entries()
        settings  = len(child.settings)
        children  = len(child.get_config_children())
        detail    = (f"{len(entries)} entries" if entries else
                     f"{settings} settings" + (f", {children} sub-sections" if children else ""))
        print(f"  {connector} [config {child.name}]  ({detail})")
    print()

    print("─" * 70)
    # Print just the score and critical/high lines from summary
    for line in summary.splitlines():
        if any(kw in line for kw in ["SCORE", "RISK", "CRITICAL", "HIGH", "█", "░", "──"]):
            print(line)
    print("─" * 70)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 9 — MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def run_all_analyzers(root: ConfigBlock) -> list[SubsystemReport]:
    return [
        analyze_system_global(root),
        analyze_system_interface(root),
        analyze_system_admin(root),
        analyze_password_policy(root),
        analyze_dns(root),
        analyze_ntp(root),
        analyze_snmp(root),
        analyze_ha(root),
        analyze_routing(root),
        analyze_firewall_policy(root),
        analyze_ssl_profile(root),
        analyze_antivirus(root),
        analyze_ips(root),
        analyze_webfilter(root),
        analyze_appcontrol(root),
        analyze_vpn(root),
        analyze_users(root),
        analyze_logging(root),
    ]


def main():
    if len(sys.argv) < 2:
        print("Usage: python fortigate_Analyzer.py <config_file.conf>")
        print("       Analyzes a FortiGate configuration file and writes four report files.")
        sys.exit(1)

    config_file = sys.argv[1]
    if not os.path.isfile(config_file):
        print(f"Error: file not found: {config_file}")
        sys.exit(1)

    with open(config_file, "r", encoding="utf-8", errors="replace") as fh:
        raw_text = fh.read()

    base = os.path.splitext(config_file)[0]
    tree_file     = base + "_tree.txt"
    firewall_file = base + "_firewall.txt"
    analysis_file = base + "_analysis.txt"
    summary_file  = base + "_summary.txt"

    print(f"\nParsing {config_file} ...")
    root = parse_config(raw_text)

    print("Running security analyzers ...")
    reports = run_all_analyzers(root)

    print("Generating reports ...")

    tree_text     = render_tree(root)
    firewall_text = render_firewall_report(root)
    analysis_text = render_analysis(reports, config_file)
    summary_text  = render_summary(reports, config_file)

    for path, text in [
        (tree_file,     tree_text),
        (firewall_file, firewall_text),
        (analysis_file, analysis_text),
        (summary_file,  summary_text),
    ]:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"  Written: {path}")

    print_console_tree(root, summary_text)

    print(f"\n  Output files:")
    print(f"    {tree_file}")
    print(f"    {firewall_file}")
    print(f"    {analysis_file}")
    print(f"    {summary_file}")
    print()


if __name__ == "__main__":
    main()
