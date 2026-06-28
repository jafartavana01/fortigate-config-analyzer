# FortiGate Configuration Analyzer

A comprehensive, standalone Python CLI tool that performs deep security analysis on FortiGate firewall configuration exports. No dependencies beyond Python 3.10+ standard library — just one script, one command.

```bash
python fortigate_Analyzer.py sample-config.conf
```

---

## What It Does

Parses a raw FortiGate `.conf` export and audits **18 subsystems** against security best practices. Produces four structured output files plus a live terminal summary.

### Output Files

| File | Contents |
|------|----------|
| `<name>_tree.txt` | Full visual tree of every config block and setting |
| `<name>_firewall.txt` | Firewall rules in hierarchical detail, with all linked UTM profiles expanded inline |
| `<name>_analysis.txt` | Per-subsystem security findings with severity, explanation, and exact remediation CLI commands |
| `<name>_summary.txt` | Executive summary with overall risk score, finding counts, and top priority actions |

---

## Subsystems Audited

| # | Subsystem | Key Checks |
|---|-----------|------------|
| 1 | **System Global** | Admin timeout, strong-crypto, SSH CBC/HMAC-MD5, TLS version for admin HTTPS, lockout policy |
| 2 | **Interfaces** | Insecure protocols (HTTP, Telnet, FTP) on any interface; WAN management exposure (SSH, SNMP, ping) |
| 3 | **Admin Accounts** | Default `admin` account, super-admin without 2FA, any admin without 2FA |
| 4 | **Password Policy** | Minimum length, complexity requirements, expiry |
| 5 | **DNS** | Public resolver risk, missing DNS config |
| 6 | **NTP** | Sync status, server configuration |
| 7 | **SNMP** | Default/weak community strings (`public`, `private`), unrestricted host access |
| 8 | **High Availability** | Standalone mode risk, HA password |
| 9 | **Routing** | OSPF authentication, BGP config, router-id stability |
| 10 | **Firewall Policy** | ANY-ANY-ANY rules, logging disabled, no UTM profiles, missing AV/IPS |
| 11 | **SSL/SSH Inspection** | Deep inspection mode, cert validation (expired/revoked/untrusted), minimum TLS 1.2, CA config, anomaly logging |
| 12 | **Antivirus** | Per-protocol scanning, outbreak prevention (zero-day cloud detection) |
| 13 | **IPS** | Sensor configuration, block action for high/critical severity signatures |
| 14 | **Web Filter** | HTTPS scanning, FortiGuard category filtering, fail-open vs fail-closed |
| 15 | **Application Control** | Rule entries, risky category blocking |
| 16 | **VPN (IPsec)** | IKEv1 vs IKEv2, weak algorithms (DES, 3DES, MD5, SHA-1), weak DH groups (1, 2, 5), PFS on phase2, DPD, key lifetimes |
| 17 | **Local Users** | 2FA per user account |
| 18 | **Logging** | Syslog server, implicit deny logging, extended logging |

---

## Severity Levels

| Icon | Level | Score Deduction | Meaning |
|------|-------|-----------------|---------|
| ✖ | CRITICAL | −3.0 | Immediate exploitation risk or complete security control bypass |
| ⚠ | HIGH | −2.0 | Significant weakness that should be addressed urgently |
| ◆ | MEDIUM | −1.0 | Configuration weakness that reduces defence-in-depth |
| ● | LOW | −0.5 | Minor gap or hardening improvement |
| ℹ | INFO | 0 | Informational observation, no score impact |

Overall score starts at **10.0** and deductions are applied per finding.

---

## Example Terminal Output

```
╔════════════════════════════════════════════════════════════════════╗
║             FortiGate Configuration Analyzer                      ║
╚════════════════════════════════════════════════════════════════════╝

  Config sections found:
  ├─ [config system global]  (12 settings)
  ├─ [config system interface]  (3 entries)
  ├─ [config system admin]  (2 entries)
  ├─ [config firewall policy]  (4 entries)
  ├─ [config antivirus profile]  (2 entries)
  ├─ [config ips sensor]  (2 entries)
  ├─ [config vpn ipsec phase1-interface]  (1 entry)
  └─ [config log syslog setting]  (5 settings)

  OVERALL SECURITY SCORE : 3.5 / 10   [CRITICAL RISK]
  [███░░░░░░░]  3.5/10

  ✖ CRITICAL  :   3 findings
  ⚠ HIGH      :  11 findings
  ◆ MEDIUM    :   8 findings
  ● LOW       :   5 findings
```

---

## Example Analysis Output (excerpt)

```
════════════════════════════════════════════════════════════════════════════════
  SUBSYSTEM: VPN › IPsec
  Status  : ✖ CRITICAL ISSUES   Score: 0.0/10
════════════════════════════════════════════════════════════════════════════════

  ✖ [CRITICAL] VPN 'VPN-OFFICE': weak Diffie-Hellman groups
  ──────────────────────────────────────────────────────────────────────────────
    Detail: DH groups {'2', '5'} use keys smaller than 2048 bits. These are
            vulnerable to Logjam and similar attacks.

    Remediation:
      config vpn ipsec phase1-interface
          edit "VPN-OFFICE"
              set dhgrp 14 19 20
          next
      end
```

---

## Example Firewall Report (excerpt)

```
┌─────────────────────────────────────────────────────────────────────────────
│  Rule ID: 1   Name: 'LAN-to-WAN'   Action: ✔ ACCEPT
│─────────────────────────────────────────────────────────────────────────────
│  Traffic Flow:
│      Source Interface  : lan
│      Source Address    : LAN_SUBNET
│      Destination Intf  : wan1
│      Destination Addr  : ALL
│      Service           : ALL
│      NAT               : enable
│      Log Traffic       : all
│
│  UTM / Security Profiles  [ENABLED]
│      ├─ AV Profile: 'default'
│      │   Comment : Default AV profile
│      │   HTTP: av-scan=enable  outbreak-prevention=disable
│      │   SMTP: av-scan=enable  outbreak-prevention=disable
│      ├─ IPS Sensor: 'default'
│      │   Entry 1: severity=medium high critical  action=block
│      ├─ Web Filter: 'default'
│      │   Options  : https-scan
│      │   Category 26: block
└─────────────────────────────────────────────────────────────────────────────
```

---

## Usage

```bash
# Basic usage
python fortigate_Analyzer.py firewall.conf

# Use the included sample config to test immediately
python fortigate_Analyzer.py sample-config.conf
```

Requires **Python 3.10+**. No third-party packages needed.

---

## Who Is This For

- **Network Security Engineers** auditing FortiGate deployments
- **Security consultants** performing firewall configuration reviews
- **SOC / Blue Team** analysts checking hardening status
- **CCIE / security students** learning FortiGate best practices

---

## Roadmap

- [ ] HTML report output with interactive findings
- [ ] VDOM-aware parsing
- [ ] Comparison mode (diff two configs)
- [ ] CVE cross-reference for VPN and SSL weaknesses
- [ ] Integration with FortiGate REST API (live pull)
- [ ] YAML-configurable rule weights

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Author

Built with ❤️ for the network security community.
