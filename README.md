# Local-AD-infrastructure

A collection of Active Directory lab environments for penetration testing practice.

Each lab is a self-contained scenario with intentionally introduced misconfigurations, designed to practice specific attack techniques end-to-end — from a low-privileged user to Domain Admin.

## Purpose

These labs are built for **hands-on practice** of Active Directory attack paths in an isolated environment. They are not CTF challenges — they are training scenarios with realistic misconfigurations you would encounter in real corporate networks.

Target audience:

- Pentesters preparing for OSCP / OSCP+ / CRTP / CRTO
- Blue teamers who want to understand attacker tradecraft
- Anyone learning AD security in a safe, reproducible setup

## Labs

| # | Name | Vector | Difficulty | Status |
|---|---|---|---|---|
| 01 | [Basic AD + AD CS](lab-01-basic-ad/) | AS-REP + ESC1 | Medium | ✅ |
| 02 | [Basic AD + RBCD](lab-02-basic-ad/) | AS-REP + RBCD | Medium | ✅ |
| 03 | [Printer Pass-Back](lab-03-basic-ad/) | Pass-Back + binPath hijack + NTDS | Hard | ✅ |
| 04 | [Kerberoast + DCSync + Golden Ticket](lab-04-basic-ad/) | AS-REP + ForceChangePassword + Kerberoast + DCSync + Golden Ticket | Hard | ✅ |

## Environment

Standard lab topology used across all scenarios:

```
┌────────────────┐    ┌────────────────┐    ┌────────────────┐
│     DC01       │    │     VICTIM     │    │     Parrot     │
│  Win Server    │────│    Win 10      │────│   Parrot OS    │
│ 192.168.31.100 │    │ 192.168.31.204 │    │     DHCP       │
│  DC + AD CS    │    │    Client      │    │   Attacker     │
└────────────────┘    └────────────────┘    └────────────────┘
```

| Component | Version |
|---|---|
| Domain Controller | Windows Server 2022 |
| Client | Windows 10 22H2 |
| Attacker | Parrot OS |
| Domain | `corp.local` |
| Subnet | `192.168.31.0/24` |

## Tools

Common tooling used across labs:

| Category | Tools |
|---|---|
| Enumeration | `nxc` (NetExec), `enum4linux-ng`, `smbclient` |
| AD Enumeration | `bloodhound-python`, `BloodHound CE` |
| Kerberos | `GetNPUsers.py`, `GetUserSPNs.py`, `getST.py` |
| Exploitation | `impacket` (`psexec.py`, `wmiexec.py`, `secretsdump.py`) |
| Cracking | `john`, `hashcat` |
| AD Abuse | `bloodyAD`, `Certipy` |
| Shells | `evil-winrm`, `psexec.py`, `wmiexec.py` |
| Infrastructure | `Flask`, `nc`, `slapd` |

## Repository Structure

The repository follows a consistent structure across all labs. Each lab lives in its own folder and follows the same internal layout.

```
Local-AD-infrastructure/
├── README.md                    # root overview + lab index
├── .gitignore
├── lab-01-basic-ad/             # Lab 01
│   ├── README.md
│   └── screenshots/
├── lab-02-basic-ad/             # Lab 02
│   ├── README.md
│   └── screenshots/
└── lab-03-basic-ad/             # Lab 03
    ├── README.md
    └── screenshots/
```

### Conventions

| Element | Rule |
|---|---|
| Lab folder | `lab-XX-<short-name>/` (e.g. `lab-03-basic-ad/`) |
| Lab README | Always `README.md` inside the lab folder |
| Screenshots | `screenshots/` subfolder, named `NN-<step>.png` (zero-padded) |

### Lab README Template

Every lab README follows the same sections:

```
# Lab XX: <Title>

## Overview              # what the lab is about
## Topology              # ASCII diagram of the environment
## Environment           # component/version table
## Attack Chain          # high-level chain (reader → Domain Admin)
## Accounts              # users involved
## Shares                # SMB shares involved
## Vulnerabilities       # vulnerability list with MITRE IDs
## Attack Steps          # step-by-step with commands + output
## Detection             # Event IDs and log sources
## Mitigation            # how to defend
## References            # external links
## Status                # WIP / Complete
```

This layout is stable: new labs are added by creating a new `lab-XX-<name>/` folder that follows the same structure — no changes to the root README are required beyond adding a row to the **Labs** table.

## How to Use

1. Deploy the lab environment (DC01 + VICTIM + attacker VM).
2. Follow the `README.md` inside each lab folder.
3. Each write-up contains:
   - **Attack Chain** — high-level overview
   - **Attack Steps** — step-by-step commands with output
   - **Detection** — Event IDs to monitor
   - **Mitigation** — how to defend against the attack

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [HackTricks — AD Methodology](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
- [The Hacker Recipes](https://www.thehacker.recipes/)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- [Impacket](https://github.com/fortra/impacket)
- [NetExec](https://github.com/Pennyw0rth/NetExec)
- [BloodyAD](https://github.com/CravateRouge/bloodyAD)

## Disclaimer

For isolated lab use only.

All techniques described in this repository are for **educational purposes** in a controlled environment. Do not use them against systems you do not own or have explicit permission to test.

## License

MIT
