# Local-AD-infrastructure

A collection of Active Directory lab environments for penetration testing practice.

## Purpose
Each lab is a standalone AD infrastructure with intentionally introduced vulnerabilities.  
Attacks are performed in an isolated VirtualBox environment.

## Labs

| # | Name | Vector | Difficulty |
|---|---|---|---|
| [01](lab-01-basic-ad/) | Basic AD + AD CS | AS-REP + ESC1 | Medium |

## Common Infrastructure
- **DC01**: Windows Server 2022
- **VICTIM**: Windows 10
- **Attacker**: Parrot OS
- **Domain**: `corp.local`

## Disclaimer
All activities are performed in an isolated lab environment.  
Do not use against real systems.
