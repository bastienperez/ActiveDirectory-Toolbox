# Computers

The computer account functions live in the **PSADDS** module: https://github.com/bastienperez/PSADDS

| Function | Purpose |
|---|---|
| `Get-ADComputerJoinedByUser` | Audit: who joined which machine to the domain (`ms-DS-CreatorSID` and object owner) |
| `Reset-ADComputerAccountSecurity` | Remediation: restore the default owner and permissions of a computer account |

Both read the owner of a computer object (`nTSecurityDescriptor`) and complement each other, so they share
the owner lookup and chain in a pipeline.

`Get-ADComputerJoinedByUser` was published here as `Get-ComputersAddedByUsers.ps1`.
