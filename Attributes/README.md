# Attributes

## Migrated to PSADDS

The replication metadata scripts now live in the [PSADDS](https://github.com/bastienperez/PSADDS) module and
have been removed from this repository. See its documentation and changelog for their current behaviour.

| Was here | Is now |
|---|---|
| `Get-ADObjectMedata.ps1` | `Get-ADObjectMetadata` |
| `Get-ADGroupMembershipMedata.ps1` | `Get-ADGroupMembershipMetadata` |

```powershell
Install-Module -Name PSADDS -Scope CurrentUser
```

## Still in this folder

`Get-ADObjectUserCertificate.ps1`, `Get-AnonymousLDAPBindState.ps1`, `Get-SIDHistory.ps1` and `PropertySet/`.
