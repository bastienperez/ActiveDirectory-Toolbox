# Password

## Migrated to PSADDS

`Get-ADUserPasswordInfo.ps1` now lives in the [PSADDS](https://github.com/bastienperez/PSADDS) module and has
been removed from this repository. See its documentation and changelog for its current behaviour.

| Was here | Is now |
|---|---|
| `Get-ADUserPasswordInfo.ps1` | `Get-ADUserPasswordInfo` |

```powershell
Install-Module -Name PSADDS -Scope CurrentUser
```

## Still in this folder

`Get-ADPasswordExpirationDateWithADSI.ps1`, an ADSI variant that works without the ActiveDirectory module, and
`Get-ADObjectWithPasswordNotRequired.ps1`, which is still empty.
