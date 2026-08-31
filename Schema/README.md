# Schema

## Migrated to PSADDS

These scripts now live in the [PSADDS](https://github.com/bastienperez/PSADDS) module and have been removed from
this repository.

| Was here | Is now |
|---|---|
| `Get-ADAttributeInfo.ps1` | `Get-ADAttributeInfo` |
| `Get-ADAttributeInfov2.ps1` | `Get-ADAttributeInfo`, the two were merged and the `v2` suffix dropped |
| `Get-ADSchemaInfo.ps1` | `Get-ADSchemaInfo` |

```powershell
Install-Module -Name PSADDS -Scope CurrentUser
Get-ADAttributeInfo -ClassName 'user'
Get-ADSchemaInfo -ConfidentialOnly
```

The module versions keep the behaviour of the v2 script, where the two differed, and add:

- **`Source`**, which says where an attribute really comes from: defined on the class itself, inherited from a
  parent class, or brought in by an auxiliary class. On an extended schema that is what tells you which product
  owns an attribute.
- **`Confidential`** and **`CanBeConfidential`**. The first is bit 128 of `searchFlags`, which makes reading the
  attribute require `CONTROL_ACCESS`. The second says whether the attribute could carry that bit at all: it is
  ignored on base schema attributes, so an attribute can look protected while being readable by anyone.
- the rest of `searchFlags` decoded into readable columns rather than a raw integer, including `RodcFiltered` and
  `NeverAudit`. Both used to be named the other way round here, which inverted the conclusion of an audit.

## Still in this folder

Other schema scripts stay here until they are migrated in turn.
