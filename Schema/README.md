# Schema

## Migrated to PSADDS

These scripts now live in the [PSADDS](https://github.com/bastienperez/PSADDS) module and have been removed from
this repository. Every schema function there is named `Get-ADSchema*`, so `Get-ADSchema` plus Tab lists the whole
family.

| Was here | Is now |
|---|---|
| `Get-ADSchemaInfo.ps1` | `Get-ADSchemaAttribute`, one row per attribute of the schema |
| `Get-ADAttributeInfo.ps1` | `Get-ADSchemaClassAttribute`, one row per class and attribute pair |
| `Get-ADAttributeInfov2.ps1` | `Get-ADSchemaClassAttribute`, the two versions were merged and the `v2` suffix dropped |
| `Get-ADAttributesFromClassName.ps1` | `Get-ADSchemaClassAttribute -ClassName`, which already did the same walk and reports more |
| `Get-ADSchemaRelatedClass.ps1` | `Get-ADSchemaRelatedClass` |
| `Get-ADSchemaClassPossibleChildren.ps1` | `Get-ADSchemaClassPossibleChildren` |
| `Get-ADSchemaVersion.ps1` | `Get-ADSchemaVersion` |

```powershell
Install-Module -Name PSADDS -Scope CurrentUser
Get-ADSchemaClassAttribute -ClassName 'user'
Get-ADSchemaAttribute -ConfidentialOnly
```

## What changed on the way

Beyond the move, the module versions fix and add the following.

**Confidentiality of an attribute**, in both `Get-ADSchemaAttribute` and `Get-ADSchemaClassAttribute`:

- `Confidential` is bit 128 of `searchFlags`, which makes reading the attribute require `CONTROL_ACCESS` rather
  than a plain `READ_PROPERTY`.
- `CanBeConfidential` says whether the attribute could carry that bit at all. It is ignored on base schema
  attributes, so an attribute can look protected while being readable by anyone. `Confidential` true with
  `CanBeConfidential` false is worth a look on any audit.

**Where an attribute comes from**, in `Get-ADSchemaClassAttribute`: the `Source` column names the class an
attribute is really defined on, whether the class itself, a parent, or an auxiliary class. On an extended schema
that is what tells you which product owns an attribute.

**Bugs fixed:**

- the `searchFlags` decoding subtracted 15 instead of 16 on bit 16, so an attribute carrying it was reported as
  indexed by mistake;
- `RODCenabled` was set to true for bit 512, which means the exact opposite: the attribute is filtered out and
  never replicated to a read only domain controller. Renamed `RodcFiltered`;
- `AttributeAuditing` was set to true for bit 256, which disables auditing. Renamed `NeverAudit`;
- `Get-ADSchemaRelatedClass` recursed into `Get-RelatedClass`, a name that existed nowhere, so it failed on any
  class having a parent;
- `Get-ADSchemaClassPossibleChildren` built the distinguished name as `CN=<ldapDisplayName>`, which only works when
  the common name of a class equals its LDAP display name. It failed on `organizationalUnit`, whose common name is
  `Organizational-Unit`.

## Still in this folder

`Get-ADControlAccessRights.ps1` and `New-AttributeOID.ps1`, plus `VulnerableSchemas/`. They will be migrated in
turn.
