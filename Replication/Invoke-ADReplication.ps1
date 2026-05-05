(Get-ADDomainController -Filter *).Name | Foreach-Object {
    $null = repadmin /syncall $_ (Get-ADDomain).DistinguishedName /e /A
}
Start-Sleep 10
Get-ADReplicationPartnerMetadata -Target "$env:userdnsdomain" -Scope Domain | Select-Object Server, LastReplicationSuccess