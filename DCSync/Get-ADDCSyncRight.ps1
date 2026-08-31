<#
.SYNOPSIS
    List the principals holding the Active Directory rights that allow a DCSync attack.

.DESCRIPTION
    Reads the ACL of the domain object and returns every access control entry granting one of the three replication
    extended rights:

    - 'Replicating Directory Changes' (DS-Replication-Get-Changes, 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
    - 'Replicating Directory Changes All' (DS-Replication-Get-Changes-All, 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)
    - 'Replicating Directory Changes in Filtered Set' (1131f6ae-9c07-11d1-f79f-00c04fc2dcd2)

    Holding the first two together is what allows an account to replicate secrets out of the directory, which is the
    DCSync attack. Domain Controllers, Domain Admins, Enterprise Admins and Administrators hold them legitimately.
    Anything else in the output deserves an explanation.

    The rightsGUID of each right is read from the configuration partition rather than hardcoded, so the script keeps
    working on a forest where the display names have been localised.

    This script uses only .NET and ADSI. It does not need the ActiveDirectory PowerShell module, so it runs on a
    machine without RSAT.

.PARAMETER Server
    Domain controller to query. Defaults to the one the machine is bound to.

.EXAMPLE
    .\Get-ADDCSyncRight.ps1

    Lists the principals holding replication rights on the current domain.

.EXAMPLE
    .\Get-ADDCSyncRight.ps1 | Where-Object { $_.AccessControlType -eq 'Allow' } | Format-Table

    Same, keeping only the entries that actually grant the right. A Deny entry appears in the output too, and
    reading it as a grant is a mistake worth avoiding.

.EXAMPLE
    .\Get-ADDCSyncRight.ps1 | Group-Object IdentityReference | Where-Object { $_.Count -ge 2 }

    Shows the principals holding at least two of the rights, which is the combination a DCSync needs.

.OUTPUTS
    System.Management.Automation.PSCustomObject, one per access control entry.

.NOTES
    Author : Bastien Perez - ITPro-Tips (https://itpro-tips.com)
#>

function Get-ADDCSyncRight {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [string]$Server
    )

    $ErrorActionPreference = 'Stop'

    # LDAP path prefix, with the target domain controller when one is given
    if ([string]::IsNullOrWhiteSpace($Server)) {
        $ldapPrefix = 'LDAP://'
    }
    else {
        $ldapPrefix = "LDAP://$Server/"
    }

    try {
        $rootDSE = [ADSI]"$($ldapPrefix)RootDSE"
        $configurationNC = [string]$rootDSE.configurationNamingContext
        $domainDN = [string]$rootDSE.defaultNamingContext
    }
    catch {
        Write-Error "Unable to read the RootDSE: $($_.Exception.Message)"
        return
    }

    if ([string]::IsNullOrWhiteSpace($domainDN)) {
        Write-Error 'The RootDSE returned no defaultNamingContext, cannot locate the domain object'
        return
    }

    # The three rights are distinct, with three different rightsGUID. They are resolved by display name from the
    # configuration partition rather than hardcoded.
    $replicationPermission = 'Replicating Directory Changes'
    $replicationAllPermission = 'Replicating Directory Changes All'
    $replicationFilteredSet = 'Replicating Directory Changes in Filtered Set'

    # Resolve the rightsGUID of a control access right from its display name
    function Get-ControlAccessRightGuid {
        param (
            [string]$DisplayName,
            [string]$ConfigurationNamingContext,
            [string]$LdapPrefix
        )

        $searcher = $null

        try {
            $configurationEntry = [ADSI]"$LdapPrefix$ConfigurationNamingContext"
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($configurationEntry)
            $searcher.Filter = "(&(objectClass=controlAccessRight)(displayName=$DisplayName))"
            $null = $searcher.PropertiesToLoad.Add('rightsGuid')

            $result = $searcher.FindOne()

            if ($null -eq $result) {
                Write-Warning "Control access right '$DisplayName' not found in the configuration partition"
                return $null
            }

            return [System.Guid]$result.Properties['rightsguid'][0]
        }
        catch {
            Write-Warning "Unable to resolve the control access right '$DisplayName': $($_.Exception.Message)"
            return $null
        }
        finally {
            if ($null -ne $searcher) {
                $searcher.Dispose()
            }
        }
    }

    $rightsGuids = [ordered]@{}

    foreach ($displayName in @($replicationPermission, $replicationAllPermission, $replicationFilteredSet)) {
        $guid = Get-ControlAccessRightGuid -DisplayName $displayName -ConfigurationNamingContext $configurationNC -LdapPrefix $ldapPrefix

        if ($null -ne $guid) {
            $rightsGuids[$displayName] = $guid
        }
    }

    if ($rightsGuids.Count -eq 0) {
        Write-Error 'None of the three replication rights could be resolved, nothing to compare the ACL against'
        return
    }

    # The domain ACL, read through ADSI. Get-ACL on the 'AD:' drive would work too, but that drive is published by
    # the ActiveDirectory module, which is exactly the dependency this script avoids.
    try {
        $domainEntry = [ADSI]"$ldapPrefix$domainDN"
        $aclOnDomain = $domainEntry.ObjectSecurity
    }
    catch {
        Write-Error "Unable to read the security descriptor of '$domainDN': $($_.Exception.Message)"
        return
    }

    [System.Collections.Generic.List[PSObject]]$dcSyncPermissionsArray = @()

    # GetAccessRules is used rather than the 'Access' property: it is explicit about the identity type wanted, and
    # does not depend on a PowerShell extended property
    $accessRules = $aclOnDomain.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])

    foreach ($accessRule in $accessRules) {

        $permission = $null

        foreach ($rightsGuid in $rightsGuids.GetEnumerator()) {
            if ($accessRule.ObjectType -eq $rightsGuid.Value) {
                $permission = $rightsGuid.Key
                break
            }
        }

        if ($null -eq $permission) {
            continue
        }

        $object = [PSCustomObject][ordered]@{
            IdentityReference = $accessRule.IdentityReference
            Permission        = $permission
            AccessControlType = $accessRule.AccessControlType
            IsInherited       = $accessRule.IsInherited
        }

        $dcSyncPermissionsArray.Add($object)
    }

    return $dcSyncPermissionsArray
}
