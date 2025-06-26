# Use native .NET/ADSI calls instead of ActiveDirectory module
[void][System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")
[void][System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices")

# Get RootDSE using ADSI instead of Get-ADRootDSE  
$rootDSE = [ADSI]"LDAP://RootDSE"

# 'Replicating Directory Changes' and 'Replicating Directory Changes All' have the same rightsGUID
# so we check only the first one
$replicationPermission = 'Replicating Directory Changes'
$replicationAllPermission = 'Replicating Directory Changes All'
$replicationFilteredSet = 'Replicating Directory Changes in Filtered Set'

# Setup LDAP connection for searching configuration naming context
$LDAPConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($rootDSE.dnsHostName)
$configurationNC = $rootDSE.configurationNamingContext

# Function to get rightsGUID for a given display name
function Get-ControlAccessRightGuid {
    param([string]$DisplayName, [string]$ConfigNC, $Connection)
    
    $request = New-Object System.DirectoryServices.Protocols.SearchRequest(
        $ConfigNC,
        "(&(objectclass=controlAccessRight)(displayName=$DisplayName))",
        "Subtree"
    )
    [void]$request.Attributes.Add("rightsGUID")
    
    $response = $Connection.SendRequest($request)
    if ($response.Entries.Count -gt 0) {
        return [System.Guid]$response.Entries[0].Attributes["rightsGUID"][0]
    }
    return $null
}

# look for rightsGUID using native LDAP calls
$repl = Get-ControlAccessRightGuid -DisplayName $replicationPermission -ConfigNC $configurationNC -Connection $LDAPConnection
$replAll = Get-ControlAccessRightGuid -DisplayName $replicationAllPermission -ConfigNC $configurationNC -Connection $LDAPConnection
$replFiltered = Get-ControlAccessRightGuid -DisplayName $replicationFilteredSet -ConfigNC $configurationNC -Connection $LDAPConnection

# Get domain DN using native LDAP call instead of Get-ADDomain
$domainDN = $rootDSE.defaultNamingContext
$aclOnDomain = Get-ACL "AD:$domainDN"

"Replicating Directory Changes:"
[System.Collections.Generic.List[PSObject]]$dcSyncPermissionsArray = @()

$aclOnDomain.Access | Where-Object { $_.ObjectType -eq $repl -or $_.ObjectType -eq $replAll -or $_.ObjectType -eq $replFiltered } | ForEach-Object {
    
    switch ($_.ObjectType ) {
        $repl {
            $permission = $replicationPermission
            break
        }
        $replAll {
            $permission = $replicationAllPermission
            break
        }
        $replFiltered {
            $permission = $replicationFilteredSet
            break
        }
        Default {
            $permission = $null
            break
        }
    }
    

    $object = [PSCustomObject][ordered]@{
        IdentityReference = $_.IdentityReference
        Permission        = $permission
    }
    $dcSyncPermissionsArray.Add($object)
}

return $dcSyncPermissionsArray