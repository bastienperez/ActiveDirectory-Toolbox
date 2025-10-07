<#
.SYNOPSIS
    Get Active Directory Object Metadata

.DESCRIPTION
    This script retrieves metadata for a specified Active Directory object, including details about attribute changes.
    It can filter the metadata based on specified attributes and can target a specific domain controller if needed.

.PARAMETER ObjectDN
    The distinguished name (DN) of the Active Directory object for which metadata is to be retrieved.

.PARAMETER Attributes
    An optional array of attribute names to filter the metadata results. If not specified, metadata for all attributes will be returned.

.PARAMETER DomainController
    An optional parameter to specify a particular domain controller to query. If not provided, the default domain controller will be used.

.EXAMPLE
    Get-ADObjectMetadata 'CN=John Doe,OU=Users,DC=example,DC=com'

    Retrieves metadata for the specified user object.

.EXAMPLE
    Get-ADObjectMetadata 'CN=John Doe,OU=Users,DC=example,DC=com' -Attributes sn, cn

    Retrieves metadata for the specified user object, filtering to show only the 'sn' and 'cn' attributes.

.EXAMPLE
    Get-ADObjectMetadata 'CN=John Doe,OU=Users,DC=example,DC=com' -DomainController 'dc01.example.com'

    Retrieves metadata for the specified user object from the specified domain controller.

.NOTES
Author: Bastien Perez
Date: 2025-10-07
Version: 1.1.0

.CHANGELOG
[1.1.0] - 2025-10-07
# Added
- Add script parameters `-DomainController` to specify a domain controller.
- Add possibility to search the object with anr (samaccountname, cn, etc.) if the DN is not found.

[1.0.0] - 2023-xx-xx
# Initial version  

#>

function Get-ADObjectMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [String] $ObjectDN,
        [Parameter(Mandatory = $false, Position = 1)]
        [String[]] $Attributes,
        [Parameter(Mandatory = $false)]
        [String] $DomainController
    )

    try {
        $null = Import-Module ActiveDirectory
    }
    catch {
        Write-Warning 'Unable to load ActiveDirectory module'
        return 1
    }

    if (-not $DomainController) {
        $DomainController = (Get-ADDomainController -Discover -Service ADWS).HostName
    }
    
    [System.Collections.Generic.List[PSObject]] $objectMetadataArray = @()

    try {
        $adObject = Get-ADObject $ObjectDN -Properties 'msDS-ReplAttributeMetaData' -Server $DomainController -ErrorAction Stop
    }
    catch {
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1a9177f4-0272-4ab8-aa22-3c3eafd39e4b
        Write-Warning "Unable to find object $ObjectDN (maybe you don't use a Distinguished Name (DN), the script will try to find it with anr=$ObjectDN)"
        
        try {
            $adObject = Get-ADObject -LDAPFilter "(anr=$ObjectDN)" -Properties 'msDS-ReplAttributeMetaData' -Server $DomainController -ErrorAction Stop

            if ( $adObject.Count -gt 1 ) {
                Write-Warning "Multiple objects found with (anr=$ObjectDN), please use the exact Distinguished Name (DN) of the object"
                return 1
            }
            elseif (-not $adObject) {
                Write-Warning "No object found with (anr=$ObjectDN), please check the DN or the name of the object"
                return 1
            }
            else {
                Write-Host -ForegroundColor Cyan "Object found, DN: $($adObject.DistinguishedName)"
            }
        }
        catch {
            Write-Warning "Unable to find object $ObjectDN with Get-ADObject -LDAPFilter (anr=$ObjectDN), please check the DN or the name of the object"
            return 1
        }
    }

    $replAttributeMetaData = $adObject.'msDS-ReplAttributeMetaData'
    $replAttributeMetaData = '<root>' + $ReplAttributeMetaData + '</root>'
    $replAttributeMetaData = $ReplAttributeMetaData.Replace([char]0, ' ')
    $replAttributeMetaData = [XML]$ReplAttributeMetaData
    $replAttributeMetaData = $ReplAttributeMetaData.root.DS_REPL_ATTR_META_DATA

    # get only attributes that are specified
    if ($Attributes) {
        foreach ($attribute in $attributes) {
            $attributeMetadata = $replAttributeMetaData | Where-Object { $_.pszAttributeName -eq $attribute }

            $object = [PSCustomObject][ordered]@{
                AttributeName             = $attributeMetadata.pszAttributeName
                Version                   = $attributeMetadata.dwVersion
                TimeLastOriginatingChange = $attributeMetadata.ftimeLastOriginatingChange
                usnOriginatingChange      = $attributeMetadata.usnOriginatingChange
                usnLocalChange            = $attributeMetadata.usnLocalChange
                LastOriginatingDsaDN      = $attributeMetadata.pszLastOriginatingDsaDN
            }

            $objectMetadataArray.Add($object)
        }
    }
    else {
        $replAttributeMetaData | ForEach-Object {

            $object = [PSCustomObject][ordered]@{
                AttributeName             = $_.pszAttributeName
                Version                   = $_.dwVersion
                TimeLastOriginatingChange = $_.ftimeLastOriginatingChange
                usnOriginatingChange      = $_.usnOriginatingChange
                usnLocalChange            = $_.usnLocalChange
                LastOriginatingDsaDN      = $_.pszLastOriginatingDsaDN
            }

            $objectMetadataArray.Add($object)
        }
    }

    return $objectMetadataArray
}