<#
.CHANGELOG
# Changelog

[2.1.0] - 2025-03-13  
# Added
- Add exclusion of some attributes that are often used for some usage (PKI, S/MIME, Windows Autopilot Intune, etc.) or other functionality. It is recommended to not remove it from any property set.

# Changes
- Change Set-ADObject to use ADSI to remove the attribute from the property set because Set-ADObject seems to not work properly on some AD version

[2.0.0] - 2025-02-18  
# Added
- Add a ShouldProcess to confirm the removal of the attribute from the property set

# Changes
- Update the -ADxxx CMDlets to use `-Server $schemamaster`
- Change the `-Simulaton`to include error message 
- Change `Check-rights` function name to `Test-ADSchemaPermission` to make it more explicit

[1.0.0] - 2023-09-06
# Changes
- Initial version


#Requires -Modules ActiveDirectory

<# https://itpro-tips.com/property-set-personal-information-and-active-directory-security-and-governance/
Examples
# run the simulation before any modification
Get-ADPropertySet -PropertySetName Personal-Information | ForEach-Object {Remove-ADAttributeFromPropertySet -ADProperties $_.AttributeLDAPDisplayName -Simulation}

# Once you are sure of what you are doing, you can remove the `-Simulation` parameter.
# Note: For each property, you need to confirm the removal. If know what are doing and don't want to confirm, you can use parameter `-Confirm:$false` to bypass confirmation.
Get-ADPropertySet -PropertySetName Personal-Information | ForEach-Object { Remove-ADAttributeFromPropertySet -ADProperties $_.AttributeLDAPDisplayName }
#>


<#
#useless
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Please launch the script in admin mode. Exiting..."
    return 1
}
#>

$schemaMaster = ([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).SchemaRoleOwner
$rootDSE = Get-ADRootDSE -Server $schemaMaster
$schemaNC = $rootDSE.schemaNamingContext
$configNC = $rootDSE.configurationNamingContext

function Test-ADSchemaPermission {
    Param (
        [string[]]$AttributeDN
    )
    
    $netBIOSName = (Get-ADDomain -Server $schemaMaster).NetBIOSName
    $identities = (Get-Acl -Path "AD:$attributeDN" | Select-Object -ExpandProperty access | Where-Object { $_.ActiveDirectoryRights -like '*WriteProperty*' }).IdentityReference

    $hasRights = $false

    foreach ($identity in $identities.Value) {
        $type = $null
        $res = $null

        # identity is DOMAIN\samaccountname. We have to remove DOMAIN\. \\ to not be consider as regex
        $identityFormatted = $identity -replace ($netBIOSName + '\\'), ''
    
        $type = (Get-ADObject -Filter "samaccountname -eq '$($identityFormatted)'" -Server $schemaMaster).ObjectClass

        # if group has rights on the attribute, we found if the current user is a member of this group (in the Kerberos token)
        if ($type -eq 'group') {
            # The group membership checking is not realize against AD group because it is not relecting the current right of the user.
            # Instead we check the group membership in the Kerberos token to be more accurate
            # source : https://activedirectoryfaq.com/2016/08/read-kerberos-token-powershell/
            $groupMembership = (([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups).Translate([System.Security.Principal.NTAccount])

            $res = $groupMembership -contains $identity
        }
        else {
            $res = $env:USERNAME -eq $identity
        }

        if ($res) {
            $hasRights = $true
        }
    }

    return $hasRights
}

function Get-ADPropertySet {
    param (
        [Parameter(Mandatory = $false)]
        [string]$PropertySetName,
        [Parameter(Mandatory = $false)]
        [switch]$DoNoIncludeAttributes
    )

    # List all Property Sets and their attributes
    [System.Collections.Generic.List[PSObject]] $propertySetArray = @()

    if ($PropertySetName) {
        $filter = "rightsGuid -like '*' -and Name -like '$PropertySetName'"
    }
    else {
        $filter = "rightsGuid -like '*'"
    }
    
    # extendedRight is a controlAccessRight with validAccesses = 0x30 (48)
    $propertySets = @(Get-ADObject -Filter $filter -SearchBase "CN=Extended-Rights,$configNC" -Properties rightsGuid, validAccesses -Server $schemaMaster | Where-Object { $_.validAccesses -eq 48 })

    if ($DoNoIncludeAttributes) {
        foreach ($propertySet in $propertySets) {
            $object = [PSCustomObject][ordered]@{
                PropertySetName = $propertySet.Name
                PropertySetDN   = $propertySet.DistinguishedName
                PropertySetGUID = $propertySet.ObjectGUID
            }

            $propertySetArray.Add($object)
        }
    }
    else {
        # get all AD attributes for each property set
        if ($propertySets.Count -eq '0') {
            Write-Warning "No Property Set $PropertySetName found"
            
        }
        else {
            foreach ($propertySet in $propertySets) {

                $guid = [guid]$propertySet.rightsGuid
                $guidByteArray = $guid.ToByteArray()

                $properties = Get-ADObject -Filter { attributeSecurityGUID -eq $guidByteArray } -SearchBase $schemaNC -Properties * -Server $schemaMaster

                if ($properties.Count -eq '0') {
                    $object = [PSCustomObject][ordered]@{
                        PropertySetName           = $propertySet.Name
                        PropertySetDN             = $propertySet.DistinguishedName
                        PropertySetGUID           = $propertySet.ObjectGUID
                        AttributeName             = 'No attribute found'
                        AttributeLDAPDisplayName  = 'No attribute found'
                        AttributeAdminDescription = 'No attribute found'
                        AttributeAdminDisplayName = 'No attribute found'
                        AttributeDN               = 'No attribute found'
                    }

                    $propertySetArray.Add($object)
                }
                else {
                    foreach ($property in $properties) {
                        $object = [PSCustomObject][ordered]@{
                            PropertySetName           = $propertySet.Name
                            PropertySetDN             = $propertySet.DistinguishedName
                            PropertySetGUID           = $propertySet.ObjectGUID
                            AttributeName             = $property.Name
                            AttributeLDAPDisplayName  = $property.lDAPDisplayName
                            AttributeAdminDescription = $property.adminDescription
                            AttributeAdminDisplayName = $property.adminDisplayName
                            AttributeDN               = $property.DistinguishedName
                        }
    
                        $propertySetArray.Add($object)
                    }
                }
            }
        }
    }

    return $propertySetArray
}

function Get-ADPropertySetForAttribute {
    Param
    (
        [Parameter(Mandatory = $true)]
        [string]$Attribute
    )

    $property = $null

    try {
        $property = Get-ADObject -Filter { Name -eq $Attribute -or lDAPDisplayName -eq $Attribute } -SearchBase $schemaNC -Properties * -Server $schemaMaster -ErrorAction Stop
    }
    catch {
        Write-Warning $_.Exception.Message

    }

    if ($property) {
        if ($property.attributeSecurityGUID) {

            $propertySetGUID = New-Object Guid @(, $property.attributeSecurityGUID)

            # The Property Set are in "CN=Extended-Rights,CN=configuration,DC=domain,DC=com"
            $propertySet = Get-ADObject -Filter { rightsGuid -eq $propertySetGUID } -SearchBase "CN=Extended-Rights,$configNC" -Server $schemaMaster
                
            $object = [PSCustomObject]@{
                AttributeName             = $property.Name
                AttributeLDAPDisplayName  = $property.lDAPDisplayName
                AttributeAdminDescription = $property.adminDescription
                AttributeAdminDisplayName = $property.adminDisplayName
                AttributeDN               = $property.DistinguishedName
                PropertySetDN             = $propertySet.DistinguishedName
                PropertySetName           = $propertySet.Name
                PropertySetGUID           = $propertySet.ObjectGUID
            }
        }
        else {
            Write-Host -ForegroundColor Yellow "IGNORED: $property not part of any Property Set"
        }
    }
    else {
        Write-Warning "$ADProperty attribute not exists"
    }

    return $object
}

function Remove-ADAttributeFromPropertySet {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    Param(
        [Parameter(Mandatory = $true)]
        [string[]]$ADProperties,
        [Parameter(Mandatory = $false)]
        [switch]$Simulation
    )

    foreach ($ADProperty in $ADProperties) {
                
        $attribute = Get-ADPropertySetForAttribute -Attribute $ADProperty

        $attributesToExclude = @(
            'mSMQSignCertificates'
            'msDS-HostServiceAccount'
            'msDS-ExternalDirectoryObjectId'
            'msDS-SupportedEncryptionTypes'
            'msDS-LastSuccessfulInteractiveLogonTime'
            'msDS-LastFailedInteractiveLogonTime'
            'msDS-FailedInteractiveLogonCount'
            'msDS-FailedInteractiveLogonCountAtLastSuccessfulLogon'
            'userCert'
            'userSMIMECertificate'
            'userCertificate'
            'mSMQDigests'
        )

        if ($attribute.AttributeLDAPDisplayName -in $attributesToExclude) {
            Write-Host -ForegroundColor Yellow "The attribute $ADProperty is often used for some usage (PKI, S/MIME, Windows Autopilot Intune, etc.) or any functionality. It is recommended to not remove it from any property set."
            continue
        }

        elseif ($null -ne $attribute) {
            if (Test-ADSchemaPermission -AttributeDN $attribute.AttributeDN) {
                if ($Simulation) {
                    Write-Host -ForegroundColor Cyan "SIMULATION: Remove attribute '$($attribute.AttributeName)' from $($attribute.PropertySetDN) ($($attribute.PropertySetGuid))"
                }
                else {
                    $message = "Are you sure you want to remove attribute '$($attribute.AttributeName)' from property set '$($attribute.PropertySetName)'?"
                    if ($PSCmdlet.ShouldProcess($attribute.AttributeName, $message)) {
                        try {
                            #Set-ADObject -Identity $attribute.AttributeDN -Clear attributeSecurityGUID -ErrorAction Stop -Server $schemaMaster
                            $adObject = [ADSI]"LDAP://$($schemaMaster)/$($attribute.AttributeDN)"
                            $adObject.PutEx(1, 'attributeSecurityGUID', @())
                            $adObject.SetInfo()
                            Write-Host -ForegroundColor Green "Attribute '$($attribute.AttributeName)' removed from $($attribute.PropertySetDN) ($($attribute.PropertySetGuid))"                        
                        }
                        catch {
                            Write-Warning $_.Exception.Message
                        }
                    }
                }
            }
            else {
                Write-Warning "You don't have the rights on the schema to remove the attribute $($attribute.AttributeName) from $($attribute.PropertySetDN)"
            }
        }
    }
}