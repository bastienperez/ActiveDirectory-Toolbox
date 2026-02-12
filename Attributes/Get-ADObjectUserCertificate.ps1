<#
    .SYNOPSIS
    Retrieves user certificates from Active Directory objects.

    .DESCRIPTION
    This function searches for and retrieves user certificates stored in Active Directory objects.
    It can search specific objects by name, or search all objects of specified types (Users, Computers, or All objects).
    The function retrieves certificates from UserCertificate, UserSMIMECertificate, and userCert attributes.

    .PARAMETER Name
    The name of a specific AD object to retrieve certificates from. This parameter accepts pipeline input.

    .PARAMETER DomainController
    Array of domain controller names to query. If not specified, uses the current domain.

    .PARAMETER QueryAllDCs
    Switch to query all available domain controllers in the domain.

    .PARAMETER ObjectType
    Specifies the type of AD objects to search. Valid values are 'All', 'Users', or 'Computers'.
    Default value is 'All'.

    .EXAMPLE
    Get-ADObjectUserCertificate
    
    Retrieves certificates from all AD objects in the current domain.

    .EXAMPLE
    Get-ADObjectUserCertificate -ObjectType "Users"
    
    Retrieves certificates from all user objects only.

    .EXAMPLE
    Get-ADObjectUserCertificate -Name "john.doe"
    
    Retrieves certificates from a specific user named john.doe.

    .EXAMPLE
    Get-ADObjectUserCertificate -QueryAllDCs -ObjectType "Computers"
    
    Retrieves certificates from all computer objects across all domain controllers.

    .EXAMPLE
    Get-ADObjectUserCertificate | Where-Object { $_.NotBefore -gt (Get-Date).AddDays(-7) }
    
    Retrieves all certificates and filters to show only those issued within the last 7 days.

    .EXAMPLE
    Get-ADObjectUserCertificate | Where-Object { $_.NotBefore -gt (Get-Date).AddDays(30) }

    Retrieves all certificates and filters to show only those that will expire within the next 30 days.

    .EXAMPLE
    Get-ADObjectUserCertificate | Where-Object { $_.NotBefore -gt (Get-Date).AddDays(-7) }
    
    Retrieves all certificates and filters to show only those issued within the last 7 days.

    .OUTPUTS
    System.Management.Automation.PSCustomObject
    Returns objects with certificate details including Name, DisplayName, Issuer, Subject, validity dates, etc.

    .NOTES
    Requires Active Directory PowerShell module.
    The function searches for certificates in UserCertificate, UserSMIMECertificate, and userCert attributes.
#>
    
function Get-ADObjectUserCertificate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [String]$Name,
        [Parameter(Mandatory = $false)]
        [String[]]$DomainController,
        [Parameter(Mandatory = $false)]
        [switch]$QueryAllDCs,
        [Parameter(Mandatory = $false)]
        [ValidateSet('All', 'Users', 'Computers')]
        [String]$ObjectType = 'All'
    )    
    
    [System.Collections.Generic.List[PSObject]]$certificatesArray = @()

    if ($QueryAllDCs.IsPresent) {
        # get all domain controllers
        $DomainController = (Get-ADDomainController -Filter *).Name
    }
    elseif (-not ($DomainController)) {
        $DomainController = $env:USERDNSDOMAIN
    }

    foreach ($DC in $DomainController) {

        if ($Name) {
            # Search by name using string filter with embedded values
            $computerName = "$Name$"
            $adObjectsWithCertificate = Get-ADObject -Filter "(Name -eq '$Name' -or SamAccountName -eq '$Name' -or SamAccountName -eq '$computerName') -and (UserCertificate -like '*' -or userCert -like '*' -or UserSMIMECertificate -like '*')" -Properties * -Server $DC
        }
        elseif ($ObjectType -eq 'Users') {
            $adObjectsWithCertificate = Get-ADObject -Filter { objectClass -eq 'user' -and (UserCertificate -like '*' -or userCert -like '*' -or UserSMIMECertificate -like '*') } -Properties * -Server $DC
        }
        elseif ($ObjectType -eq 'Computers') {
            $adObjectsWithCertificate = Get-ADObject -Filter { objectClass -eq 'computer' -and (UserCertificate -like '*' -or userCert -like '*' -or UserSMIMECertificate -like '*') } -Properties * -Server $DC
        }
        else {
            $adObjectsWithCertificate = Get-ADObject -Filter { UserCertificate -like '*' -or userCert -like '*' -or UserSMIMECertificate -like '*' } -Properties * -Server $DC
        }

        foreach ($adObject in $ADObjectsWithCertificate) {
            [System.Collections.Generic.List[PSObject]]$certificates = @()

            if ($adObject.UserCertificate) {
                $adObject | Select-Object -ExpandProperty usercertificate | ForEach-Object {
                    $certificates.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]$_)
                }
            }
            if ($adObject.UserSMIMECertificate) {
                $adObject | Select-Object -ExpandProperty UserSMIMECertificate | ForEach-Object {
                    $certificates.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]$_)
                }
            }
            if ($adObject.userCert) {
                $adObject | Select-Object -ExpandProperty userCert | ForEach-Object {
                    $certificates.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]$_)
                }
            }

            foreach ($certificate in $certificates) {
                $object = [PSCustomObject][ordered]@{
                    Name               = $adObject.Name
                    DisplayName        = $adObject.displayname
                    DistinguishedName  = $adObject.DistinguishedName
                    IssuedTo           = $certificate.Subject
                    IssuedBy           = $certificate.Issuer
                    IntendedPurpose    = $certificate.EnhancedKeyUsageList
                    NotBefore          = $certificate.NotBefore
                    NotAfter           = $certificate.NotAfter
                    SerialNumber       = $certificate.SerialNumber
                    Thumbprint         = $certificate.Thumbprint
                    ObjectClass        = $adObject.ObjectClass
                    CertDnsNameList    = $certificate.DnsNameList
                    IssuerName         = $certificate.IssuerName.Name
                    SubjectName        = $certificate.SubjectName.Name
                    SignatureAlgorithm = $certificate.SignatureAlgorithm.FriendlyName
                    FromDC             = $DC
                }

                $certificatesArray.Add($object)
            }
        }
    }

    return $certificatesArray
}