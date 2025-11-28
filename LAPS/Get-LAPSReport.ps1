function Get-LAPSReport {
    [CmdletBinding()]
    param (
        [Switch]$IncludeComputersWithoutLAPS,
        [Switch]$IncludePasswordsAsPlainText,
        [Switch]$OnlyComputersWithoutLAPS,
        [String]$OnlyComputersInGroup,
        [Switch]$NoCheckLAPSPermissions,
        [Switch]$LegacyLAPSOnly,
        [Switch]$WindowsLAPSOnly
    )
    
    [System.Collections.Generic.List[PSObject]]$lapsReport = @()
    
    #Edit the following variable to specify the domain or OU to search (e.g. workstations or servers) 
    $searchBase = (Get-ADDomain).DistinguishedName

    #Specify exclusions for OUs which should be skipped, use distinguished name separated by | 
    $exclusions = 'OU=Domain Controllers' 

    #Run query against the PDC emulator
    $DC = (Get-ADDomain).PDCEmulator

    $now = [DateTime]::Now.ToFileTimeUtc().ToString() 

    [System.Collections.Generic.List[PSObject]]$properties = @('canonicalname', 'lastlogontimestamp', 'pwdlastset', 'OperatingSystem', 'Enabled')
    $legacyLAPSAttributes = @('ms-Mcs-AdmPwdExpirationTime')
    $windowsLAPSAttributes = @('msLAPS-Password', 'msLAPS-EncryptedPassword', 'msLAPS-EncryptedDSRMPassword', 'msLAPS-PasswordExpirationTime', 'msLAPS-EncryptedPasswordHistory', 'msLAPS-EncryptedDSRMPasswordHistory')
    
    if ($LegacyLAPSOnly) {
        $legacyLAPSAttributes | ForEach-Object { $properties.Add($_) }
    }

    <#
    msLAPS-Password
    msLAPS-EncryptedPassword
    msLAPS-EncryptedDSRMPassword
    msLAPS-PasswordExpirationTime
    msLAPS-EncryptedPasswordHistory
    msLAPS-EncryptedDSRMPasswordHistory

    #>
    elseif ($WindowsLAPSOnly) {
        $windowsLAPSAttributes | ForEach-Object { $properties.Add($_) }
    }
    # get both legacy and Windows LAPS attributes
    else {
        $legacyLAPSAttributes | ForEach-Object { $properties.Add($_) }
        $windowsLAPSAttributes | ForEach-Object { $properties.Add($_) }
    }

    if ($IncludePasswordsAsPlainText) {
        $properties.Add('ms-MCS-AdmPwd')
    }

    if ($OnlyComputersInGroup) {
        $properties.Add('memberOf')
    }
    #LDAP query for LAPS ExpirationTime
    if ($IncludeComputersWithoutLAPS -or $OnlyComputersWithoutLAPS) {
        $filter = '*'
    }
    else {
        $filter = 'ms-Mcs-AdmPwdExpirationTime -like "*" -or msLAPS-PasswordExpirationTime -like "*"'
    }

    # only check computers in a specific group
    if ($OnlyComputersInGroup) {
        #$computers = Get-ADComputer -Filter $filter -Properties $properties | Where-Object { $_.MemberOf -like "*CN=$OnlyComputersInGroup*" }
        # * instead of $properties because we don't know which LAPS attributes are present
        $computers = Get-ADComputer -Filter $filter -Properties * | Where-Object { $_.MemberOf -like "*$OnlyComputersInGroup*" }
    }
    else {
        $computers = Get-ADComputer -Filter $filter -Server $DC -SearchBase $searchBase -Properties *
    }

    if ($null -ne $exclusions) {
        $computers = $computers | Where-Object { $_.DistinguishedName -notmatch $exclusions }
    }

    # Permission check on the 'ms-Mcs-AdmPwd' attribute in the schema
    # before the foreach loop to avoid multiple calls to Get-ADObject
    if (-not $NoCheckLAPSPermissions) {
        $legacyLapsSchemaAttribute = $null
        $windowsLapsSchemaAttribute = $null
        $windowsLapsEncryptedSchemaAttribute = $null

        # erroraction silentlycontinue to avoid error if the attribute does not exist
        $legacyLapsSchemaAttribute = Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Server $DC -LDAPFilter '(ldapDisplayName=ms-Mcs-AdmPwd)' -Properties schemaIDGuid -ErrorAction SilentlyContinue
        if ($legacyLapsSchemaAttribute) {
            $legacyLapsSchemaGUID = ([system.guid]$legacyLapsSchemaAttribute.schemaIDGuid).guid
        }
        
        $windowsLapsSchemaAttribute = Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Server $DC -LDAPFilter '(ldapDisplayName=msLAPS-Password)' -Properties schemaIDGuid -ErrorAction SilentlyContinue
        if ($windowsLapsSchemaAttribute) {
            $windowsLapsSchemaGUID = ([system.guid]$windowsLapsSchemaAttribute.schemaIDGuid).guid
        }

        <# useless because use AuthorizedDecryptor and the part of codebelow  is not accuareete
        $windowsLapsEncryptedSchemaAttribute = Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Server $DC -LDAPFilter '(ldapDisplayName=msLAPS-EncryptedPassword)' -Properties schemaIDGuid -ErrorAction SilentlyContinue
        if ($windowsLapsEncryptedSchemaAttribute) {
            $windowsLapsEncryptedSchemaGUID = ([system.guid]$windowsLapsEncryptedSchemaAttribute.schemaIDGuid).guid
        }
        #>

        <#
        $legacyLapsSchemaGUID = ([system.guid](Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Server $DC -LDAPFilter "(ldapDisplayName=ms-Mcs-AdmPwd)" -Properties schemaIDGuid -ErrorAction SilentlyContinue).schemaIDGuid).guid
        $windowsLapsSchemaGUID = ([system.guid](Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Server $DC -LDAPFilter "(ldapDisplayName=msLAPS-Password)" -Properties schemaIDGuid -ErrorAction SilentlyContinue).schemaIDGuid).guid
        $windowsLapsEncryptedSchemaGUID = ([system.guid](Get-ADObject -SearchBase (Get-ADRootDSE).SchemaNamingContext -Server $DC -LDAPFilter "(ldapDisplayName=msLAPS-EncryptedPassword)" -Properties schemaIDGuid -ErrorAction SilentlyContinue).schemaIDGuid).guid
        #>
    }

    if ($OnlyComputersWithoutLAPS) {
        $computers = $computers | Where-Object { -not $_.'ms-MCS-AdmPwdExpirationTime' }
    }
    
    # Get the ACL of each computer object
    foreach ($computer in $computers) {    
        $legacyLapsPwdExpired = $false
        $legacyLapsEnabled = $false
        $legacyLapsExpirationDate = 'null'
        $windowsLapsEnabled = $false
        $windowsLapsPwdExpired = $false
        $windowsLapsExpirationDate = 'null'

        if ($computer.'ms-MCS-AdmPwdExpirationTime') {
            $legacyLapsEnabled = $true
            $legacyLapsExpirationDate = [datetime]::FromFileTime($computer.'ms-MCS-AdmPwdExpirationTime').ToString('yyyy/MM/dd HH:mm')

            if ($computer.'ms-MCS-AdmPwdExpirationTime' -and $computer.'ms-MCS-AdmPwdExpirationTime' -lt $now) {
                $legacyLapsPwdExpired = $true
            }
        }

        if ($computer.'msLAPS-PasswordExpirationTime') {
            $windowsLapsEnabled = $true
            $windowsLapsExpirationDate = [datetime]::FromFileTime($computer.'msLAPS-PasswordExpirationTime').ToString('yyyy/MM/dd HH:mm')

            if ($computer.'msLAPS-PasswordExpirationTime' -and $computer.'msLAPS-PasswordExpirationTime' -lt $now) {
                $windowsLapsPwdExpired = $true
            }
        }

        $WindowsLAPS = Get-LapsADPassword -Identity $computer.DistinguishedName

        $object = [PSCustomObject][ordered]@{
            ComputerName                   = $computer.Name
            ComputerDistinguishedName      = $computer.DistinguishedName
            WindowsLapsEnabled             = $windowsLapsEnabled
            WindowsLapsExpirationDate      = $windowsLapsExpirationDate
            WindowsLapsPwdExpired          = $windowsLapsPwdExpired
            WindowsLAPSaccount             = $WindowsLAPS.Account
            WindowsLapsExpirationTimestamp = $WindowsLAPS.ExpirationTimestamp
            WindowsLapsPasswordUpdateTime  = $WindowsLAPS.PasswordUpdateTime            
            WindowsLapsSource              = $WindowsLAPS.Source
            WindowsLapsDecryptionStatus    = $WindowsLAPS.DecryptionStatus
            WindowsLapsAuthorizedDecryptor = $WindowsLAPS.AuthorizedDecryptor
            LegacyLapsEnabled              = $legacyLapsEnabled
            LegacyLapsExpirationDate       = $legacyLapsExpirationDate
            LegacyLapsPwdExpired           = $legacyLapsPwdExpired
            ComputerOperatingSystem        = $computer.OperatingSystem
            ComputerLastLogon              = [datetime]::FromFileTime($computer.lastlogontimestamp).ToString('yyyy/MM/dd HH:mm')
            ComputerPwdLastSet             = [datetime]::FromFileTime($computer.pwdlastset).ToString('yyyy/MM/dd HH:mm')
            ComputerEnabled                = $computer.Enabled
        }

        if (-not $NoCheckLAPSPermissions) {

            # Filter identities with ExtendedRight on the ms-Mcs-AdmPwd and LAPS attribute or all extended attributes (00000000-0000-0000-0000-000000000000),  Full Control (GenericAll) (GenericWriteAll does not contains Extended attributes so not used)
            if ($legacyLapsSchemaGUID) {

            
                $legacyLAPSACLsAccess = ((Get-Acl -Path "AD:$($computer.DistinguishedName)").access | Where-Object { (($_.ActiveDirectoryRights -match 'ExtendedRight' -and ( ($_.ObjectType -eq $legacyLapsSchemaGUID) -or ($_.ObjectType -eq '00000000-0000-0000-0000-000000000000') )) -or ($_.ActiveDirectoryRights -like '*GenericAll*')) }).IdentityReference 
                <#
            [Commented because Find-AdmPwdExtendedRights from AdmPwd does not work on specific object. If we parse to get parent and include computers, this CMDlet does not return inherited permissions]
            $parent = (Get-ADcomputer -Identity $computer | Select-Object @{Name = 'Parent'; Expression = { ([adsi]"LDAP://$($_.DistinguishedName)").Parent.Replace('LDAP://', '') } }).Parent
            $admPwdExtendedRights = Find-AdmPwdExtendedRights -Identity $parent -IncludeComputers
    
            $whoCanReadLAPSPwd = ($admPwdExtendedRights | Where-Object { $_.ObjectDN -eq "$($computer.distinguishedName)" })
    
            #>
                [System.Collections.Generic.List[String]]$WhoCanReadLegacyLAPSPwd = @()
                foreach ($access in $legacyLAPSACLsAccess) {
                    # if SID, we try to resolve it
                    if ($access -like 'S-1-5-32*') {
                        $access = (Get-ADGroup -Identity $access -Server $DC).Name
                    }
    
                    $WhoCanReadLegacyLAPSPwd.Add($access)
                }

                $object | Add-Member -MemberType NoteProperty -Name WhoCanReadLegacyLAPSPwd -Value ($WhoCanReadLegacyLAPSPwd -join '|')

            }

            if ($windowsLapsSchemaGUID) {
                $windowsLAPSACLsAccess = ((Get-Acl -Path "AD:$($computer.DistinguishedName)").access | Where-Object { (($_.ActiveDirectoryRights -match 'ExtendedRight' -and ( ($_.ObjectType -eq $windowsLapsSchemaGUID) -or ($_.ObjectType -eq '00000000-0000-0000-0000-000000000000') )) -or ($_.ActiveDirectoryRights -like '*GenericAll*')) }).IdentityReference
        
                [System.Collections.Generic.List[String]]$whoCanReadWindowsLapsPwd = @()
                foreach ($access in $windowsLAPSACLsAccess) {
                    # if SID, we try to resolve it
                    if ($access -like 'S-1-5-32*') {
                        $access = (Get-ADGroup -Identity $access -Server $DC).Name
                    }
    
                    $whoCanReadWindowsLapsPwd.Add($access)
                }

                $object | Add-Member -MemberType NoteProperty -Name WhoCanReadWindowsLapsPwd -Value ($whoCanReadWindowsLapsPwd -join '|')
            }

            <# don't work as expected
            if ($windowsLapsEncryptedSchemaGUID) {
                $windowsLAPSACLsEncryptedAccess = ((Get-Acl -Path "AD:$($computer.DistinguishedName)").access | Where-Object { (($_.ActiveDirectoryRights -match 'ExtendedRight' -and ( ($_.ObjectType -eq $windowsLapsEncryptedSchemaGUID) -or ($_.ObjectType -eq '00000000-0000-0000-0000-000000000000') )) -or ($_.ActiveDirectoryRights -like '*GenericAll*')) }).IdentityReference

                [System.Collections.Generic.List[String]]$whoCanReadWindowsLapsEncryptedPwd = @()
                foreach ($access in $windowsLAPSACLsEncryptedAccess) {
                    # if SID, we try to resolve it
                    if ($access -like 'S-1-5-32*') {
                        $access = (Get-ADGroup -Identity $access -Server $DC).Name
                    }
    
                    $whoCanReadWindowsLapsEncryptedPwd.Add($access)
                }

                $object | Add-Member -MemberType NoteProperty -Name WhoCanReadWindowsLapsEncryptedPwd -Value ($whoCanReadWindowsLapsEncryptedPwd -join '|')

            }
            #>
        }

        if ($IncludePasswordsAsPlainText) {
            $object | Add-Member -MemberType NoteProperty -Name LegacyLapsPassword -Value $($computer.'ms-lapsMCS-AdmPwd')
            $windowsLapsPassword = Get-LapsADPassword -Identity $computer.DistinguishedName -AsPlainText

            $object | Add-Member -MemberType NoteProperty -Name WindowsLapsPassword -Value $windowsLapsPassword.Password
        }

        $lapsReport.Add($object)
    }

    return $lapsReport
}