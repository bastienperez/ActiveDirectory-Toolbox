function Get-ADPasswordSettingsByUser {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string[]]$SamAccountName,
        [Parameter(Mandatory = $false)]
        [string]$DomainController
    )
    Import-Module ActiveDirectory
    
    [System.Collections.Generic.List[PSObject]]$passwordSettingsByUser = @()
    
    #$defautPasswordPolicyObject = (Get-GPInheritance -Target (Get-ADDomain).DistinguishedName).inheritedGpoLinks | Select-Object -First 1
    if (-not $DomainController) {
        # choose PDC emulator
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $DomainController = $domain.PdcRoleOwner.Name
        Write-Host -ForegroundColor Cyan "For accurate results, the domain controller with the PDC emulator role will be used: $DomainController"

    }

    $defautPasswordPolicyObject = Get-ADDefaultDomainPasswordPolicy -Server $DomainController
    $defautPasswordPolicyDays = $defautPasswordPolicyObject.MaxPasswordAge.Days
    $attributes = 'DisplayName', 'msDS-UserPasswordExpiryTimeComputed', 'PasswordNeverExpires', 'pwdLastSet', 'Enabled', 'badPwdCount', 'badPasswordTime', 'LastLogonDate', 'PasswordNotRequired'

    if ($SamAccountName) {
        [System.Collections.Generic.List[PSObject]]$users = @()

        foreach ($sam in $SamAccountName) {
            Write-Verbose "Processing user: $sam"
            try {
                $u = Get-ADUser -Identity $sam -Properties $attributes -ErrorAction Stop -Server $DomainController
            }
            catch {
                Write-Warning "$($_.Exception.Message)"
                return
            }

            $users.Add($u)
        }
    }
    else {
        Write-Verbose 'Processing all users'
        try {
            $users = Get-ADUser -Filter * -Properties $attributes -ErrorAction Stop -Server $DomainController
        }
        catch {
            Write-Warning "$($_.Exception.Message)"
            return
        }
    }

    $i = 0
    foreach ($user in $users) {
        $i++
        Write-Verbose "Processing user $i/$($users.Count): $($user.SamAccountName)"
        $policy = $null
        $passwordPolicyMaxPasswordAge = $null

        Write-Verbose "Getting password policy for $($user.SamAccountName)"
        $fineGrainedPassword = Get-ADUserResultantPasswordPolicy -Identity $user.SamAccountName -Server $DomainController
        
        switch ($fineGrainedPassword.Name) {
            $null {
                $policy = 'GPO or domain settings'
                $passwordPolicyMaxPasswordAge = $defautPasswordPolicyDays
                $lockoutDuration = $defautPasswordPolicyObject.LockoutDuration
                $lockoutObservationWindow = $defautPasswordPolicyObject.LockoutObservationWindow
                $lockoutThreshold = $defautPasswordPolicyObject.LockoutThreshold
                $passwordMinimumLength = $defautPasswordPolicyObject.MinPasswordLength
                $passwordComplexityEnabled = $defautPasswordPolicyObject.ComplexityEnabled
                $passwordHistoryCount = $defautPasswordPolicyObject.PasswordHistoryCount
                break
            }
            default {
                $policy = $fineGrainedPassword.Name + ' (Fine Grained Password)'
                $passwordPolicyMaxPasswordAge = $fineGrainedPassword.MaxPasswordAge.Days
                $lockoutDuration = $fineGrainedPassword.LockoutDuration
                $lockoutObservationWindow = $fineGrainedPassword.LockoutObservationWindow
                $lockoutThreshold = $fineGrainedPassword.LockoutThreshold
                $passwordMinimumLength = $fineGrainedPassword.MinPasswordLength
                $passwordComplexityEnabled = $fineGrainedPassword.ComplexityEnabled
                $passwordHistoryCount = $fineGrainedPassword.PasswordHistoryCount
                break
            }
        }
        
        if ($user.PasswordNotRequired) {
            $policy = 'None - User has "PasswordNotRequired" flag set. This setting allows a user in AD to bypass any password policy and set a blank password if they want to.'
        }

        if ($user.pwdLastSet -eq 0) {
            $pwdLastSet = 'Never'
        }
        else {
            $pwdLastSet = $([datetime]::FromFileTime($user.pwdLastSet).ToUniversalTime())
        }
    
        if ($user.'msDS-UserPasswordExpiryTimeComputed' -eq 9223372036854775807 -and $user.PasswordNeverExpires -eq $false) {
            $expirationDate = 'Never (no password policy in GPO or never set)'
            $daysLeft = '-'
        }
        elseif ($user.PasswordNeverExpires -and $user.'msDS-UserPasswordExpiryTimeComputed' -ne 0) {
            $expirationDate = "Never (configured as 'Never expires')"
            $daysLeft = '-'
        }
        elseif ($user.'msDS-UserPasswordExpiryTimeComputed' -eq 0) {
            if ($defautPasswordPolicyDays -eq 0) {
                $expirationDate = 'Never (no password policy in GPO)'
            }
            else {
                $expirationDate = "Password is set to be changed at 'next logon' so no way to calculate the password expiration date"
            }

            $daysLeft = '-'
        }
        else {
            $expirationDate = $([datetime]::FromFileTime($user.'msDS-UserPasswordExpiryTimeComputed').ToUniversalTime())
            $daysLeft = New-TimeSpan (Get-Date).ToUniversalTime() $expirationDate
            
            if ($daysLeft -le 0 -and $null -ne $daysLeft) {
                $daysLeft = 'Already expired'
            }
            else {
                $daysLeft = $daysLeft.Days
            }
        }
    
        $object = [PSCustomObject][ordered]@{
            Identity                                                   = $user.SamAccountName
            DisplayName                                                = $user.DisplayName
            Enabled                                                    = $user.Enabled
            DistinguishedName                                          = $user.DistinguishedName
            PasswordPolicy                                             = $policy
            PasswordPolicyMaxPasswordAge                               = $passwordPolicyMaxPasswordAge
            PasswordMinimumLength                                      = $passwordMinimumLength
            PasswordHistoryCount                                       = $passwordHistoryCount
            PasswordComplexityEnabled                                  = $passwordComplexityEnabled
            'PasswordLastSet (UTC Time)'                               = $pwdLastSet
            'PasswordExpirationDate (UTC Time)'                        = $expirationDate
            'Days left before password change (according to UTC Time)' = $daysLeft
            LockoutDuration                                            = $lockoutDuration
            LockoutObservationWindow                                   = $lockoutDuration
            LockoutThreshold                                           = $lockoutThreshold
            LastLogonDate                                              = if ($user.LastLogonDate) { $user.LastLogonDate }else { 'Never logged in' }
            BadPwdCount                                                = $user.BadPwdCount
            BadPasswordTime                                            = [datetime]::FromFileTimeUTC($user.BadPasswordTime) # is integer, convert to datetime
            FromDomainController                                       = $DomainController
        }
    
        $passwordSettingsByUser.add($object)
    }
    
    $passwordSettingsByUser | Sort-Object PasswordExpirationDate* -Descending
}