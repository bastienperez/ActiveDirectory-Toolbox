<#
    .SYNOPSIS
    Retrieves password information for Active Directory users, including password expiration dates and policies.

    .DESCRIPTION
    The function fetches password-related information for specified Active Directory users or all users in the domain if no specific users are provided.
    It determines the applicable password policy (either from Group Policy or Fine Grained Password Policies) and calculates password expiration dates.

    .PARAMETER SamAccountName
    An array of SAM account names of the users for whom to retrieve password information. If not provided, information for all users in the domain will be retrieved.

    .PARAMETER DomainController
    The domain controller to query for user information. If not specified, the PDC emulator will be used.

    .PARAMETER SimulatedMaxPasswordAgeDays
    An optional parameter to simulate password expiration based on a specified maximum password age in days.
    If provided, the function will calculate a simulated password expiration date and indicate whether the password would be expired based on this simulated age.

    .EXAMPLE
    Get-ADUserPasswordInfo
    Retrieves password information for all users in the domain.

    .EXAMPLE
    Get-ADUserPasswordInfo -SamAccountName 'jdoe', 'asmith'
    Retrieves password information for the users 'jdoe' and 'asmith'.

    .EXAMPLE
    Get-ADUserPasswordInfo -SimulatedMaxPasswordAgeDays 180
    Retrieves password information for all users and simulates what would happen with a 180-day password expiration policy, showing both current and simulated expiration dates.

#>
function Get-ADUserPasswordInfo {
    [CmdletBinding()]
    [Alias('Get-ADPasswordSettingsByUser')]
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [string[]]$SamAccountName,

        [Parameter(Mandatory = $false)]
        [string]$DomainController,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$SimulatedMaxPasswordAgeDays
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
    $attributes = 'DisplayName', 'msDS-UserPasswordExpiryTimeComputed', 'PasswordNeverExpires', 'pwdLastSet', 'Enabled', 'badPwdCount', 'badPasswordTime', 'LastLogonDate', 'PasswordNotRequired', 'mail', 'UserPrincipalName'

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
            $pwdLastSet = $null
        }
        else {
            $convertedDate = [datetime]::FromFileTime($user.pwdLastSet).ToUniversalTime()
            if ($convertedDate -eq [datetime]::new(1601, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)) {
                $pwdLastSet = $null
            }
            else {
                $pwdLastSet = $convertedDate
            }
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
            
            if ($expirationDate -eq [datetime]::new(1601, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)) {
                $expirationDate = $null
                $daysLeft = '-'
            }
            else {
                $daysLeft = New-TimeSpan (Get-Date).ToUniversalTime() $expirationDate
                
                if ($daysLeft -le 0 -and $null -ne $daysLeft) {
                    $daysLeft = 'Already expired'
                }
                else {
                    $daysLeft = $daysLeft.Days
                }
            }
        }
    
        if ($SimulatedMaxPasswordAgeDays -and $user.pwdLastSet -and $pwdLastSet -ne [datetime]::new(1601, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)) {
            # Calculate simulated password expiration if SimulatedMaxPasswordAgeDays is provided
            $simulatedPasswordExpirationDateUTC = $null
            $simulatedPasswordExpired = $false
            $simulatedPasswordExpirationDateUTC = $pwdLastSet.AddDays($SimulatedMaxPasswordAgeDays)
            if ($pwdLastSet -lt (Get-Date).AddDays(-$SimulatedMaxPasswordAgeDays)) {
                $simulatedPasswordExpired = $true
            }
        }

        
        $object = [PSCustomObject][ordered]@{
            Identity                        = $user.SamAccountName
            DisplayName                     = $user.DisplayName
            Enabled                         = $user.Enabled
            UserPrincipalName               = $user.UserPrincipalName
            Mail                            = $user.mail
            PasswordLastSetUTCTime          = $pwdLastSet
            PasswordPolicy                  = $policy
            PasswordPolicyMaxPasswordAge    = $passwordPolicyMaxPasswordAge
            PasswordMinimumLength           = $passwordMinimumLength
            PasswordHistoryCount            = $passwordHistoryCount
            PasswordComplexityEnabled       = $passwordComplexityEnabled
            PasswordExpirationDateUTC       = $expirationDate
            DaysLeftBeforePasswordChangeUTC = $daysLeft
            PasswordExpired                 = if ($daysLeft -eq 'Already expired') { $true } else { $false }
            LockoutDuration                 = $lockoutDuration
            LockoutObservationWindow        = $lockoutDuration
            LockoutThreshold                = $lockoutThreshold
            LastLogonDate                   = if ($user.LastLogonDate) { $user.LastLogonDate }else { 'Never logged in' }
            BadPwdCount                     = $user.BadPwdCount
            BadPasswordTime                 = if ($user.BadPasswordTime -eq 0 -or [datetime]::FromFileTimeUTC($user.BadPasswordTime) -eq [datetime]::new(1601, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)) { $null } else { [datetime]::FromFileTimeUTC($user.BadPasswordTime) }
            FromDomainController            = $DomainController
            DistinguishedName               = $user.DistinguishedName
        }

        if ( $SimulatedMaxPasswordAgeDays) {
            $object | Add-Member -MemberType NoteProperty -Name 'SimulatedPasswordExpirationDateUTC' -Value $simulatedPasswordExpirationDateUTC
            $object | Add-Member -MemberType NoteProperty -Name 'SimulatedPasswordExpired' -Value $simulatedPasswordExpired
        }
    
        $passwordSettingsByUser.add($object)
    }
    
    $passwordSettingsByUser | Sort-Object PasswordExpirationDate* -Descending
}