<#
.CHANGELOG

[2.1.0] - 2025-10-17
# Added
- Add `ExportCSV` parameter to export results to CSV file.

[2.0.0] - 2025-03-05
# Changed
- Replace `Computer` parameter by `ComputerName` to be consistent with other scripts.
- Add `Computer` as alias for `ComputerName` to backward compatibility.
- Add `ComputerName` parameter to be able to specify multiple computers.
- Return all group membership by default (previous version imposed to specify a group name).
- Merge the two scripts `Get-LocalGroupMembersWithWinNT` and `Get-RemoteLocalGroupsMembership` into this script.
- Enhance `PrincipalSource` detection to be able to distinguish between local, EntraID and Active Directory users/groups.

[1.0.0] - 2024-xx-xx
# Initial Version
- Custom function instead of Get-LocalGroupMember because it's not working if member has unresolved SID.
  By example, `Get-LocalGroupMember` PowerShell command doesn't work on an Microsoft Entra ID joined device as there are two unresolved SIDs in the member list. 
  It will throw the following error: `Failed to compare two elements in the array`
  Issue #2996 · PowerShell/PowerShell · GitHub
#>

function Get-LocalGroupMembersWithWinNT {
    param(
        [Parameter(Mandatory = $False, Position = 1)]
        [string]$GroupName,
        [Parameter(Mandatory = $False)]
        [Alias('Computer')]
        [String[]]$ComputerName,
        [Parameter(Mandatory = $False)]
        [Switch]$ExportCSV
    )

    [System.Collections.Generic.List[PSObject]]$groupMembersArray = @()

    if ([String]::IsNullOrWhitespace($ComputerName)) {
        $ComputerName = $env:COMPUTERNAME
    }

    foreach ($comp in $ComputerName) {
        if ($comp -eq 'localhost') {
            $comp = $env:COMPUTERNAME
        }
        
        $ADSIComputer = [ADSI]("WinNT://$comp,computer")

        try {
            # Test ADSI
            [void]$ADSIComputer.Tostring()
        }
        catch {
            # Try with invoke-command if not the local computer and load the function because sometimes the network path is not found
            if ($env:COMPUTERNAME -ne $computer) {
        
                $ADSIComputer = Invoke-Command -ComputerName $computer -ScriptBlock {
                    [ADSI]"WinNT://$env:COMPUTERNAME,computer"
                }
            }

            try {
                [void]$ADSIComputer.Tostring()
            }
            catch {
                $errorMessage = $_.Exception.Message

                $object = [PSCustomObject][ordered]@{
                    Computername               = $comp
                    GroupName                  = $errorMessage
                    MemberName                 = $errorMessage
                    MemberEnabled              = $errorMessage
                    MemberPath                 = $errorMessage
                    MemberSid                  = $errorMessage
                    MemberType                 = $errorMessage
                    MemberPrincipalSource      = $errorMessage
                    LastLogin                  = $errorMessage
                    LockoutObservationInterval = $errorMessage
                    LoginHours                 = $errorMessage
                    LoginScript                = $errorMessage
                    MaxBadPasswordsAllowed     = $errorMessage
                    MaxPasswordAge             = $errorMessage
                    MaxStorage                 = $errorMessage
                    MinPasswordAge             = $errorMessage
                    MinPasswordLength          = $errorMessage
                    PasswordAge                = $errorMessage
                    PasswordExpired            = $errorMessage
                    PasswordHistoryLength      = $errorMessage
                    PrimaryGroupID             = $errorMessage
                    UserFlags                  = $errorMessage
                }

                $remoteLocalGroupsMembershipArray.Add($object)

                continue
            }
        }

        # If no group name is specified, retrieve all local groups
        if ([string]::IsNullOrWhiteSpace($GroupName)) {
            $groups = $ADSIComputer.psbase.children | Where-Object { $_.psbase.schemaClassName -eq 'group' }
        }
        else {
            # Otherwise, retrieve only the specified group
            try {
                $group = $ADSIComputer.psbase.children.find("$GroupName", 'Group')
                $groups = @($group)
            }
            catch {
                Write-Error "Le groupe '$GroupName' n'a pas été trouvé sur l'ordinateur '$comp'."
                return $groupMembersArray
            }
        }

        foreach ($currentGroup in $groups) {
            $currentGroupName = $currentGroup.Name[0]
        
            $currentGroup.psbase.invoke('members') | ForEach-Object {

                $memberType = $null
                $memberName = $null
                $memberSID = $null
                $memberStatus = 'UnknownOrNotApplicable'

                $path = $null

                try {
                    $memberSID = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $_.GetType().InvokeMember('ObjectSID', 'GetProperty', $null, $_, $null), 0
                }
                catch {
                    $memberSID = 'Unable to resolve SID'
                }

                $path = $_.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $_, $null)

                if ($path -like "*/$comp/*") {
                    $principalSource = 'Local'
                }
                elseif ($path -like 'WinNT://AzureAD/*') {
                    $principalSource = 'EntraID'
                }
                elseif ($path -like 'WinNT://S-1-5-21-*') {
                    $principalSource = 'ActiveDirectory (unable to resolve SID because former user/group)'
                }
                elseif ($path -like 'WinNT://S-1-12-1-*') {
                    $principalSource = 'EntraID (unable to resolve SID)'
                }
                # known SID for local account has the pattern S-1-5-x
                elseif ($memberSID.Value -match 'S-1-5-\d+') {
                    $principalSource = 'Local'
                }
                else {
                    $principalSource = 'Unknown'
                }
            
                $memberType = $_.GetType().InvokeMember('Class', 'GetProperty', $null, $_, $null)
                $memberName = $_.GetType().InvokeMember('Name', 'GetProperty', $null, $_, $null)
            
                if ($memberType -eq 'User' -and $principalSource -eq 'Local') {
                    # return $true if the account is disabled
                    try {
                        $lastLogin = $_.GetType().InvokeMember('LastLogin', 'GetProperty', $null, $_, $null)
                        $memberStatus = -not ($_.GetType().InvokeMember('AccountDisabled', 'GetProperty', $null, $_, $null))
                        $lockoutObservationInterval = $_.GetType().InvokeMember('LockoutObservationInterval', 'GetProperty', $null, $_, $null)
                        $loginHours = $_.GetType().InvokeMember('LoginHours', 'GetProperty', $null, $_, $null)
                        $loginScript = $_.GetType().InvokeMember('LoginScript', 'GetProperty', $null, $_, $null)
                        $maxBadPasswordsAllowed = $_.GetType().InvokeMember('MaxBadPasswordsAllowed', 'GetProperty', $null, $_, $null)
                        $maxPasswordAge = $_.GetType().InvokeMember('MaxPasswordAge', 'GetProperty', $null, $_, $null)
                        $maxStorage = $_.GetType().InvokeMember('MaxStorage', 'GetProperty', $null, $_, $null)
                        $minPasswordAge = $_.GetType().InvokeMember('MinPasswordAge', 'GetProperty', $null, $_, $null)
                        $minPasswordLength = $_.GetType().InvokeMember('MinPasswordLength', 'GetProperty', $null, $_, $null)
                        $passwordAge = $_.GetType().InvokeMember('PasswordAge', 'GetProperty', $null, $_, $null)
                        $passwordExpired = $_.GetType().InvokeMember('PasswordExpired', 'GetProperty', $null, $_, $null)
                        $passwordHistoryLength = $_.GetType().InvokeMember('PasswordHistoryLength', 'GetProperty', $null, $_, $null)
                        $primaryGroupID = $_.GetType().InvokeMember('PrimaryGroupID', 'GetProperty', $null, $_, $null)
                        $userFlags = $_.GetType().InvokeMember('UserFlags', 'GetProperty', $null, $_, $null)
                    }
                    catch {
                        $lastLogin = 'Error retrieving data'
                        $memberStatus = 'Error retrieving data'
                        $lockoutObservationInterval = 'Error retrieving data'
                        $loginHours = 'Error retrieving data'
                        $loginScript = 'Error retrieving data'
                        $maxBadPasswordsAllowed = 'Error retrieving data'
                        $maxPasswordAge = 'Error retrieving data'
                        $maxStorage = 'Error retrieving data'
                        $minPasswordAge = 'Error retrieving data'
                        $minPasswordLength = 'Error retrieving data'
                        $passwordAge = 'Error retrieving data'
                        $passwordExpired = 'Error retrieving data'
                        $passwordHistoryLength = 'Error retrieving data'
                        $primaryGroupID = 'Error retrieving data'
                        $userFlags = 'Error retrieving data'
                    }
                }
                else {
                    $lastLogin = 'UnknownOrNotApplicable'
                    $memberStatus = 'UnknownOrNotApplicable'
                    $lockoutObservationInterval = 'UnknownOrNotApplicable'
                    $loginHours = 'UnknownOrNotApplicable'
                    $loginScript = 'UnknownOrNotApplicable'
                    $maxBadPasswordsAllowed = 'UnknownOrNotApplicable'
                    $maxPasswordAge = 'UnknownOrNotApplicable'
                    $maxStorage = 'UnknownOrNotApplicable'
                    $minPasswordAge = 'UnknownOrNotApplicable'
                    $minPasswordLength = 'UnknownOrNotApplicable'
                    $passwordAge = 'UnknownOrNotApplicable'
                    $passwordExpired = 'UnknownOrNotApplicable'
                    $passwordHistoryLength = 'UnknownOrNotApplicable'
                    $primaryGroupID = 'UnknownOrNotApplicable'
                    $userFlags = 'UnknownOrNotApplicable'
                }
            
                $object = [PSCustomObject][ordered]@{
                    Computername               = $comp
                    GroupName                  = $currentGroupName
                    MemberName                 = $memberName
                    MemberEnabled              = $memberStatus
                    MemberPath                 = $path
                    MemberSid                  = $memberSID
                    MemberType                 = $memberType
                    MemberPrincipalSource      = $principalSource
                    LastLogin                  = $lastLogin
                    LockoutObservationInterval = $lockoutObservationInterval
                    LoginHours                 = $loginHours
                    LoginScript                = $loginScript
                    MaxBadPasswordsAllowed     = $maxBadPasswordsAllowed
                    MaxPasswordAge             = $maxPasswordAge
                    MaxStorage                 = $maxStorage
                    MinPasswordAge             = $minPasswordAge
                    MinPasswordLength          = $minPasswordLength
                    PasswordAge                = $passwordAge
                    PasswordExpired            = $passwordExpired
                    PasswordHistoryLength      = $passwordHistoryLength
                    PrimaryGroupID             = $primaryGroupID
                    UserFlags                  = $userFlags
                }

                $groupMembersArray.Add($object)
            }
        }
    }

    if ($ExportCSV) {
        $now = (Get-Date).ToString('yyyyMMdd')
    
        # export to the desktop by default
        $exportFolder = [System.Environment]::GetFolderPath('Desktop')

        $exportFile = Join-Path -Path $exportFolder -ChildPath "$now-LocalGroupsMembers.csv" -ErrorAction Stop
    
        try {
            $groupMembersArray | Export-Csv -Path $exportFile -NoTypeInformation -Encoding UTF8 -Delimiter ';'
            Write-Host "Results exported to $exportFile" -ForegroundColor Green
        }
        catch {
            Write-Warning "Could not export results to CSV file. $($_.Exception.Message)"
        }
    }
    else {
        return $groupMembersArray
    }
}