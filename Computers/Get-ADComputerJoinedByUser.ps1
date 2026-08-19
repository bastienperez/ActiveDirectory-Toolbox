<#
    .SYNOPSIS
    Get the computers joined to the current domain by a regular user
    .DESCRIPTION
    Get the list of computers joined to the domain by a regular user.
    By default, each user can join up to 10 computers to an Active Directory domain.
    This setting is set in the 'ms-DS-MachineAccountQuota' attribute (https://support.microsoft.com/en-us/help/243327/default-limit-to-number-of-workstations-a-user-can-join-to-the-domain)
    If a computer object is added to a domain by a regular user, the 'ms-DS-CreatorSID' attribute is set with the SID of the creator.
    This attribute is not set if the user has Domain Admin permissions or has been delegated the permission to create computers objects at the computers creation time.

    .OUTPUTS
    A System.Collections.Generic.List[PSObject] with all computers joined by regular users (ie. users without built-in Admin permissions).
    If you have some tiering in your domain, you will find some computers joined by users with tiering permissions, it's not a problem.
    
    .NOTES
    Version : 1.2 - August 2026
    Author : Bastien Perez - ITPro-Tips (https://itpro-tips.com)
    
    .LINK
    https://itpro-tips.com
    If you have any problem, any bug, please tell me.
    Github : https://github.com/itpro-tips/ActiveDirectory-Toolbox/blob/master/Computers/Get-ADComputerJoinedByUser.ps1
#>

function Get-ADComputerJoinedByUser {

    # Import module if Get-ADObject is not recognized
    if (-not (Get-Command Get-ADObject -ErrorAction SilentlyContinue)) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
        }
        catch {
            Write-Warning "Unable to import ActiveDirectory module: $($_.Exception.Message)"
            return
        }
    }

    [System.Collections.Generic.List[PSObject]]$computersJoinedByUser = @()

    Write-Host '[i] Search objects with ms-DS-CreatorSID not empty' -ForegroundColor Cyan

    $computersFound = $null

    try {
        $getADObjectParams = @{
            LDAPFilter  = 'ms-DS-CreatorSID=*'
            Properties  = 'ms-DS-CreatorSID', 'WhenCreated'
            ErrorAction = 'Stop'
        }
        $computersFound = Get-ADObject @getADObjectParams
    }
    catch {
        Write-Warning "Unable to query the domain: $($_.Exception.Message)"
    }

    if (-not ($computersFound -and $computersFound.Count -gt 0)) {
        return $computersJoinedByUser
    }

    foreach ($computerFound in $computersFound) {

        $objectSID = $null
        $objectUser = $null

        # Try to resolve the SID into an account
        try {
            $objectSID = [System.Security.Principal.SecurityIdentifier]::new($computerFound.'ms-DS-CreatorSID', 0)
            $objectUser = $objectSID.Translate([System.Security.Principal.NTAccount])
        }
        catch {
            $objectUser = 'Unknown user (maybe user deleted from AD)'
        }

        $whenCreated = $null

        if ($null -ne $computerFound.WhenCreated) {
            $whenCreated = $computerFound.WhenCreated.ToString('yyyyMMdd-HH:mm:ss')
        }

        $computerInfo = [PSCustomObject][ordered]@{
            ComputerName = $computerFound.Name
            ComputerDN   = $computerFound.DistinguishedName
            UserName     = $objectUser
            UserSID      = $objectSID
            WhenCreated  = $whenCreated
        }

        $computersJoinedByUser.Add($computerInfo)
    }

    return $computersJoinedByUser
}
