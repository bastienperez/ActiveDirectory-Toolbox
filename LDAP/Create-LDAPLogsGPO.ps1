#requires -modules GroupPolicy
#requires -modules ActiveDirectory

# Tested on 2025-07-22-123543 on Windows Server 2022 on Azure : the domain controllers must be restarted to apply the GPO
#Check if powershell is launched as elevevated
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning 'Please run PowerShell as administrator'
    return
}

Import-Module ActiveDirectory
Import-Module GroupPolicy

function Create-LDAPLogsGPO {
    param(
        [string]$GpoName = 'DC - Enable LDAP logs to level basic',
        [int]$DirectoryServiceLogMaxSize = '1048576000' # 524288000 = 512MB; 1048576000 = 1GB;2097152000 = 2GB
    )
    
    $DC = (Get-ADDomainController -Discover -Service ADWS).Name

    if ($DirectoryServiceLogMaxSize -lt 64000) {
        Write-Warning 'DirectoryServiceLogMaxSize parameter must be greater than or equal to 64Kb'
        return
    }

    if ($DirectoryServiceLogMaxSize % 64000 -ne 0) {
        Write-Warning 'DirectoryServiceLogMaxSize parameter must be a multiple of 64Kb'
        return
    }
  
    Write-Host -ForegroundColor Green "$GpoName - Create GPO"
    try {
        $gpoObject = New-GPO -Name $GpoName -Comment 'GPO to enable LDAP logs (level basic)' -Server $DC -ErrorAction Stop    
    }
    catch {
        Write-Warning $_.Exception.Message
        break
    }

    try {
        Write-Host -ForegroundColor Green "$GpoName - Enable LDAP Logs"
        $null = Set-GPPrefRegistryValue -Name $GpoName -Context 'Computer' -Key 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -ValueName '16 LDAP Interface Events' -Value 2 -Type DWord -Action Update -Server $DC -ErrorAction Stop
        
        # convert to hexa
        $maxSize = '{0:x4}' -f $DirectoryServiceLogMaxSize
        Write-Host -ForegroundColor Green "$GpoName - Increase DirectoryService Log to $DirectoryServiceLogMaxSize"
        $null = Set-GPPrefRegistryValue -Name $GpoName -Context 'Computer' -Key 'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Directory Service' -ValueName 'MaxSize' -Value $DirectoryServiceLogMaxSize -Type DWord -Action Update -Server $DC -ErrorAction Stop
    }
    catch {
        Write-Warning $_.Exception.Message
    }


    # source : https://learn.microsoft.com/en-us/entra/identity/devices/hybrid-join-control

    $domainSID = (Get-ADDomain).DomainSID.Value

    # Authenticated users has a well known SID : S-1-5-11. We need to get the group name to delete this group after the GPO creation
    $authenticatedUsersGroupName = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11')).Translate([System.Security.Principal.NTAccount]).Value.split('\')[1] 

    # Domain Controllers group has a well known SID : S-1-5-domain-516. We need to get the group name to add this group after the GPO creation
    $domainControllersGroupName = (New-Object System.Security.Principal.SecurityIdentifier("$domainSID-516")).Translate([System.Security.Principal.NTAccount]).Value.split('\')[1] 

    Write-Host -ForegroundColor Cyan "$GpoName - Remove Authenticated Users from GPO"
    $null = Set-GPPermission -Guid $gpoObject.Id -TargetName $authenticatedUsersGroupName -PermissionLevel None -TargetType Group -Confirm:$true
    
    Write-Host -ForegroundColor Cyan "$GpoName - Set Security Filtering to Domain Controllers group only"
    $null = Set-GPPermission -Guid $gpoObject.Id -TargetName $domainControllersGroupName -PermissionLevel GpoApply -TargetType Group -Confirm:$true

    Write-Host -ForegroundColor Cyan "$GpoName - Disable User Settings"
    $gpoObject.GpoStatus = 'UserSettingsDisabled'

    $dcOU = Get-ADOrganizationalUnit -Filter { Name -eq 'Domain Controllers' } 
        
    Write-Host -ForegroundColor Green "$GpoName - Link GPO to $($dcOU.DistinguishedName)"
    $null = New-GPLink -Guid $gpoObject.Id -Target $dcOU -LinkEnabled Yes -Server $DC -ErrorAction Stop
}

Create-LDAPLogsGPO