function Get-ComputerPublicIPAddress {
    <#
    .SYNOPSIS
    Get the public IP address of a computer
    .PARAMETER ComputerName
    Remote computer (use WSMan)

    .EXAMPLE
    Get-ComputerPublicIPAddress
    
    .EXAMPLE
    Get-ComputerPublicIPAddress -ComputerName DC01

    #>
    
    param (
        [String]$ComputerName
    )

    # use mullvad because no API key needed and return : ip, country, city, longitude, latitude, blacklisted, organization (ISP)
    $getIP = 'https://am.i.mullvad.net/json'

    if ($ComputerName) {
        $ipAddress = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            param($uri)
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-RestMethod -Method Get -Uri $uri
        } -ArgumentList $getIP
    }
    else {
        $computerName = $env:COMPUTERNAME
        $ipAddress = Invoke-RestMethod -Method Get -Uri $getIP
    }

    [System.Collections.Generic.List[String]]$blackListedArray = @()

    foreach ($blacklist in $ipAddress.blacklisted.results) {
        $blackListedArray.Add("$($blacklist.name)=$($blacklist.blackListed)")
    }

    $object = [PSCustomObject][ordered] @{
        ComputerName     = $computerName
        IP               = $ipAddress.ip
        Country          = $ipAddress.country
        City             = $ipAddress.city
        Longitude        = $ipAddress.longitude
        Latitude         = $ipAddress.latitude
        Blacklisted      = if (($ipAddress.blacklisted.results | Where-Object { $_.blacklisted }).count -gt 0) { $true } else { $false }
        BlacklistDetails = $blackListedArray -join '|'
        Organization     = $ipAddress.organization
        GMaps            = "https://maps.google.com/?q=$($ipAddress.latitude),$($ipAddress.longitude)"
    }

    return $object
}