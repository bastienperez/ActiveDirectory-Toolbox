function Get-LastFullShutdownOrReboot {
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$IncludeReason
    )
   
    $filterHashTable = @{
        LogName      = 'System'
        ProviderName = 'Microsoft-Windows-Kernel-Boot'
        ID           = 27
    }

    # Checking last full shutdown or reboot (ignore hibernation or FastStartup)
    <# eventID 27 message
    0x0: Full shutdown or reboot
    0x1: Shutdown with fast boot
    0x2: Resume from hibernation
    We want to check only for 0x0 because we want to know when the computer was completely shutdown or rebooted
    #>

    # Select the last boot. Event 27 is logged at boot time and contains info about the last shutdown/reboot
    $bootEvent = Get-WinEvent -FilterHashtable $filterHashTable -ErrorAction SilentlyContinue | Where-Object { $_.message -match '0x0' } | Select-Object -First 1

    if ($null -ne $bootEvent) {
        Write-Verbose 'Full shutdown or reboot event found'
        $lastBootFromFullShutdownOrReboot = $bootEvent.TimeCreated
    }
    else {
        Write-Verbose 'No boot event found (i.e no event log with ID 27, either because not exist or newer event logs overwritten older event 27 logs), use last reboot time from Win32_OperatingSystem'
        $lastRebootFromCim = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
        $lastBootFromFullShutdownOrReboot = $lastRebootFromCim
    }

    # Create the result object
    $result = [PSCustomObject]@{
        LastBootTime = $lastBootFromFullShutdownOrReboot
        RebootReason = $null
        RebootType   = $null
        InitiatedBy  = $null
    }

    # If the reason is requested, try to find the shutdown/reboot reason
    if ($IncludeReason) {
        # Look for planned shutdown events (Event ID 1074)
        $shutdownEvent = Get-WinEvent -FilterHashtable @{LogName = 'System'; ID = 1074} -ErrorAction SilentlyContinue |
                         Where-Object { $_.TimeCreated -le $lastBootFromFullShutdownOrReboot } |
                         Select-Object -First 1

        # Look for unexpected shutdown events (Event ID 6008)
        $unexpectedShutdownEvent = Get-WinEvent -FilterHashtable @{LogName = 'System'; ID = 6008} -ErrorAction SilentlyContinue |
                                  Where-Object { $_.TimeCreated -le $lastBootFromFullShutdownOrReboot } |
                                  Select-Object -First 1

        # Look for kernel power events (Event ID 41) which indicate a crash or power loss
        $kernelPowerEvent = Get-WinEvent -FilterHashtable @{LogName = 'System'; ID = 41} -ErrorAction SilentlyContinue |
                           Where-Object { $_.TimeCreated -le $lastBootFromFullShutdownOrReboot } |
                           Select-Object -First 1

        # Determine the most recent event that happened before the boot time
        if ($shutdownEvent) {
            $result.RebootType = 'Planned'
            
            # Extract information from XML data which is language-independent
            $eventXml = [xml]$shutdownEvent.ToXml()
            
            # Extract shutdown reason and user from the event data
            $eventData = $eventXml.Event.EventData.Data
            
            # Map the reason code to human-readable text
            $reasonCode = $eventData | Where-Object { $_.Name -eq 'Reason' } | Select-Object -ExpandProperty '#text'
            $typeCode = $eventData | Where-Object { $_.Name -eq 'Type' } | Select-Object -ExpandProperty '#text'
            
            # Common reason codes
            $reasonMap = @{
                '0x500ff' = 'User Initiated'
                '0x0' = 'Other (Unplanned)'
                '0x5' = 'Other Failure: System Unresponsive'
                '0x80020002' = 'Software Installation'
                '0x80020003' = 'Hardware Installation'
                '0x8002000E' = 'Operating System: Upgrade'
                '0x80020010' = 'Service Pack: Installation'
                '0x0000000a' = 'Application maintenance (Planned)'
                '0x00000000' = 'Other (Unplanned)'
            }
            
            # Common shutdown types
            $typeMap = @{
                '1' = 'Shutdown'
                '2' = 'Restart'
                '3' = 'Power Off'
                '4' = 'Hibernate'
                '5' = 'Fast Startup'
            }
            
            # Extract who initiated the shutdown
            $initiatedBy = $eventData | Where-Object { $_.Name -eq 'User' -or $_.Name -eq 'Process' } | Select-Object -ExpandProperty '#text'
            $comment = $eventData | Where-Object { $_.Name -eq 'Comment' } | Select-Object -ExpandProperty '#text'
            
            # Set the values
            $result.RebootReason = if ($reasonMap.ContainsKey($reasonCode)) { $reasonMap[$reasonCode] } else { "Unknown reason code: $reasonCode" }
            $result.InitiatedBy = $initiatedBy
            # Add additional type information if available
            if ($typeMap.ContainsKey($typeCode)) {
                $result.RebootType = $typeMap[$typeCode]
            }
        }
        elseif ($unexpectedShutdownEvent) {
            $result.RebootType = 'Unexpected'
            $result.RebootReason = 'System was not properly shut down'
        }
        elseif ($kernelPowerEvent) {
            $result.RebootType = 'Crash/Power Loss'
            $result.RebootReason = 'System crash or power loss'
        }
        else {
            $result.RebootType = 'Unknown'
            $result.RebootReason = 'No shutdown reason found in event logs'
        }
    }

    # Return just the timestamp if reason not requested, otherwise return the full object
    if (-not $IncludeReason) {
        return $lastBootFromFullShutdownOrReboot
    }
    else {
        return $result
    }
}