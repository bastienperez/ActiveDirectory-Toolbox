function Get-ComputerPowerEvent {
    <#
    .SYNOPSIS
    Returns the boot and shutdown events of a computer, with the reason and the initiator of each shutdown.

    .DESCRIPTION
    Merges what was previously split across Get-ComputerBootEvents, Get-ComputerFullShutdownOrRebootEvents and Get-LastFullShutdownOrReboot.

    Each boot is always correlated with the shutdown that explains it, so a single row tells when the computer started and why the previous shutdown happened.

    Two event sources are used, they are complementary :
    - Microsoft-Windows-Kernel-Boot ID 27, logged at boot time. It gives the boot time and the type of the PREVIOUS shutdown (full, fast startup, hibernation), but neither the reason nor the initiator.
    - System log IDs 41, 1074, 1076, 6006 and 6008, logged around the shutdown. They give who/which process asked for the shutdown, the reason code, and whether the shutdown was unexpected.


    .PARAMETER ComputerName
    Remote computer to query. The local computer is queried in process when the parameter is omitted.

    .PARAMETER EventType
    All      : both, sorted by date descending (default, so nothing is missed)
    Boot     : one row per boot event only
    Shutdown : one row per shutdown event only (IDs 41, 1074, 1076, 6006, 6008)

    .PARAMETER LastOnly
    Keeps only the most recent event of each requested category.

    .PARAMETER FullShutdownOnly
    Keeps only the boots that follow a full shutdown or reboot (BootType 0x0), ignoring fast startup and hibernation. Replaces Get-ComputerFullShutdownOrRebootEvents.

    .PARAMETER LastDays
    Limits the collection to the last N days. Filtering is done by the event log itself, which is much faster than a Where-Object on the whole log.

    .PARAMETER MaxEvents
    Maximum number of events read per category.

    .EXAMPLE
    Get-ComputerPowerEvent -LastDays 30

    Every boot and shutdown of the last 30 days on the local computer.

    .EXAMPLE
    Get-ComputerPowerEvent -EventType Boot -LastOnly

    Last boot of the local computer, with the reason and the initiator of the previous shutdown.

    .EXAMPLE
    Get-ComputerPowerEvent -EventType Shutdown -LastDays 30 | Format-Table TimeCreated, EventCategory, ShutdownAction, ShutdownReason, InitiatedBy

    Every shutdown of the last 30 days. Useful to find out why a server restarts on its own.

    .EXAMPLE
    Get-ComputerPowerEvent -ComputerName 'SRV01' -LastDays 7

    Full power timeline of a remote computer for the last 7 days.

    .EXAMPLE
    Get-ComputerPowerEvent -EventType Boot -LastOnly -FullShutdownOnly

    Last real shutdown or reboot, ignoring fast startup and hibernation.

    .NOTES
    .CHANGELOG
    # [2.0.0] - 2026-07-31
    ## Added
    - Shutdown events (41, 1074, 1076, 6006, 6008) with the reason, the initiator and the shutdown type
    - Each boot row is correlated with the shutdown explaining it, without any parameter to ask for it : an empty reason now means the log has nothing, not that a switch was forgotten
    - EventType, FullShutdownOnly, LastDays and MaxEvents parameters
    ## Changed
    - Merges Get-ComputerBootEvents, Get-ComputerFullShutdownOrRebootEvents and Get-LastFullShutdownOrReboot
    - Singular noun, as required by the PowerShell naming guidelines (PSUseSingularNouns)
    - EventType defaults to All : boots and shutdowns are returned together, so nothing is missed. Use -EventType Boot to get the output of the former Get-ComputerBootEvents
    - No compatibility alias : every caller must use the new name
    - The boot type is read from the BootType field of the event XML instead of a regex on the message, which is localized
    - A single remote call collects everything, instead of one Invoke-Command per piece of information
    ## Fixed
    - The fallback on Win32_OperatingSystem.LastBootUpTime built its object but never added it to the returned list, so the function returned nothing when the event 27 records had been overwritten
    - Same fallback : BootTimeDifferenceRaw was computed from $bootEvent.TimeCreated while $bootEvent was null
    - ComputerName was empty in the output when the function targeted the local computer
    - The reason code of the event 1074 was looked up by field name (Reason, Type, User) while the event exposes positional params, so the reason was always unknown. It is now decoded from the reason code bit fields (major/minor/planned)
    - Correlation missed every unexpected shutdown : the events 41, 6008 and 1076 are written by the NEXT startup, so they are timestamped a few seconds AFTER the boot they explain. Looking only before the boot silently attributed the last clean shutdown found higher in the log to a boot that actually followed a crash
    - Correlation could reach across another boot and attribute a shutdown from a previous cycle. The search is now bounded by the previous boot
    ## Performance
    - The shutdown events are read by batches of 50, paged with EndTime because Get-WinEvent has no -Skip, and reading stops as soon as the oldest reported boot is covered. A computer up for a year keeps digging until its last shutdown is found, while -LastOnly reads a single batch
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [String]$ComputerName,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Boot', 'Shutdown', 'All')]
        [String]$EventType = 'All',

        [Parameter(Mandatory = $false)]
        [switch]$LastOnly,

        [Parameter(Mandatory = $false)]
        [switch]$FullShutdownOnly,

        [Parameter(Mandatory = $false)]
        [int]$LastDays,

        [Parameter(Mandatory = $false)]
        [int]$MaxEvents
    )

    # credits to https://4sysops.com/archives/format-time-and-date-output-of-powershell-new-timespan/
    function Get-TimeSpanToString {
        <#
        .SYNOPSIS
        Displays the time span between two dates in a single line, in an easy-to-read format
        .DESCRIPTION
        Only non-zero weeks, days, hours, minutes and seconds are displayed.
        If the time span is less than a second, the function displays 'Less than a second'
        #>

        [CmdletBinding()]
        [OutputType([String])]
        param (
            [Parameter(Mandatory, ValueFromPipeline)]
            [ValidateNotNull()]
            [timespan]$TimeSpan
        )

        process {
            [string]$timeSpanToString = ''

            $blocks = [ordered]@{
                weeks   = [math]::Floor($TimeSpan.Days / 7)
                days    = [int]$TimeSpan.Days % 7
                hours   = [int]$TimeSpan.Hours
                minutes = [int]$TimeSpan.Minutes
                seconds = [int]$TimeSpan.Seconds
            }

            foreach ($part in $blocks.Keys) {
                # Skip if zero
                if ($blocks.$part -ne 0) {
                    $timeSpanToString += '{0} {1}, ' -f $blocks.$part, $part
                }
            }

            if ($timeSpanToString.Length -ne 0) {
                # Delete the trailing coma and space
                $timeSpanToString = $timeSpanToString.Substring(0, $timeSpanToString.Length - 2)
            }
            else {
                # Happens when start and end time are identical
                $timeSpanToString = 'Less than a second'
            }

            $timeSpanToString
        }
    }

    function ConvertFrom-ShutdownReasonCode {
        <#
        .SYNOPSIS
        Converts the reason code of the event 1074 into readable text.
        .DESCRIPTION
        The code is a bit field (see SHTDN_REASON_* in winnt.h) : major reason on bits 16-23, minor reason on bits 0-15,
        flag 0x80000000 for a planned shutdown and 0x40000000 for a user defined reason.
        Decoding the bit fields covers every code, unlike a lookup table listing only the most common ones.
        #>

        [CmdletBinding()]
        [OutputType([String])]
        param (
            [Parameter(Mandatory)]
            [AllowNull()]
            [AllowEmptyString()]
            $ReasonCode
        )

        if ($null -eq $ReasonCode -or $ReasonCode -eq '') {
            return $null
        }

        try {
            $code = [uint32]$ReasonCode
        }
        catch {
            return "Unknown reason code: $ReasonCode"
        }

        $majorReasons = @{
            0x00 = 'Other'
            0x01 = 'Hardware'
            0x02 = 'Operating System'
            0x03 = 'Software'
            0x04 = 'Application'
            0x05 = 'System'
            0x06 = 'Power'
            0x07 = 'Legacy API'
        }

        $minorReasons = @{
            0x00 = 'Other'
            0x01 = 'Maintenance'
            0x02 = 'Installation'
            0x03 = 'Upgrade'
            0x04 = 'Reconfiguration'
            0x05 = 'Unresponsive system'
            0x06 = 'Unstable system'
            0x07 = 'Disk'
            0x08 = 'Processor'
            0x09 = 'Network card'
            0x0A = 'Power supply'
            0x0B = 'Cord unplugged'
            0x0C = 'Environment'
            0x0D = 'Hardware driver'
            0x0E = 'Other driver'
            0x0F = 'Blue screen'
            0x10 = 'Service pack'
            0x11 = 'Hotfix'
            0x12 = 'Security fix'
            0x13 = 'Security issue'
            0x14 = 'Network connectivity'
            0x15 = 'WMI'
            0x16 = 'Service pack uninstall'
            0x17 = 'Hotfix uninstall'
            0x18 = 'Security fix uninstall'
            0x19 = 'MMC'
            0x1A = 'System restore'
            0x1B = 'Terminal Services'
            0x1C = 'Domain controller promotion'
            0x1D = 'Domain controller demotion'
            0xFF = 'Other'
        }

        $majorCode = ($code -shr 16) -band 0xFF
        $minorCode = $code -band 0xFFFF
        $planned = ($code -band 0x80000000) -ne 0
        $userDefined = ($code -band 0x40000000) -ne 0

        if ($majorReasons.ContainsKey([int]$majorCode)) {
            $major = $majorReasons[[int]$majorCode]
        }
        else {
            $major = "Unknown major reason (0x{0:X2})" -f $majorCode
        }

        if ($minorReasons.ContainsKey([int]$minorCode)) {
            $minor = $minorReasons[[int]$minorCode]
        }
        else {
            $minor = "Unknown minor reason (0x{0:X4})" -f $minorCode
        }

        if ($planned) {
            $qualifier = 'Planned'
        }
        else {
            $qualifier = 'Unplanned'
        }

        if ($userDefined) {
            $qualifier = "$qualifier, user defined"
        }

        return "$major - $minor ($qualifier)"
    }

    # Everything is collected in a single pass, so a remote target means a single Invoke-Command.
    # The events are converted to plain objects inside the script block : the records deserialized by
    # PowerShell remoting lose the ToXml() method and the typed Properties collection
    $collectScript = {
        param($CollectBoot, $CollectShutdown, $BootMaxEvents, $ShutdownMaxEvents, $StartTime)

        <#
        HiberbootEnabled = 1 : fast startup is enabled
        HiberbootEnabled = 0 or missing : fast startup is disabled
        #>
        $fastStartup = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -ErrorAction SilentlyContinue).HiberbootEnabled

        [System.Collections.Generic.List[PSObject]]$bootEvents = @()
        [System.Collections.Generic.List[PSObject]]$shutdownEvents = @()

        if ($CollectBoot) {
            $bootFilter = @{
                LogName      = 'System'
                ProviderName = 'Microsoft-Windows-Kernel-Boot'
                Id           = 27
            }

            if ($StartTime) {
                $bootFilter.StartTime = $StartTime
            }

            $bootParams = @{
                FilterHashtable = $bootFilter
                ErrorAction     = 'SilentlyContinue'
            }

            if ($BootMaxEvents -gt 0) {
                $bootParams.MaxEvents = $BootMaxEvents
            }

            foreach ($bootEvent in (Get-WinEvent @bootParams)) {
                $bootType = $null

                # The BootType field of the event data is language independent, unlike the rendered message
                try {
                    $eventXml = [xml]$bootEvent.ToXml()
                    $bootTypeNode = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq 'BootType' }

                    if ($bootTypeNode) {
                        $bootType = [int]$bootTypeNode.'#text'
                    }
                }
                catch {
                    Write-Verbose "Unable to read the event data of the boot event, falling back on the message : $($_.Exception.Message)"
                }

                if ($null -eq $bootType -and $bootEvent.Message -match '0x(\d)') {
                    $bootType = [int]$matches[1]
                }

                $bootEvents.Add([PSCustomObject]@{
                        TimeCreated  = $bootEvent.TimeCreated
                        Id           = $bootEvent.Id
                        ProviderName = $bootEvent.ProviderName
                        BootType     = $bootType
                        Message      = ($bootEvent.Message -replace '\s+', ' ')
                    })
            }
        }

        if ($CollectShutdown) {
            <#
            41   : Kernel-Power, the system rebooted without shutting down cleanly (crash or power loss)
            1074 : shutdown or restart initiated by a user or a process, with the reason
            1076 : reason supplied afterwards for the last unexpected shutdown
            6006 : event log service stopped, meaning a clean shutdown
            6008 : the previous shutdown was unexpected

            Reading strategy : the shutdown events are only needed down to the oldest boot being reported.
            Get-WinEvent has no -Skip, so paging is done with EndTime : each batch is bounded by the
            oldest event of the previous one. Reading stops as soon as an event older than the oldest boot
            is reached, or when the log is exhausted. That way -LastOnly reads a single small batch on a
            healthy computer, but keeps digging when a computer has been up for a year and its last
            shutdown events are buried far down the log
            #>
            $targetTime = $null

            if ($CollectBoot -and $bootEvents.Count -gt 0) {
                $targetTime = ($bootEvents.TimeCreated | Sort-Object | Select-Object -First 1)
            }

            $batchSize = 50
            # Hard stop, so a corrupted or hostile log cannot loop forever : 40 batches = 2000 shutdown events
            $maxBatchCount = 40
            $batchCount = 0
            $endTime = $null
            $keepReading = $true

            [System.Collections.Generic.HashSet[Int64]]$seenRecordIds = [System.Collections.Generic.HashSet[Int64]]::new()

            while ($keepReading) {
                $batchCount++

                $shutdownFilter = @{
                    LogName = 'System'
                    Id      = 41, 1074, 1076, 6006, 6008
                }

                if ($StartTime) {
                    $shutdownFilter.StartTime = $StartTime
                }

                if ($endTime) {
                    $shutdownFilter.EndTime = $endTime
                }

                $shutdownParams = @{
                    FilterHashtable = $shutdownFilter
                    ErrorAction     = 'SilentlyContinue'
                }

                if ($ShutdownMaxEvents -gt 0) {
                    # Explicit -MaxEvents : a single read, no paging
                    $shutdownParams.MaxEvents = $ShutdownMaxEvents
                    $keepReading = $false
                }
                elseif ($targetTime) {
                    $shutdownParams.MaxEvents = $batchSize
                }
                else {
                    # No boot to correlate (EventType Shutdown) : the whole filtered log is wanted
                    $keepReading = $false
                }

                $batchEvents = @(Get-WinEvent @shutdownParams)

                if ($batchEvents.Count -eq 0) {
                    break
                }

                $newEventCount = 0

                foreach ($shutdownEvent in $batchEvents) {
                    # EndTime is inclusive, so the boundary event comes back in the next batch
                    if (-not $seenRecordIds.Add($shutdownEvent.RecordId)) {
                        continue
                    }

                    $newEventCount++

                    [System.Collections.Generic.List[String]]$values = @()

                    foreach ($property in $shutdownEvent.Properties) {
                        $values.Add([string]$property.Value)
                    }

                    $shutdownEvents.Add([PSCustomObject]@{
                            TimeCreated  = $shutdownEvent.TimeCreated
                            Id           = $shutdownEvent.Id
                            ProviderName = $shutdownEvent.ProviderName
                            Properties   = $values.ToArray()
                            Message      = ($shutdownEvent.Message -replace '\s+', ' ')
                        })
                }

                if ($keepReading) {
                    $oldestTime = ($batchEvents[-1]).TimeCreated

                    if ($batchEvents.Count -lt $batchSize) {
                        # Log exhausted
                        $keepReading = $false
                    }
                    elseif ($oldestTime -lt $targetTime) {
                        # The oldest boot is now covered, everything below is another cycle
                        $keepReading = $false
                    }
                    elseif ($newEventCount -eq 0) {
                        # No progress, every event of the batch was already known : stop instead of looping
                        $keepReading = $false
                    }
                    elseif ($batchCount -ge $maxBatchCount) {
                        Write-Warning "Stopped reading the shutdown events after $($batchCount * $batchSize) records without reaching the oldest boot. Use -LastDays or -MaxEvents to narrow the search"
                        $keepReading = $false
                    }
                    else {
                        $endTime = $oldestTime
                    }
                }
            }
        }

        return [PSCustomObject]@{
            ComputerName    = $env:COMPUTERNAME
            FastStartup     = $fastStartup
            LastBootFromCim = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue).LastBootUpTime
            BootEvents      = $bootEvents.ToArray()
            ShutdownEvents  = $shutdownEvents.ToArray()
        }
    }

    $now = Get-Date

    $collectBoot = $EventType -in @('Boot', 'All')

    # Always collected : either they are returned as rows, or they explain the boot rows
    $collectShutdown = $true

    <#
    -LastOnly cannot be pushed down to MaxEvents when a filter is applied afterwards, otherwise the single
    event read may be discarded and nothing is returned.
    Two boots are read instead of one : the previous boot is the lower bound of the correlation window.
    Without it a shutdown belonging to an older cycle would be attributed to the last boot, and -LastOnly
    would disagree with the full listing on the very same boot
    #>
    if ($LastOnly -and -not $FullShutdownOnly) {
        $bootMaxEvents = 2
    }
    else {
        $bootMaxEvents = $MaxEvents
    }

<#
    The shutdown events cannot be limited the same way as the boots : correlation needs the events
    surrounding each boot, and a boot is described by several of them (1074 then 6006, or 41 then 6008).
    0 means no explicit limit : the collection script then pages through the log by batches and stops
    as soon as the oldest boot is covered
    #>
    $shutdownMaxEvents = $MaxEvents

    if ($LastDays -gt 0) {
        $startTime = $now.AddDays(-$LastDays)
    }
    else {
        $startTime = $null
    }

    try {
        if ($ComputerName) {
            $collected = Invoke-Command -ComputerName $ComputerName -ScriptBlock $collectScript -ArgumentList $collectBoot, $collectShutdown, $bootMaxEvents, $shutdownMaxEvents, $startTime -ErrorAction Stop
            $targetName = $ComputerName
        }
        else {
            $collected = & $collectScript $collectBoot $collectShutdown $bootMaxEvents $shutdownMaxEvents $startTime
            $targetName = $env:COMPUTERNAME
        }
    }
    catch {
        Write-Warning "Unable to collect the power events on $ComputerName : $($_.Exception.Message)"
        return
    }

    $fastStartupEnabled = $collected.FastStartup -eq 1

    [System.Collections.Generic.List[PSObject]]$shutdownDetails = @()

    foreach ($shutdownEvent in $collected.ShutdownEvents) {
        $properties = $shutdownEvent.Properties
        $category = 'Shutdown'
        $detail = $null
        $action = $null
        $reasonCode = $null
        $initiatedBy = $null
        $initiatedByProcess = $null
        $comment = $null

        switch ($shutdownEvent.Id) {
            1074 {
                <#
                The event exposes positional parameters :
                0 process, 1 computer, 2 reason text (localized), 3 reason code, 4 shutdown type, 5 comment, 6 user
                #>
                $detail = 'Shutdown or restart initiated'
                $initiatedByProcess = $properties[0]
                $reasonCode = $properties[3]
                $action = $properties[4]
                $comment = $properties[5]
                $initiatedBy = $properties[6]
            }
            1076 {
                $category = 'UnexpectedShutdown'
                $detail = 'Reason supplied for the last unexpected shutdown'
                $comment = ($properties -join ' | ')
            }
            6006 {
                $detail = 'Event log service stopped (clean shutdown)'
            }
            6008 {
                $category = 'UnexpectedShutdown'
                $detail = 'The previous shutdown was unexpected'
            }
            41 {
                $category = 'PowerLoss'
                $detail = 'System rebooted without shutting down cleanly (crash or power loss)'
            }
            default {
                $detail = 'Unknown event'
            }
        }

        $shutdownDetails.Add([PSCustomObject][ordered]@{
                ComputerName                 = $targetName
                TimeCreated                  = $shutdownEvent.TimeCreated
                EventCategory                = $category
                EventId                      = $shutdownEvent.Id
                ProviderName                 = $shutdownEvent.ProviderName
                Detail                       = $detail
                BootTime                     = $null
                BootTimeDifference           = $null
                BootTimeDifferenceRaw        = $null
                IsLastBootTime               = $null
                FastStartupEnabled           = $fastStartupEnabled
                PreviousShutdownOrRebootType = $null
                PreviousShutdownCategory     = $null
                PreviousShutdownTime         = $null
                ShutdownAction               = $action
                ShutdownReason               = (ConvertFrom-ShutdownReasonCode -ReasonCode $reasonCode)
                ShutdownReasonCode           = $reasonCode
                InitiatedBy                  = $initiatedBy
                InitiatedByProcess           = $initiatedByProcess
                Comment                      = $comment
                Message                      = $shutdownEvent.Message
            })
    }

    [System.Collections.Generic.List[PSObject]]$powerEvents = @()

    if ($collectBoot) {
        $bootEvents = $collected.BootEvents

        if ($FullShutdownOnly) {
            # BootType 0x0 only : ignore fast startup and hibernation resume
            $bootEvents = @($bootEvents | Where-Object { $_.BootType -eq 0 })
        }

        if ($LastOnly -and $bootEvents -and $bootEvents.Count -gt 1) {
            $bootEvents = @($bootEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1)
        }

        # Unfiltered boot times, used to bound the correlation window : a shutdown event can only explain
        # a boot if it happened after the previous boot, otherwise an old shutdown gets attributed to the wrong boot
        $allBootTimes = @($collected.BootEvents.TimeCreated | Sort-Object -Descending)

        if ($bootEvents -and $bootEvents.Count -gt 0) {
            $isLastBootTime = $true

            foreach ($bootEvent in ($bootEvents | Sort-Object TimeCreated -Descending)) {
                <#
                Event 27 BootType :
                0 full shutdown or reboot
                1 shutdown with fast boot
                2 resume from hibernation
                #>
                switch ($bootEvent.BootType) {
                    0 { $previousShutdownOrRebootType = 'Full shutdown or reboot (0x0)' }
                    1 { $previousShutdownOrRebootType = 'Shutdown with fast boot (0x1)' }
                    2 { $previousShutdownOrRebootType = 'Resume from hibernation (0x2)' }
                    default { $previousShutdownOrRebootType = "Unknown $($bootEvent.Message)" }
                }

                $previousShutdown = $null

                if ($shutdownDetails.Count -gt 0) {
                    $bootTime = $bootEvent.TimeCreated

                    <#
                    Two families of events, logged at two different moments :
                    - 1074 and 6006 are written while the computer is shutting down, so BEFORE the boot
                    - 41, 6008 and 1076 are written by the next startup, when Windows notices the previous
                      shutdown was dirty, so a few seconds AFTER the boot
                    Looking only before the boot, as a naive correlation does, always misses the unexpected
                    shutdowns and silently replaces them with the last clean shutdown found higher in the log
                    #>

                    # Upper bound of the post boot window : 5 minutes, capped by the next boot when there is one
                    $postBootLimit = $bootTime.AddMinutes(5)
                    $nextBootTime = $allBootTimes | Where-Object { $_ -gt $bootTime } | Select-Object -Last 1

                    if ($nextBootTime -and $nextBootTime -lt $postBootLimit) {
                        $postBootLimit = $nextBootTime
                    }

                    # Lower bound : the previous boot. A shutdown older than that belongs to another cycle
                    $previousBootTime = $allBootTimes | Where-Object { $_ -lt $bootTime } | Select-Object -First 1

                    # An unexpected shutdown wins : it is reported after the fact and describes this very boot
                    $unexpected = $shutdownDetails |
                        Where-Object { $_.EventId -in @(41, 6008, 1076) -and $_.TimeCreated -ge $bootTime -and $_.TimeCreated -le $postBootLimit } |
                        Sort-Object TimeCreated |
                        Select-Object -First 1

                    if ($unexpected) {
                        $previousShutdown = $unexpected
                    }
                    else {
                        $candidates = @($shutdownDetails | Where-Object {
                                $_.EventId -in @(1074, 6006) -and
                                $_.TimeCreated -le $bootTime -and
                                ($null -eq $previousBootTime -or $_.TimeCreated -gt $previousBootTime)
                            } | Sort-Object TimeCreated -Descending)

                        if ($candidates.Count -gt 0) {
                            # 1074 wins over 6006 when both describe the same shutdown, because it carries
                            # the reason and the initiator. 6006 is only the event log service stopping
                            $planned = $candidates | Where-Object { $_.EventId -eq 1074 } | Select-Object -First 1

                            if ($planned) {
                                $previousShutdown = $planned
                            }
                            else {
                                $previousShutdown = $candidates[0]
                            }
                        }
                    }
                }

                $powerEvents.Add([PSCustomObject][ordered]@{
                        ComputerName                 = $targetName
                        TimeCreated                  = $bootEvent.TimeCreated
                        EventCategory                = 'Boot'
                        EventId                      = $bootEvent.Id
                        ProviderName                 = $bootEvent.ProviderName
                        Detail                       = 'System started'
                        BootTime                     = $bootEvent.TimeCreated
                        BootTimeDifference           = (New-TimeSpan -Start $bootEvent.TimeCreated -End $now | Get-TimeSpanToString)
                        BootTimeDifferenceRaw        = (New-TimeSpan -Start $bootEvent.TimeCreated -End $now)
                        IsLastBootTime               = $isLastBootTime
                        FastStartupEnabled           = $fastStartupEnabled
                        PreviousShutdownOrRebootType = $previousShutdownOrRebootType
                        PreviousShutdownCategory     = $previousShutdown.EventCategory
                        PreviousShutdownTime         = $previousShutdown.TimeCreated
                        ShutdownAction               = $previousShutdown.ShutdownAction
                        ShutdownReason               = $previousShutdown.ShutdownReason
                        ShutdownReasonCode           = $previousShutdown.ShutdownReasonCode
                        InitiatedBy                  = $previousShutdown.InitiatedBy
                        InitiatedByProcess           = $previousShutdown.InitiatedByProcess
                        Comment                      = $previousShutdown.Comment
                        Message                      = $bootEvent.Message
                    })

                $isLastBootTime = $false
            }
        }
        else {
            Write-Verbose 'No boot event found (no event log with ID 27, either because it does not exist or because newer records overwrote it), use the last reboot time from Win32_OperatingSystem'

            $lastBoot = $collected.LastBootFromCim

            if ($lastBoot) {
                $powerEvents.Add([PSCustomObject][ordered]@{
                        ComputerName                 = $targetName
                        TimeCreated                  = $lastBoot
                        EventCategory                = 'Boot'
                        EventId                      = $null
                        ProviderName                 = 'Win32_OperatingSystem'
                        Detail                       = 'System started (from CIM, no event 27 available)'
                        BootTime                     = $lastBoot
                        BootTimeDifference           = (New-TimeSpan -Start $lastBoot -End $now | Get-TimeSpanToString)
                        BootTimeDifferenceRaw        = (New-TimeSpan -Start $lastBoot -End $now)
                        IsLastBootTime               = $true
                        FastStartupEnabled           = $fastStartupEnabled
                        PreviousShutdownOrRebootType = 'Unknown'
                        PreviousShutdownCategory     = $null
                        PreviousShutdownTime         = $null
                        ShutdownAction               = $null
                        ShutdownReason               = $null
                        ShutdownReasonCode           = $null
                        InitiatedBy                  = $null
                        InitiatedByProcess           = $null
                        Comment                      = $null
                        Message                      = $null
                    })
            }
            else {
                Write-Warning "$targetName - No boot event and no CIM boot time available"
            }
        }
    }

    if ($EventType -in @('Shutdown', 'All')) {
        if ($LastOnly -and $shutdownDetails.Count -gt 1) {
            $keptShutdowns = @($shutdownDetails | Sort-Object TimeCreated -Descending | Select-Object -First 1)
        }
        else {
            $keptShutdowns = $shutdownDetails
        }

        foreach ($shutdownDetail in $keptShutdowns) {
            $powerEvents.Add($shutdownDetail)
        }
    }

    return ($powerEvents | Sort-Object TimeCreated -Descending)
}
