# Copyright (C) 2026 Dan Michel
# SPDX-License-Identifier: GPL-3.0-only
#
# This file is part of Windows WNF Registry Bloat Toolkit.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# See the LICENSE file in the project root for the full license text.

<#
.SYNOPSIS
    Repeatedly checks live WNF state for the toolkit's exact 72-byte target
    family over a timed observation window.

.DESCRIPTION
    This read-only watcher is intended for controlled post-cleanup testing,
    especially around the first RDS/RD Gateway logon after remediation.

    At each interval the script:
      * enumerates exact current members of the toolkit target family,
      * adds newly observed state names to a persistent watch set,
      * queries every watched state name through read-only native WNF routines,
      * records subscribers, quiescence, state-data size, change stamp, and
        native query status,
      * gives each observed value its own settling timer beginning when that
        value is first seen, then distinguishes its settling samples from its
        later post-settle samples.

    Once a target-family value has been observed, its WNF state name remains in
    the watch set for the rest of the run even if the backing registry value is
    later removed or changed.

    The final result deliberately says "live evidence observed" or "no live
    evidence observed during the polling window." WNF is a private Windows
    mechanism, so the result is diagnostic evidence rather than an
    authoritative needed/not-needed determination.

    This script does not create, update, or delete registry values or WNF state
    names.

.PARAMETER IntervalMilliseconds
    Milliseconds between scheduled polls. Default: 250.

    Sub-second polling improves the chance of observing short-lived WNF state
    activity around logon. Very small intervals increase registry, native-query,
    and output-file activity; 250 ms is the recommended starting point.

.PARAMETER DurationMinutes
    Total observation time. Default: 15 minutes.

.PARAMETER SettleSeconds
    Seconds each individual target-family value must remain under observation
    before its samples are classified as PostSettle. Earlier samples for that
    value are classified as LoginOrSettling. Default: 120 seconds.

.PARAMETER OutputRoot
    Parent directory for the timestamped run folder.

.NOTES
    Run from elevated 64-bit Windows PowerShell 5.1 on Windows Server 2019.

    For the cleanest login experiment, start this watcher before the
    controlled RDS/RD Gateway logon. Running it as SYSTEM in an on-demand
    Scheduled Task allows the watcher to remain active while the initiating
    administrator logs off and reconnects.
#>

[CmdletBinding()]
param(
    [ValidateRange(50, 60000)]
    [int] $IntervalMilliseconds = 250,

    [ValidateRange(1, 1440)]
    [int] $DurationMinutes = 15,

    [ValidateRange(0, 86400)]
    [int] $SettleSeconds = 120,

    [string] $OutputRoot = (
        Join-Path $env:ProgramData 'WindowsWnfRegistryBloatToolkit'
    )
)

$ErrorActionPreference = 'Stop'

$RegistrySubKey =
    'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications'

$RegistryDisplayPath =
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications'

[uint64] $WnfXorMask =
    [uint64]::Parse(
        '41C64E6DA3BC0074',
        [Globalization.NumberStyles]::HexNumber
    )

# Keep this fixed boundary aligned with the remediation and live-audit scripts.
[uint64] $TargetMetadata = 0x011
[int] $TargetLength = 72
$TargetPayloadHash =
    'A847320A34E3ABD0F790D27CEF46D52CDD81E7B0F5257E8BE74FEF8FEE788840'

[uint32] $StatusSuccess = 0
[uint32] $StatusBufferOverflow =
    [uint32]::Parse('80000005', [Globalization.NumberStyles]::HexNumber)
[uint32] $StatusBufferTooSmall =
    [uint32]::Parse('C0000023', [Globalization.NumberStyles]::HexNumber)


# ============================================================
# Native declarations
# ============================================================

if (-not ('WnfLiveWatchNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct WNF_STATE_NAME_WATCH
{
    public UInt32 Data0;
    public UInt32 Data1;
}

public static class WnfLiveWatchNative
{
    [DllImport("ntdll.dll")]
    public static extern UInt32 NtQueryWnfStateNameInformation(
        ref WNF_STATE_NAME_WATCH StateName,
        Int32 NameInfoClass,
        IntPtr ExplicitScope,
        out UInt32 InfoBuffer,
        UInt32 InfoBufferSize
    );

    [DllImport("ntdll.dll")]
    public static extern UInt32 NtQueryWnfStateData(
        ref WNF_STATE_NAME_WATCH StateName,
        IntPtr TypeId,
        IntPtr ExplicitScope,
        out UInt32 ChangeStamp,
        IntPtr Buffer,
        ref UInt32 BufferSize
    );
}
'@
}


# ============================================================
# Helpers
# ============================================================

$script:Sha256 = [Security.Cryptography.SHA256]::Create()

function Get-Sha256Hex {
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes
    )

    return (
        [BitConverter]::ToString(
            $script:Sha256.ComputeHash($Bytes)
        ).Replace('-', '')
    )
}

function ConvertTo-StatusHex {
    param(
        [Parameter(Mandatory)]
        [uint32] $Status
    )

    return ('0x{0:X8}' -f $Status)
}

function Test-AllowedDataProbeStatus {
    param(
        [Parameter(Mandatory)]
        [uint32] $Status
    )

    return (
        $Status -eq $StatusSuccess -or
        $Status -eq $StatusBufferOverflow -or
        $Status -eq $StatusBufferTooSmall
    )
}

function ConvertTo-WnfStateName {
    param(
        [Parameter(Mandatory)]
        [string] $ValueName
    )

    [uint64] $Encoded = [Convert]::ToUInt64($ValueName, 16)
    [byte[]] $EncodedBytes = [BitConverter]::GetBytes($Encoded)

    $StateName = New-Object WNF_STATE_NAME_WATCH
    $StateName.Data0 = [BitConverter]::ToUInt32($EncodedBytes, 0)
    $StateName.Data1 = [BitConverter]::ToUInt32($EncodedBytes, 4)

    return $StateName
}

function Test-CurrentValueMatchesTarget {
    param(
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey] $RegistryKey,

        [Parameter(Mandatory)]
        [string] $ValueName
    )

    try {
        if ($ValueName -notmatch '^[0-9A-Fa-f]{16}$') {
            return $false
        }

        [uint64] $Encoded = [Convert]::ToUInt64($ValueName, 16)
        [uint64] $Decoded = $Encoded -bxor $WnfXorMask
        [uint64] $Metadata = $Decoded -band [uint64]0x7FF

        if ($Metadata -ne $TargetMetadata) {
            return $false
        }

        $Kind = $RegistryKey.GetValueKind($ValueName)
        if (
            $Kind -ne
            [Microsoft.Win32.RegistryValueKind]::Binary
        ) {
            return $false
        }

        $Data = $RegistryKey.GetValue(
            $ValueName,
            $null,
            [Microsoft.Win32.RegistryValueOptions]::
                DoNotExpandEnvironmentNames
        )

        if ($Data -isnot [byte[]]) {
            return $false
        }

        [byte[]] $Data = $Data
        if ($Data.Length -ne $TargetLength) {
            return $false
        }

        return ((Get-Sha256Hex -Bytes $Data) -eq $TargetPayloadHash)
    }
    catch {
        return $false
    }
}

function Get-CurrentTargetNames {
    param(
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey] $RegistryKey
    )

    $Matches = New-Object 'System.Collections.Generic.List[string]'

    foreach ($ValueName in $RegistryKey.GetValueNames()) {
        if (
            Test-CurrentValueMatchesTarget `
                -RegistryKey $RegistryKey `
                -ValueName $ValueName
        ) {
            [void] $Matches.Add([string] $ValueName)
        }
    }

    return @($Matches | Sort-Object)
}

function Get-WnfLiveState {
    param(
        [Parameter(Mandatory)]
        [string] $ValueName
    )

    $StateName = ConvertTo-WnfStateName -ValueName $ValueName

    [uint32] $ExistsRaw = 0
    $ExistsStateName = $StateName
    [uint32] $ExistsStatus =
        [WnfLiveWatchNative]::NtQueryWnfStateNameInformation(
            [ref] $ExistsStateName,
            0,
            [IntPtr]::Zero,
            [ref] $ExistsRaw,
            4
        )

    [uint32] $SubscribersRaw = 0
    $SubscribersStateName = $StateName
    [uint32] $SubscribersStatus =
        [WnfLiveWatchNative]::NtQueryWnfStateNameInformation(
            [ref] $SubscribersStateName,
            1,
            [IntPtr]::Zero,
            [ref] $SubscribersRaw,
            4
        )

    [uint32] $QuiescentRaw = 0
    $QuiescentStateName = $StateName
    [uint32] $QuiescentStatus =
        [WnfLiveWatchNative]::NtQueryWnfStateNameInformation(
            [ref] $QuiescentStateName,
            2,
            [IntPtr]::Zero,
            [ref] $QuiescentRaw,
            4
        )

    [uint32] $ChangeStamp = 0
    [uint32] $RequiredSize = 0
    $DataStateName = $StateName
    [uint32] $DataStatus =
        [WnfLiveWatchNative]::NtQueryWnfStateData(
            [ref] $DataStateName,
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            [ref] $ChangeStamp,
            [IntPtr]::Zero,
            [ref] $RequiredSize
        )

    $QueryFailure =
        (
            $ExistsStatus -ne $StatusSuccess -or
            $SubscribersStatus -ne $StatusSuccess -or
            $QuiescentStatus -ne $StatusSuccess -or
            -not (Test-AllowedDataProbeStatus -Status $DataStatus)
        )

    $StateExists =
        if ($ExistsStatus -eq $StatusSuccess) {
            [bool] ($ExistsRaw -ne 0)
        }
        else {
            $null
        }

    $SubscribersPresent =
        if ($SubscribersStatus -eq $StatusSuccess) {
            [bool] ($SubscribersRaw -ne 0)
        }
        else {
            $null
        }

    $IsQuiescent =
        if ($QuiescentStatus -eq $StatusSuccess) {
            [bool] ($QuiescentRaw -ne 0)
        }
        else {
            $null
        }

    $Evidence = New-Object 'System.Collections.Generic.List[string]'

    if ($SubscribersPresent -eq $true) {
        [void] $Evidence.Add('SubscribersPresent')
    }

    if ($RequiredSize -gt 0) {
        [void] $Evidence.Add('StateDataPresent')
    }

    if ($ChangeStamp -gt 0) {
        [void] $Evidence.Add('NonZeroChangeStamp')
    }

    if ($IsQuiescent -eq $false) {
        [void] $Evidence.Add('NotQuiescent')
    }

    $LiveEvidence =
        (
            $SubscribersPresent -eq $true -or
            $RequiredSize -gt 0 -or
            $ChangeStamp -gt 0 -or
            $IsQuiescent -eq $false
        )

    return [pscustomobject]@{
        QueryFailure          = $QueryFailure
        StateNameExists       = $StateExists
        SubscribersPresent    = $SubscribersPresent
        IsQuiescent           = $IsQuiescent
        StateDataRequiredSize = $RequiredSize
        ChangeStamp           = $ChangeStamp
        LiveEvidence          = $LiveEvidence
        EvidenceSummary       = $Evidence -join ';'
        ExistsStatus          = ConvertTo-StatusHex -Status $ExistsStatus
        SubscribersStatus     = ConvertTo-StatusHex -Status $SubscribersStatus
        QuiescentStatus       = ConvertTo-StatusHex -Status $QuiescentStatus
        StateDataStatus       = ConvertTo-StatusHex -Status $DataStatus
    }
}

function Write-RunLog {
    param(
        [Parameter(Mandatory)]
        [string] $Message,

        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string] $Level = 'INFO'
    )

    $Line = '[{0}] [{1}] {2}' -f (
        Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    ), $Level, $Message

    Add-Content -LiteralPath $RunLogPath -Value $Line -Encoding UTF8

    switch ($Level) {
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Host $Line -ForegroundColor Red }
        default { Write-Host $Line }
    }
}

function Export-AppendCsv {
    param(
        [Parameter(Mandatory)]
        [object] $InputObject,

        [Parameter(Mandatory)]
        [string] $LiteralPath
    )

    if (Test-Path -LiteralPath $LiteralPath -PathType Leaf) {
        $InputObject |
            Export-Csv `
                -LiteralPath $LiteralPath `
                -NoTypeInformation `
                -Encoding UTF8 `
                -Append
    }
    else {
        $InputObject |
            Export-Csv `
                -LiteralPath $LiteralPath `
                -NoTypeInformation `
                -Encoding UTF8
    }
}

function New-TrackingState {
    param(
        [Parameter(Mandatory)]
        [string] $ValueName,

        [Parameter(Mandatory)]
        [datetime] $FirstSeenAt,

        [Parameter(Mandatory)]
        [double] $FirstSeenElapsedSeconds,

        [Parameter(Mandatory)]
        [string] $FirstSeenPhase
    )

    return [pscustomobject]@{
        ValueName                       = $ValueName
        FirstSeenAt                     = $FirstSeenAt
        FirstSeenElapsedSeconds         = $FirstSeenElapsedSeconds
        FirstSeenPhase                  = $FirstSeenPhase
        LastSeenInRegistryAt            = $FirstSeenAt
        Polls                            = 0
        PostSettlePolls                  = 0
        RegistryPresentPolls             = 0
        RegistryAbsentPolls              = 0
        QueryFailurePolls                = 0
        PostSettleQueryFailurePolls      = 0
        StateExistsEver                  = $false
        SubscribersEverPresent           = $false
        StateDataEverPresent             = $false
        NonZeroChangeStampEver           = $false
        NotQuiescentEver                 = $false
        LiveEvidenceEver                 = $false
        PostSettleSubscribersEverPresent = $false
        PostSettleStateDataEverPresent   = $false
        PostSettleNonZeroChangeStampEver = $false
        PostSettleNotQuiescentEver       = $false
        PostSettleLiveEvidenceEver       = $false
        FirstLiveEvidenceAt              = $null
        LastLiveEvidenceAt               = $null
        FirstPostSettleLiveEvidenceAt    = $null
        LastPostSettleLiveEvidenceAt     = $null
        MaxStateDataRequiredSize         = [uint32]0
        MaxChangeStamp                   = [uint32]0
        LastStateNameExists              = $null
        LastSubscribersPresent           = $null
        LastIsQuiescent                  = $null
        LastStateDataRequiredSize        = $null
        LastChangeStamp                  = $null
        LastLiveEvidence                 = $null
    }
}


# ============================================================
# Preconditions and output paths
# ============================================================

if (-not [Environment]::Is64BitProcess) {
    throw 'Run this script from 64-bit Windows PowerShell.'
}

try {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object `
        -TypeName Security.Principal.WindowsPrincipal `
        -ArgumentList $Identity

    if (
        -not $Principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
    ) {
        throw (
            'Run this watcher from an elevated Windows PowerShell session. ' +
            'The script is read-only, but elevation avoids ambiguous ' +
            'access-denied results.'
        )
    }
}
catch {
    throw "Could not confirm elevated administrator context: $($_.Exception.Message)"
}

$Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunDirectory = Join-Path $OutputRoot "Wnf-LiveWatch-$Timestamp"
New-Item -ItemType Directory -Path $RunDirectory -Force | Out-Null

$RunLogPath = Join-Path $RunDirectory 'Run.log'
$SampleCsv = Join-Path $RunDirectory 'Live-State-Samples.csv'
$PollCsv = Join-Path $RunDirectory 'Poll-Summary.csv'
$ValueSummaryCsv = Join-Path $RunDirectory 'Value-Summary.csv'
$RunSummaryCsv = Join-Path $RunDirectory 'Run-Summary.csv'

$RunStart = Get-Date
$Stopwatch = [Diagnostics.Stopwatch]::StartNew()
$DurationSeconds = [double] ($DurationMinutes * 60)
$Tracked = @{}
$PollNumber = 0
$TotalQueryFailures = 0
$PostSettleQueryFailures = 0
$TotalLiveEvidenceSamples = 0
$PostSettleLiveEvidenceSamples = 0
$NewValuesDuringWatch = 0
$BaseKey = $null
$Key = $null

Write-RunLog "Live-state watcher started."
Write-RunLog "Registry key: $RegistryDisplayPath"
Write-RunLog "Interval: $IntervalMilliseconds millisecond(s)."
Write-RunLog "Duration: $DurationMinutes minute(s)."
Write-RunLog (
    "Each value enters PostSettle after it has been observed for " +
    "$SettleSeconds second(s)."
)
Write-RunLog (
    'Target family: metadata 0x{0:X3}; length {1}; SHA-256 {2}' -f
        $TargetMetadata,
        $TargetLength,
        $TargetPayloadHash
)
Write-RunLog "Output directory: $RunDirectory"
Write-Host
Write-Host (
    'Each value is labeled LoginOrSettling until it has been observed for ' +
    "$SettleSeconds second(s); later samples are labeled PostSettle."
)
Write-Host 'Press Ctrl+C to stop early; completed samples remain on disk.'
Write-Host


# ============================================================
# Timed observation loop
# ============================================================

try {
    $BaseKey =
        [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64
        )

    $Key = $BaseKey.OpenSubKey($RegistrySubKey, $false)
    if ($null -eq $Key) {
        throw "Registry key was not found: $RegistryDisplayPath"
    }

    while ($Stopwatch.Elapsed.TotalSeconds -lt $DurationSeconds) {
        $PollNumber++
        $PollStartedAt = Get-Date
        $PollStartedElapsedMilliseconds =
            $Stopwatch.Elapsed.TotalMilliseconds
        $ElapsedSeconds = [Math]::Round($Stopwatch.Elapsed.TotalSeconds, 3)

        $CurrentTargetNames = @(Get-CurrentTargetNames -RegistryKey $Key)
        $CurrentSet = @{}

        foreach ($Name in $CurrentTargetNames) {
            $CurrentSet[$Name] = $true

            if (-not $Tracked.ContainsKey($Name)) {
                $FirstSeenPhase =
                    if ($PollNumber -eq 1) {
                        'Baseline'
                    }
                    else {
                        'NewDuringWatch'
                    }

                $Tracked[$Name] =
                    New-TrackingState `
                        -ValueName $Name `
                        -FirstSeenAt $PollStartedAt `
                        -FirstSeenElapsedSeconds $ElapsedSeconds `
                        -FirstSeenPhase $FirstSeenPhase

                if ($PollNumber -gt 1) {
                    $NewValuesDuringWatch++
                }

                Write-RunLog (
                    "New exact target-family value observed: $Name " +
                    "(elapsed=$ElapsedSeconds s; source=$FirstSeenPhase)"
                )
            }
        }

        $PollQueryFailures = 0
        $PollLiveEvidence = 0
        $PollSubscribers = 0
        $PollStateData = 0
        $PollNonZeroChangeStamp = 0
        $PollNotQuiescent = 0
        $PollValuesSettling = 0
        $PollValuesPostSettle = 0
        $SampleRows = New-Object 'System.Collections.Generic.List[object]'

        foreach ($Name in @($Tracked.Keys | Sort-Object)) {
            $Tracking = $Tracked[$Name]
            $RegistryPresent = $CurrentSet.ContainsKey($Name)
            $ValueAgeSeconds = [Math]::Max(
                0,
                [Math]::Round(
                    ($PollStartedAt - $Tracking.FirstSeenAt).TotalSeconds,
                    3
                )
            )
            $Phase =
                if ($ValueAgeSeconds -ge $SettleSeconds) {
                    'PostSettle'
                }
                else {
                    'LoginOrSettling'
                }

            $Tracking.Polls++
            if ($Phase -eq 'PostSettle') {
                $Tracking.PostSettlePolls++
                $PollValuesPostSettle++
            }
            else {
                $PollValuesSettling++
            }

            if ($RegistryPresent) {
                $Tracking.RegistryPresentPolls++
                $Tracking.LastSeenInRegistryAt = $PollStartedAt
            }
            else {
                $Tracking.RegistryAbsentPolls++
            }

            $Live = Get-WnfLiveState -ValueName $Name

            if ($Live.QueryFailure) {
                $PollQueryFailures++
                $TotalQueryFailures++
                $Tracking.QueryFailurePolls++

                if ($Phase -eq 'PostSettle') {
                    $PostSettleQueryFailures++
                    $Tracking.PostSettleQueryFailurePolls++
                }
            }

            if ($Live.StateNameExists -eq $true) {
                $Tracking.StateExistsEver = $true
            }

            if ($Live.SubscribersPresent -eq $true) {
                $Tracking.SubscribersEverPresent = $true
                $PollSubscribers++

                if ($Phase -eq 'PostSettle') {
                    $Tracking.PostSettleSubscribersEverPresent = $true
                }
            }

            if ($Live.StateDataRequiredSize -gt 0) {
                $Tracking.StateDataEverPresent = $true
                $PollStateData++

                if ($Phase -eq 'PostSettle') {
                    $Tracking.PostSettleStateDataEverPresent = $true
                }
            }

            if ($Live.ChangeStamp -gt 0) {
                $Tracking.NonZeroChangeStampEver = $true
                $PollNonZeroChangeStamp++

                if ($Phase -eq 'PostSettle') {
                    $Tracking.PostSettleNonZeroChangeStampEver = $true
                }
            }

            if ($Live.IsQuiescent -eq $false) {
                $Tracking.NotQuiescentEver = $true
                $PollNotQuiescent++

                if ($Phase -eq 'PostSettle') {
                    $Tracking.PostSettleNotQuiescentEver = $true
                }
            }

            if (
                $Live.StateDataRequiredSize -gt
                $Tracking.MaxStateDataRequiredSize
            ) {
                $Tracking.MaxStateDataRequiredSize =
                    [uint32] $Live.StateDataRequiredSize
            }

            if ($Live.ChangeStamp -gt $Tracking.MaxChangeStamp) {
                $Tracking.MaxChangeStamp = [uint32] $Live.ChangeStamp
            }

            if ($Live.LiveEvidence) {
                $PollLiveEvidence++
                $TotalLiveEvidenceSamples++

                if (-not $Tracking.LiveEvidenceEver) {
                    $Tracking.FirstLiveEvidenceAt = $PollStartedAt
                }

                $Tracking.LiveEvidenceEver = $true
                $Tracking.LastLiveEvidenceAt = $PollStartedAt

                if ($Phase -eq 'PostSettle') {
                    $PostSettleLiveEvidenceSamples++

                    if (-not $Tracking.PostSettleLiveEvidenceEver) {
                        $Tracking.FirstPostSettleLiveEvidenceAt =
                            $PollStartedAt
                    }

                    $Tracking.PostSettleLiveEvidenceEver = $true
                    $Tracking.LastPostSettleLiveEvidenceAt =
                        $PollStartedAt
                }
            }

            $Tracking.LastStateNameExists = $Live.StateNameExists
            $Tracking.LastSubscribersPresent = $Live.SubscribersPresent
            $Tracking.LastIsQuiescent = $Live.IsQuiescent
            $Tracking.LastStateDataRequiredSize =
                $Live.StateDataRequiredSize
            $Tracking.LastChangeStamp = $Live.ChangeStamp
            $Tracking.LastLiveEvidence = $Live.LiveEvidence

            $SampleRow = [pscustomobject]@{
                CheckedAt                = $PollStartedAt
                PollNumber               = $PollNumber
                ElapsedSeconds           = $ElapsedSeconds
                ValueAgeSeconds          = $ValueAgeSeconds
                Phase                    = $Phase
                ValueName                = $Name
                RegistryTargetPresent    = $RegistryPresent
                StateNameExists          = $Live.StateNameExists
                SubscribersPresent       = $Live.SubscribersPresent
                IsQuiescent              = $Live.IsQuiescent
                StateDataRequiredSize    = $Live.StateDataRequiredSize
                ChangeStamp              = $Live.ChangeStamp
                LiveEvidence             = $Live.LiveEvidence
                EvidenceSummary          = $Live.EvidenceSummary
                NativeQueryFailure       = $Live.QueryFailure
                ExistsStatus             = $Live.ExistsStatus
                SubscribersStatus        = $Live.SubscribersStatus
                QuiescentStatus          = $Live.QuiescentStatus
                StateDataStatus          = $Live.StateDataStatus
            }

            [void] $SampleRows.Add($SampleRow)
        }

        if ($SampleRows.Count -gt 0) {
            Export-AppendCsv `
                -InputObject $SampleRows `
                -LiteralPath $SampleCsv
        }

        $PollWorkMilliseconds = [Math]::Round(
            (
                $Stopwatch.Elapsed.TotalMilliseconds -
                $PollStartedElapsedMilliseconds
            ),
            3
        )

        $PollRow = [pscustomobject]@{
            CheckedAt                    = $PollStartedAt
            PollNumber                   = $PollNumber
            ElapsedSeconds               = $ElapsedSeconds
            PollWorkMilliseconds         = $PollWorkMilliseconds
            CurrentTargetFamilyCount     = $CurrentTargetNames.Count
            TotalTrackedNames            = $Tracked.Count
            ValuesInSettlingPeriod       = $PollValuesSettling
            ValuesInPostSettlePeriod     = $PollValuesPostSettle
            NativeQueryFailures          = $PollQueryFailures
            ValuesWithLiveEvidence       = $PollLiveEvidence
            SubscribersPresent           = $PollSubscribers
            StateDataPresent             = $PollStateData
            NonZeroChangeStamp            = $PollNonZeroChangeStamp
            NotQuiescent                 = $PollNotQuiescent
        }

        Export-AppendCsv -InputObject $PollRow -LiteralPath $PollCsv

        if (
            $PollNumber -eq 1 -or
            $PollLiveEvidence -gt 0 -or
            $PollQueryFailures -gt 0 -or
            (
                $PollNumber %
                [Math]::Max(
                    1,
                    [int] [Math]::Round(10000 / $IntervalMilliseconds)
                )
            ) -eq 0
        ) {
            Write-Progress `
                -Activity 'Watching exact WNF target-family live state' `
                -Status (
                    'Elapsed {0:n0}s; current={1}; tracked={2}; settling={3}; ' +
                    'postSettle={4}; liveEvidence={5}; queryFailures={6}' -f
                        $ElapsedSeconds,
                        $CurrentTargetNames.Count,
                        $Tracked.Count,
                        $PollValuesSettling,
                        $PollValuesPostSettle,
                        $PollLiveEvidence,
                        $PollQueryFailures
                ) `
                -PercentComplete (
                    [Math]::Min(
                        100,
                        [Math]::Floor(
                            ($Stopwatch.Elapsed.TotalSeconds / $DurationSeconds) * 100
                        )
                    )
                )
        }

        # Maintain approximately the requested interval between poll starts.
        # If a poll itself takes longer than the requested interval, begin the
        # next poll immediately rather than trying to "catch up" with a burst.
        $PollElapsedMilliseconds =
            $Stopwatch.Elapsed.TotalMilliseconds -
            $PollStartedElapsedMilliseconds

        $RemainingMilliseconds = [int] [Math]::Floor(
            $IntervalMilliseconds - $PollElapsedMilliseconds
        )

        if ($RemainingMilliseconds -gt 0) {
            Start-Sleep -Milliseconds $RemainingMilliseconds
        }
    }
}
finally {
    Write-Progress `
        -Activity 'Watching exact WNF target-family live state' `
        -Completed

    $RunEnd = Get-Date
    $Stopwatch.Stop()

    if ($null -ne $Key) {
        $Key.Dispose()
    }

    if ($null -ne $BaseKey) {
        $BaseKey.Dispose()
    }

    if ($null -ne $script:Sha256) {
        $script:Sha256.Dispose()
    }
}


# ============================================================
# Final summaries
# ============================================================

$ValueSummaries = @(
    foreach ($Name in @($Tracked.Keys | Sort-Object)) {
        $Tracking = $Tracked[$Name]

        [pscustomobject]@{
            ValueName                         = $Name
            FirstSeenAt                       = $Tracking.FirstSeenAt
            FirstSeenElapsedSeconds           = $Tracking.FirstSeenElapsedSeconds
            FirstSeenPhase                    = $Tracking.FirstSeenPhase
            LastSeenInRegistryAt              = $Tracking.LastSeenInRegistryAt
            Polls                              = $Tracking.Polls
            PostSettlePolls                    = $Tracking.PostSettlePolls
            RegistryPresentPolls               = $Tracking.RegistryPresentPolls
            RegistryAbsentPolls                = $Tracking.RegistryAbsentPolls
            QueryFailurePolls                  = $Tracking.QueryFailurePolls
            PostSettleQueryFailurePolls        = $Tracking.PostSettleQueryFailurePolls
            StateExistsEver                    = $Tracking.StateExistsEver
            SubscribersEverPresent             = $Tracking.SubscribersEverPresent
            StateDataEverPresent               = $Tracking.StateDataEverPresent
            NonZeroChangeStampEver             = $Tracking.NonZeroChangeStampEver
            NotQuiescentEver                   = $Tracking.NotQuiescentEver
            LiveEvidenceEver                   = $Tracking.LiveEvidenceEver
            PostSettleSubscribersEverPresent   = $Tracking.PostSettleSubscribersEverPresent
            PostSettleStateDataEverPresent     = $Tracking.PostSettleStateDataEverPresent
            PostSettleNonZeroChangeStampEver   = $Tracking.PostSettleNonZeroChangeStampEver
            PostSettleNotQuiescentEver         = $Tracking.PostSettleNotQuiescentEver
            PostSettleLiveEvidenceEver         = $Tracking.PostSettleLiveEvidenceEver
            FirstLiveEvidenceAt                = $Tracking.FirstLiveEvidenceAt
            LastLiveEvidenceAt                 = $Tracking.LastLiveEvidenceAt
            FirstPostSettleLiveEvidenceAt      = $Tracking.FirstPostSettleLiveEvidenceAt
            LastPostSettleLiveEvidenceAt       = $Tracking.LastPostSettleLiveEvidenceAt
            MaxStateDataRequiredSize           = $Tracking.MaxStateDataRequiredSize
            MaxChangeStamp                     = $Tracking.MaxChangeStamp
            LastStateNameExists                = $Tracking.LastStateNameExists
            LastSubscribersPresent             = $Tracking.LastSubscribersPresent
            LastIsQuiescent                    = $Tracking.LastIsQuiescent
            LastStateDataRequiredSize          = $Tracking.LastStateDataRequiredSize
            LastChangeStamp                    = $Tracking.LastChangeStamp
            LastLiveEvidence                   = $Tracking.LastLiveEvidence
        }
    }
)

if ($ValueSummaries.Count -gt 0) {
    $ValueSummaries |
        Export-Csv `
            -LiteralPath $ValueSummaryCsv `
            -NoTypeInformation `
            -Encoding UTF8
}

$ValuesWithPostSettleSamples = @(
    $ValueSummaries |
        Where-Object { $_.PostSettlePolls -gt 0 }
).Count

$ValuesWithPostSettleLiveEvidence = @(
    $ValueSummaries |
        Where-Object { $_.PostSettleLiveEvidenceEver -eq $true }
).Count

$ValuesWithAnyLiveEvidence = @(
    $ValueSummaries |
        Where-Object { $_.LiveEvidenceEver -eq $true }
).Count

$Conclusion = ''
$ConclusionDetail = ''

if ($ValueSummaries.Count -eq 0) {
    $Conclusion = 'NoTargetFamilyValuesObserved'
    $ConclusionDetail =
        'No exact target-family value was observed during the run.'
}
elseif ($ValuesWithPostSettleSamples -eq 0) {
    $Conclusion = 'InconclusiveNoPostSettleSamples'
    $ConclusionDetail =
        'Target-family values were observed, but none received a post-settle sample.'
}
elseif ($PostSettleQueryFailures -gt 0) {
    $Conclusion = 'InconclusivePostSettleQueryFailures'
    $ConclusionDetail =
        'One or more native WNF queries failed during the post-settle period.'
}
elseif ($ValuesWithPostSettleLiveEvidence -gt 0) {
    $Conclusion = 'PostSettleLiveEvidenceObserved'
    $ConclusionDetail =
        "$ValuesWithPostSettleLiveEvidence target-family value(s) showed " +
        'subscribers, state data, a nonzero change stamp, or a non-quiescent ' +
        'state after the settle threshold.'
}
else {
    $Conclusion = 'NoPostSettleLiveEvidenceObserved'
    $ConclusionDetail =
        'All observed target-family values that reached the post-settle ' +
        'period were queried without native-query failures, and none showed ' +
        'subscribers, state data, a nonzero change stamp, or a non-quiescent ' +
        'state during those post-settle samples.'
}

$RunSummary = [pscustomobject]@{
    StartedAt                       = $RunStart
    EndedAt                         = $RunEnd
    ActualElapsedSeconds            = [Math]::Round($Stopwatch.Elapsed.TotalSeconds, 3)
    IntervalMilliseconds            = $IntervalMilliseconds
    RequestedDurationMinutes        = $DurationMinutes
    SettleSeconds                   = $SettleSeconds
    PollCount                       = $PollNumber
    TargetMetadata                  = ('0x{0:X3}' -f $TargetMetadata)
    TargetLength                    = $TargetLength
    TargetPayloadHash               = $TargetPayloadHash
    UniqueTargetValuesObserved      = $ValueSummaries.Count
    NewTargetValuesDuringWatch      = $NewValuesDuringWatch
    ValuesWithAnyLiveEvidence       = $ValuesWithAnyLiveEvidence
    ValuesWithPostSettleSamples     = $ValuesWithPostSettleSamples
    ValuesWithPostSettleLiveEvidence = $ValuesWithPostSettleLiveEvidence
    TotalNativeQueryFailures        = $TotalQueryFailures
    PostSettleNativeQueryFailures   = $PostSettleQueryFailures
    TotalLiveEvidenceSamples        = $TotalLiveEvidenceSamples
    PostSettleLiveEvidenceSamples   = $PostSettleLiveEvidenceSamples
    Conclusion                      = $Conclusion
    ConclusionDetail                = $ConclusionDetail
    SampleCsv                       = $SampleCsv
    PollSummaryCsv                  = $PollCsv
    ValueSummaryCsv                 = $ValueSummaryCsv
    RunDirectory                    = $RunDirectory
}

$RunSummary |
    Export-Csv `
        -LiteralPath $RunSummaryCsv `
        -NoTypeInformation `
        -Encoding UTF8

Write-Host
Write-Host 'Timed live-state watch completed.'
Write-Host
Write-Host "Unique target values observed:       $($ValueSummaries.Count)"
Write-Host "Values with any live evidence:       $ValuesWithAnyLiveEvidence"
Write-Host "Values with post-settle samples:     $ValuesWithPostSettleSamples"
Write-Host "Post-settle live-evidence values:    $ValuesWithPostSettleLiveEvidence"
Write-Host "Post-settle native query failures:   $PostSettleQueryFailures"
Write-Host "New target values during watch:      $NewValuesDuringWatch"
Write-Host
Write-Host "Conclusion: $Conclusion"
Write-Host $ConclusionDetail
Write-Host
Write-Host "Run summary:   $RunSummaryCsv"
Write-Host "Value summary: $ValueSummaryCsv"
Write-Host "Samples:       $SampleCsv"
Write-Host "Poll summary:  $PollCsv"
Write-Host "Run log:       $RunLogPath"
Write-Host
