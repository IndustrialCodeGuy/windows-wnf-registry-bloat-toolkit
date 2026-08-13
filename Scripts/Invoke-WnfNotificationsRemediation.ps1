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
    Audits or removes the confirmed repeated 72-byte WNF registration family
    from the Windows Notifications registry key.

.DESCRIPTION
    This script is tailored to the investigated Windows Server 2019 condition
    under:

    HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications

    The default Audit mode is read-only. It inventories every root-level value,
    identifies the exact target family by 16-character hexadecimal value name,
    REG_BINARY type, decoded metadata 0x011, 72-byte length, and the confirmed
    SHA-256 payload hash. It also counts the separate 136-byte metadata-0x091
    user/AppContainer family and exports a structural summary and fixed
    candidate-name list.

    Cleanup mode repeats the authoritative structural inventory immediately
    before backup or deletion, requires explicit maintenance-window and
    rollback acknowledgement, requires an elevated local administrator at the
    console by default, saves the complete Notifications key, and re-reads,
    revalidates, and live-checks every candidate immediately before deletion.

    A candidate is preserved when its structure or payload no longer matches,
    a native WNF query fails, subscribers are present, state data is present,
    the change stamp is nonzero, or IsQuiescent is False. Cleanup preserves the
    Notifications key, all subkeys, SequenceNumber, the 136-byte family, all
    nonmatching root values, and values created after the fixed candidate list
    was captured. The script does not reboot automatically.

    Read-only audit:
        .\Invoke-WnfNotificationsRemediation.ps1

    Full cleanup simulation with per-value live checks:
        .\Invoke-WnfNotificationsRemediation.ps1 -Mode Cleanup -WhatIf

    Production cleanup using the immediate internal inventory:
        .\Invoke-WnfNotificationsRemediation.ps1 -Mode Cleanup -RollbackConfirmed -MaintenanceWindowConfirmed

    Previously approved counts may be supplied as optional additional guards.
    The -WhatIf cleanup simulation does not save the registry key or delete
    values and may take several hours because it performs the same per-value
    live WNF checks used by an actual cleanup. Diagnostic run logs and CSV
    output are still written during -WhatIf so the simulation can be reviewed.

.NOTES
    Run from elevated 64-bit Windows PowerShell 5.1 on Windows Server 2019.

    WNF is a private Windows mechanism. This script relies on the exact family
    established by the investigation and should not be generalized to other
    servers or payloads without separate validation.

    For production cleanup, disable new RDS logons, log off ordinary users,
    reboot, sign in through the physical, hypervisor, or out-of-band console
    with a local administrator, verify rollback, run cleanup, reboot after a
    successful cleanup, and validate the server before restoring user access.
#>

[CmdletBinding(
    SupportsShouldProcess = $true,
    ConfirmImpact = 'High'
)]
param(
    [ValidateSet('Audit', 'Cleanup')]
    [string] $Mode = 'Audit',

    # Optional additional guard. Use 0 to accept the candidate count found by
    # the cleanup run's immediate internal inventory.
    [ValidateRange(0, 10000000)]
    [int] $ExpectedCandidateCount = 0,

    # Optional additional guard. Use -1 to skip this comparison.
    [ValidateRange(-1, 10000000)]
    [int] $ExpectedUserScopedCount = -1,

    # Optional additional guard. Use 0 to skip this comparison.
    [ValidateRange(0, 10000000)]
    [int] $ExpectedTotalRootValues = 0,

    [string] $OutputRoot = (
        Join-Path $env:ProgramData 'WindowsWnfRegistryBloatToolkit'
    ),

    # Audit mode is structural by default. This switch performs the same
    # per-value live checks as cleanup, but never deletes anything.
    [switch] $IncludeLiveCheck,

    # Required for an actual Cleanup run.
    [switch] $RollbackConfirmed,

    # Required for an actual Cleanup run.
    [switch] $MaintenanceWindowConfirmed,

    # Cleanup is blocked outside a console session unless explicitly
    # overridden. An override is logged prominently.
    [switch] $AllowNonConsoleSession,

    # Cleanup is blocked for a domain account unless explicitly overridden.
    [switch] $AllowNonLocalAccount,

    [ValidateRange(1, 1000)]
    [int] $MaximumDeleteFailures = 5,

    [ValidateRange(100, 100000)]
    [int] $ProgressInterval = 2500,

    [ValidateRange(10, 10000)]
    [int] $CsvBatchSize = 500,

    [ValidateRange(100, 100000)]
    [int] $FlushInterval = 5000
)

$ErrorActionPreference = 'Stop'

# ============================================================
# Fixed, investigation-specific target
# ============================================================

$RegistrySubKey =
    'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications'

$RegistryDisplayPath =
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications'

$RegistryNativePath =
    'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications'

$DataSubKeyNativePath =
    'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications\Data'

$DataSubKeyProviderPath =
    'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications\Data'

[uint64] $WnfXorMask =
    [uint64]::Parse(
        '41C64E6DA3BC0074',
        [Globalization.NumberStyles]::HexNumber
    )

[uint64] $TargetMetadata = 0x011
[int] $TargetLength = 72

$TargetPayloadHash =
    'A847320A34E3ABD0F790D27CEF46D52CDD81E7B0F5257E8BE74FEF8FEE788840'

[uint64] $UserMetadata = 0x091
[int] $UserLength = 136

[uint32] $StatusSuccess = 0
[uint32] $StatusBufferOverflow =
    [uint32]::Parse(
        '80000005',
        [Globalization.NumberStyles]::HexNumber
    )
[uint32] $StatusBufferTooSmall =
    [uint32]::Parse(
        'C0000023',
        [Globalization.NumberStyles]::HexNumber
    )


# ============================================================
# Native declarations
# ============================================================

if (-not ('WnfRemediationNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct WNF_STATE_NAME_REMEDIATION
{
    public UInt32 Data0;
    public UInt32 Data1;
}

public static class WnfRemediationNative
{
    public const Int32 ERROR_SUCCESS = 0;
    public const Int32 ERROR_MORE_DATA = 234;
    public const Int32 ERROR_NO_MORE_ITEMS = 259;

    [DllImport(
        "advapi32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true
    )]
    public static extern Int32 RegEnumValue(
        IntPtr hKey,
        UInt32 dwIndex,
        StringBuilder lpValueName,
        ref UInt32 lpcchValueName,
        IntPtr lpReserved,
        ref UInt32 lpType,
        byte[] lpData,
        ref UInt32 lpcbData
    );

    [DllImport("ntdll.dll")]
    public static extern UInt32 NtQueryWnfStateNameInformation(
        ref WNF_STATE_NAME_REMEDIATION StateName,
        Int32 NameInfoClass,
        IntPtr ExplicitScope,
        out UInt32 InfoBuffer,
        UInt32 InfoBufferSize
    );

    [DllImport("ntdll.dll")]
    public static extern UInt32 NtQueryWnfStateData(
        ref WNF_STATE_NAME_REMEDIATION StateName,
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
# Output and logging
# ============================================================

$SafeMode = $Mode -replace '[^A-Za-z0-9._-]', '_'
$Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$OutputDirectory = Join-Path $OutputRoot "Wnf-Remediation-$SafeMode-$Timestamp"

New-Item -ItemType Directory -Path $OutputDirectory -Force -WhatIf:$false | Out-Null

$RunLogPath = Join-Path $OutputDirectory 'Run.log'
$PreSummaryPath = Join-Path $OutputDirectory 'PreCleanup-StructuralSummary.csv'
$CandidateListPath = Join-Path $OutputDirectory 'PreCleanup-TargetCandidates.csv'
$ActionLogPath = Join-Path $OutputDirectory 'Cleanup-Actions.csv'
$CleanupSummaryPath = Join-Path $OutputDirectory 'Cleanup-Summary.csv'
$PostSummaryPath = Join-Path $OutputDirectory 'PostCleanup-StructuralSummary.csv'
$PostCandidatesPath = Join-Path $OutputDirectory 'PostCleanup-TargetCandidates.csv'
$SessionSnapshotPath = Join-Path $OutputDirectory 'User-Sessions-BeforeCleanup.txt'

function Write-RunLog {
    param(
        [Parameter(Mandatory)]
        [string] $Message,

        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string] $Level = 'INFO'
    )

    $Line =
        '[{0}] [{1}] {2}' -f (
            Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        ),
        $Level,
        $Message

    Add-Content -LiteralPath $RunLogPath -Value $Line -Encoding UTF8 -WhatIf:$false

    switch ($Level) {
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Host $Line -ForegroundColor Red }
        default { Write-Host $Line }
    }
}

Write-RunLog "Script started in $Mode mode."
Write-RunLog "Output directory: $OutputDirectory"


# ============================================================
# Helpers
# ============================================================

$script:Sha256 =
    [Security.Cryptography.SHA256]::Create()

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

function Copy-ByteRange {
    param(
        [Parameter(Mandatory)]
        [byte[]] $Source,

        [Parameter(Mandatory)]
        [int] $Length
    )

    [byte[]] $Destination =
        New-Object byte[] $Length

    [Array]::Copy(
        $Source,
        0,
        $Destination,
        0,
        $Length
    )

    return $Destination
}

function ConvertTo-WnfStateName {
    param(
        [Parameter(Mandatory)]
        [string] $ValueName
    )

    [uint64] $Encoded =
        [Convert]::ToUInt64($ValueName, 16)

    [byte[]] $EncodedBytes =
        [BitConverter]::GetBytes($Encoded)

    $StateName =
        New-Object WNF_STATE_NAME_REMEDIATION

    $StateName.Data0 =
        [BitConverter]::ToUInt32(
            $EncodedBytes,
            0
        )

    $StateName.Data1 =
        [BitConverter]::ToUInt32(
            $EncodedBytes,
            4
        )

    return $StateName
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

function Get-WnfLiveSafety {
    param(
        [Parameter(Mandatory)]
        [string] $ValueName
    )

    $StateName =
        ConvertTo-WnfStateName `
            -ValueName $ValueName

    [uint32] $ExistsRaw = 0
    $ExistsStateName = $StateName

    [uint32] $ExistsStatus =
        [WnfRemediationNative]::
            NtQueryWnfStateNameInformation(
                [ref] $ExistsStateName,
                0,
                [IntPtr]::Zero,
                [ref] $ExistsRaw,
                4
            )

    [uint32] $SubscribersRaw = 0
    $SubscribersStateName = $StateName

    [uint32] $SubscribersStatus =
        [WnfRemediationNative]::
            NtQueryWnfStateNameInformation(
                [ref] $SubscribersStateName,
                1,
                [IntPtr]::Zero,
                [ref] $SubscribersRaw,
                4
            )

    [uint32] $QuiescentRaw = 0
    $QuiescentStateName = $StateName

    [uint32] $QuiescentStatus =
        [WnfRemediationNative]::
            NtQueryWnfStateNameInformation(
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
        [WnfRemediationNative]::
            NtQueryWnfStateData(
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
            -not (
                Test-AllowedDataProbeStatus `
                    -Status $DataStatus
            )
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

    $Evidence =
        New-Object 'System.Collections.Generic.List[string]'

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
        ExistsStatus          =
            ConvertTo-StatusHex -Status $ExistsStatus
        SubscribersStatus     =
            ConvertTo-StatusHex -Status $SubscribersStatus
        QuiescentStatus       =
            ConvertTo-StatusHex -Status $QuiescentStatus
        StateDataStatus       =
            ConvertTo-StatusHex -Status $DataStatus
    }
}

function Test-CurrentValueMatchesTarget {
    param(
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey] $RegistryKey,

        [Parameter(Mandatory)]
        [string] $ValueName
    )

    try {
        $Kind =
            $RegistryKey.GetValueKind($ValueName)

        $Data =
            $RegistryKey.GetValue(
                $ValueName,
                $null,
                [Microsoft.Win32.RegistryValueOptions]::
                    DoNotExpandEnvironmentNames
            )

        if (
            $Kind -ne
                [Microsoft.Win32.RegistryValueKind]::Binary -or
            $Data -isnot [byte[]]
        ) {
            return [pscustomobject]@{
                Match  = $false
                Reason = 'Registry type is not REG_BINARY'
                Hash   = ''
                Length = $null
            }
        }

        [byte[]] $Data = $Data

        if ($Data.Length -ne $TargetLength) {
            return [pscustomobject]@{
                Match  = $false
                Reason =
                    "Data length is $($Data.Length), expected $TargetLength"
                Hash   = ''
                Length = $Data.Length
            }
        }

        if ($ValueName -notmatch '^[0-9A-Fa-f]{16}$') {
            return [pscustomobject]@{
                Match  = $false
                Reason = 'Value name is not 16 hexadecimal characters'
                Hash   = ''
                Length = $Data.Length
            }
        }

        [uint64] $Encoded =
            [Convert]::ToUInt64($ValueName, 16)

        [uint64] $Decoded =
            $Encoded -bxor $WnfXorMask

        [uint64] $Metadata =
            $Decoded -band [uint64] 0x7FF

        if ($Metadata -ne $TargetMetadata) {
            return [pscustomobject]@{
                Match  = $false
                Reason =
                    ('Metadata is 0x{0:X3}, expected 0x{1:X3}' -f
                        $Metadata,
                        $TargetMetadata)
                Hash   = ''
                Length = $Data.Length
            }
        }

        $Hash =
            Get-Sha256Hex -Bytes $Data

        if ($Hash -ne $TargetPayloadHash) {
            return [pscustomobject]@{
                Match  = $false
                Reason = 'Complete payload hash differs from target'
                Hash   = $Hash
                Length = $Data.Length
            }
        }

        return [pscustomobject]@{
            Match  = $true
            Reason = ''
            Hash   = $Hash
            Length = $Data.Length
        }
    }
    catch {
        return [pscustomobject]@{
            Match  = $false
            Reason =
                "Value unavailable or unreadable: $($_.Exception.Message)"
            Hash   = ''
            Length = $null
        }
    }
}


# ============================================================
# Structural inventory
# ============================================================

function Get-NotificationsStructuralInventory {
    param(
        [Parameter(Mandatory)]
        [string] $Label
    )

    $BaseKey = $null
    $Key = $null

    try {
        $BaseKey =
            [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine,
                [Microsoft.Win32.RegistryView]::Registry64
            )

        $Key =
            $BaseKey.OpenSubKey(
                $RegistrySubKey,
                $false
            )

        if ($null -eq $Key) {
            throw "Registry key was not found: $RegistryDisplayPath"
        }

        $Handle =
            $Key.Handle.DangerousGetHandle()

        $InitialValueCount =
            $Key.ValueCount

        $Candidates =
            New-Object `
                'System.Collections.Generic.List[object]'

        $Counters = [ordered]@{
            TotalRootValues                = 0
            SequenceNumberValues           = 0
            ExactTargetFamily              = 0
            System72Metadata011OtherHash   = 0
            User136Metadata091             = 0
            OtherRootValues                = 0
            PayloadReadFailures            = 0
        }

        [byte[]] $DataBuffer =
            New-Object byte[] 512

        for (
            [uint32] $EnumerationIndex = 0;
            ;
            $EnumerationIndex++
        ) {
            if (
                $EnumerationIndex -eq 0 -or
                (
                    $EnumerationIndex %
                    $ProgressInterval
                ) -eq 0
            ) {
                $PercentComplete = 0

                if ($InitialValueCount -gt 0) {
                    $PercentComplete =
                        [Math]::Min(
                            100,
                            [Math]::Floor(
                                (
                                    $EnumerationIndex /
                                    $InitialValueCount
                                ) * 100
                            )
                        )
                }

                Write-Progress `
                    -Activity "Inventorying Notifications values ($Label)" `
                    -Status (
                        "$EnumerationIndex examined; " +
                        "$($Counters.ExactTargetFamily) exact targets"
                    ) `
                    -PercentComplete $PercentComplete
            }

            $NameCapacity = 16384
            $NameBuffer =
                New-Object Text.StringBuilder(
                    $NameCapacity
                )

            [uint32] $NameLength =
                $NameCapacity

            [uint32] $ValueType = 0
            [uint32] $DataLength =
                $DataBuffer.Length

            $EnumResult =
                [WnfRemediationNative]::RegEnumValue(
                    $Handle,
                    $EnumerationIndex,
                    $NameBuffer,
                    [ref] $NameLength,
                    [IntPtr]::Zero,
                    [ref] $ValueType,
                    $DataBuffer,
                    [ref] $DataLength
                )

            if (
                $EnumResult -eq
                [WnfRemediationNative]::
                    ERROR_NO_MORE_ITEMS
            ) {
                break
            }

            if (
                $EnumResult -ne
                    [WnfRemediationNative]::
                        ERROR_SUCCESS -and
                $EnumResult -ne
                    [WnfRemediationNative]::
                        ERROR_MORE_DATA
            ) {
                throw (
                    "RegEnumValue failed at index " +
                    "$EnumerationIndex with Win32 error " +
                    "$EnumResult."
                )
            }

            $Counters.TotalRootValues++
            $ValueName =
                $NameBuffer.ToString()

            if ($ValueName -eq 'SequenceNumber') {
                $Counters.SequenceNumberValues++
                continue
            }

            $Classified = $false

            if (
                $ValueName -match
                    '^[0-9A-Fa-f]{16}$'
            ) {
                try {
                    [uint64] $Encoded =
                        [Convert]::ToUInt64(
                            $ValueName,
                            16
                        )

                    [uint64] $Decoded =
                        $Encoded -bxor $WnfXorMask

                    [uint64] $Metadata =
                        $Decoded -band [uint64] 0x7FF

                    [uint64] $UniqueId =
                        $Decoded -shr 11

                    if (
                        $ValueType -eq 3 -and
                        $DataLength -eq $TargetLength -and
                        $Metadata -eq $TargetMetadata
                    ) {
                        if (
                            $EnumResult -ne
                            [WnfRemediationNative]::
                                ERROR_SUCCESS
                        ) {
                            $Counters.PayloadReadFailures++
                            $Counters.
                                System72Metadata011OtherHash++
                            $Classified = $true
                        }
                        else {
                            [byte[]] $Payload =
                                Copy-ByteRange `
                                    -Source $DataBuffer `
                                    -Length $TargetLength

                            $PayloadHash =
                                Get-Sha256Hex `
                                    -Bytes $Payload

                            if (
                                $PayloadHash -eq
                                $TargetPayloadHash
                            ) {
                                $Counters.ExactTargetFamily++

                                [void] $Candidates.Add(
                                    [pscustomobject]@{
                                        EnumerationIndex =
                                            [int64] $EnumerationIndex
                                        ValueName =
                                            $ValueName
                                        UniqueId =
                                            ('0x{0:X}' -f $UniqueId)
                                    }
                                )
                            }
                            else {
                                $Counters.
                                    System72Metadata011OtherHash++
                            }

                            $Classified = $true
                        }
                    }
                    elseif (
                        $ValueType -eq 3 -and
                        $DataLength -eq $UserLength -and
                        $Metadata -eq $UserMetadata
                    ) {
                        $Counters.User136Metadata091++
                        $Classified = $true
                    }
                }
                catch {
                    $Classified = $false
                }
            }

            if (-not $Classified) {
                $Counters.OtherRootValues++
            }
        }

        Write-Progress `
            -Activity "Inventorying Notifications values ($Label)" `
            -Completed

        $Summary = [pscustomobject]@{
            CheckedAt =
                Get-Date
            Label =
                $Label
            RegistryPath =
                $RegistryDisplayPath
            TotalRootValues =
                $Counters.TotalRootValues
            SequenceNumberValues =
                $Counters.SequenceNumberValues
            ExactTargetFamily =
                $Counters.ExactTargetFamily
            System72Metadata011OtherHash =
                $Counters.System72Metadata011OtherHash
            User136Metadata091 =
                $Counters.User136Metadata091
            OtherRootValues =
                $Counters.OtherRootValues
            PayloadReadFailures =
                $Counters.PayloadReadFailures
            TargetMetadata =
                ('0x{0:X3}' -f $TargetMetadata)
            TargetLength =
                $TargetLength
            TargetPayloadHash =
                $TargetPayloadHash
        }

        return [pscustomobject]@{
            Summary =
                $Summary
            Candidates =
                $Candidates
        }
    }
    finally {
        if ($null -ne $Key) {
            $Key.Dispose()
        }

        if ($null -ne $BaseKey) {
            $BaseKey.Dispose()
        }
    }
}


# ============================================================
# Backup
# ============================================================

function New-NotificationsRegistryBackup {
    $RegExe = Join-Path $env:SystemRoot 'System32\reg.exe'

    if (-not (Test-Path -LiteralPath $RegExe -PathType Leaf)) {
        throw "reg.exe was not found: $RegExe"
    }

    $HiveBackupPath = Join-Path $OutputDirectory 'Notifications-BeforeCleanup.hiv'

    $HiveBackupLog = Join-Path $OutputDirectory 'Notifications-BeforeCleanup-reg-save.log'

    Write-RunLog (
        "Saving the complete Notifications key to " +
        $HiveBackupPath
    )

    $SaveOutput = & $RegExe save $RegistryNativePath $HiveBackupPath /y 2>&1

    $SaveExitCode =
        $LASTEXITCODE

    $SaveOutput |
        Out-File -LiteralPath $HiveBackupLog -Encoding UTF8 -WhatIf:$false

    if ($SaveExitCode -ne 0) {
        throw (
            "reg save failed with exit code " +
            "$SaveExitCode. See $HiveBackupLog"
        )
    }

    if (-not (Test-Path -LiteralPath $HiveBackupPath -PathType Leaf)) {
        throw (
            'reg save reported success, but the backup ' +
            'file does not exist.'
        )
    }

    $HiveFile = Get-Item -LiteralPath $HiveBackupPath

    if ($HiveFile.Length -le 0) {
        throw 'The registry backup file is empty.'
    }

    $HiveHash = (Get-FileHash -LiteralPath $HiveBackupPath -Algorithm SHA256).Hash

    $DataExportPath = Join-Path $OutputDirectory 'Notifications-Data-BeforeCleanup.reg'

    $DataExportLog = Join-Path $OutputDirectory 'Notifications-Data-reg-export.log'

    $DataExported = $false

    if (Test-Path -LiteralPath $DataSubKeyProviderPath) {
        Write-RunLog (
            'Exporting the Notifications\Data subkey ' +
            'as an additional readable backup.'
        )

        $ExportOutput = & $RegExe export $DataSubKeyNativePath $DataExportPath /y 2>&1

        $ExportExitCode =
            $LASTEXITCODE

        $ExportOutput |
            Out-File -LiteralPath $DataExportLog -Encoding UTF8 -WhatIf:$false

        if (
            $ExportExitCode -eq 0 -and
            (
                Test-Path -LiteralPath $DataExportPath -PathType Leaf
            )
        ) {
            $DataExported = $true
        }
        else {
            Write-RunLog (
                'The optional Notifications\Data export ' +
                'did not complete successfully. The complete ' +
                'binary key backup succeeded and remains the ' +
                'required backup.'
            ) 'WARN'
        }
    }

    $Manifest = [pscustomobject]@{
        CreatedAt =
            Get-Date
        RegistryPath =
            $RegistryDisplayPath
        HiveBackupPath =
            $HiveBackupPath
        HiveBackupBytes =
            $HiveFile.Length
        HiveBackupSha256 =
            $HiveHash
        CompleteKeySaveExitCode =
            $SaveExitCode
        DataSubKeyExported =
            $DataExported
        DataSubKeyExportPath =
            if ($DataExported) {
                $DataExportPath
            }
            else {
                ''
            }
    }

    $Manifest |
        Export-Csv -LiteralPath (
            Join-Path $OutputDirectory 'Backup-Manifest.csv'
        ) -NoTypeInformation -Encoding UTF8 -WhatIf:$false

    Write-RunLog (
        "Registry backup verified: " +
        "$($HiveFile.Length) bytes; SHA-256 $HiveHash"
    )

    return $Manifest
}


# ============================================================
# Per-candidate live check and cleanup
# ============================================================

function Invoke-TargetCandidateEvaluation {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IEnumerable] $Candidates,

        [Parameter(Mandatory)]
        [bool] $PerformDeletion,

        [Parameter(Mandatory)]
        [string] $OperationLabel
    )

    $BaseKey = $null
    $WritableKey = $null

    $Batch =
        New-Object `
            'System.Collections.Generic.List[object]'

    $script:ActionCsvInitialized = $false

    $Counters = [ordered]@{
        CandidateCount =
            0
        Evaluated =
            0
        ExactAtEvaluation =
            0
        FilterMismatchOrMissing =
            0
        NativeQueryFailure =
            0
        LiveEvidencePreserved =
            0
        WouldDelete =
            0
        Deleted =
            0
        DeleteFailure =
            0
    }

    function Flush-ActionBatch {
        if ($Batch.Count -eq 0) {
            return
        }

        if (-not $script:ActionCsvInitialized) {
            $Batch |
                Export-Csv -LiteralPath $ActionLogPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false

            $script:ActionCsvInitialized = $true
            $script:ActionCsvPath =
                $ActionLogPath
        }
        else {
            $Batch |
                Export-Csv -LiteralPath $ActionLogPath -NoTypeInformation -Encoding UTF8 `
                    -Append -WhatIf:$false
        }

        $script:ActionCsvInitialized = $true
        $Batch.Clear()
    }

    try {
        $BaseKey =
            [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine,
                [Microsoft.Win32.RegistryView]::Registry64
            )

        $WritableKey =
            $BaseKey.OpenSubKey(
                $RegistrySubKey,
                $PerformDeletion
            )

        if ($null -eq $WritableKey) {
            $AccessText =
                if ($PerformDeletion) {
                    'write'
                }
                else {
                    'read'
                }

            throw (
                "Could not open the registry key with " +
                "$AccessText access: $RegistryDisplayPath"
            )
        }

        $CandidateCount = $Candidates.Count

        $Counters.CandidateCount =
            $CandidateCount

        $Processed = 0
        $DeletedSinceFlush = 0

        foreach ($Candidate in $Candidates) {
            $Processed++
            $Counters.Evaluated++

            if (
                $Processed -eq 1 -or
                ($Processed % 100) -eq 0
            ) {
                $PercentComplete =
                    if ($CandidateCount -gt 0) {
                        [Math]::Floor(
                            (
                                $Processed /
                                $CandidateCount
                            ) * 100
                        )
                    }
                    else {
                        100
                    }

                Write-Progress `
                    -Activity $OperationLabel `
                    -Status (
                        "$Processed of $CandidateCount; " +
                        "$($Counters.Deleted) deleted; " +
                        "$($Counters.LiveEvidencePreserved) " +
                        'preserved for live evidence'
                    ) `
                    -PercentComplete $PercentComplete
            }

            $ValueName =
                [string] $Candidate.ValueName

            $Action = 'Preserved'
            $Reason = ''
            $ErrorText = ''
            $FilterMatch = $false
            $PayloadHash = ''
            $DataLength = $null

            $StateNameExists = $null
            $SubscribersPresent = $null
            $IsQuiescent = $null
            $StateDataRequiredSize = $null
            $ChangeStamp = $null
            $EvidenceSummary = ''
            $ExistsStatus = ''
            $SubscribersStatus = ''
            $QuiescentStatus = ''
            $StateDataStatus = ''

            try {
                $MatchResult =
                    Test-CurrentValueMatchesTarget `
                        -RegistryKey $WritableKey `
                        -ValueName $ValueName

                $FilterMatch =
                    $MatchResult.Match

                $PayloadHash =
                    $MatchResult.Hash

                $DataLength =
                    $MatchResult.Length

                if (-not $MatchResult.Match) {
                    $Counters.FilterMismatchOrMissing++
                    $Reason =
                        $MatchResult.Reason
                }
                else {
                    $Counters.ExactAtEvaluation++

                    $LiveResult =
                        Get-WnfLiveSafety `
                            -ValueName $ValueName

                    $StateNameExists =
                        $LiveResult.StateNameExists

                    $SubscribersPresent =
                        $LiveResult.SubscribersPresent

                    $IsQuiescent =
                        $LiveResult.IsQuiescent

                    $StateDataRequiredSize =
                        $LiveResult.
                            StateDataRequiredSize

                    $ChangeStamp =
                        $LiveResult.ChangeStamp

                    $EvidenceSummary =
                        $LiveResult.EvidenceSummary

                    $ExistsStatus =
                        $LiveResult.ExistsStatus

                    $SubscribersStatus =
                        $LiveResult.SubscribersStatus

                    $QuiescentStatus =
                        $LiveResult.QuiescentStatus

                    $StateDataStatus =
                        $LiveResult.StateDataStatus

                    if ($LiveResult.QueryFailure) {
                        $Counters.NativeQueryFailure++
                        $Reason =
                            'Preserved because a native WNF ' +
                            'query did not return an accepted status.'
                    }
                    elseif ($LiveResult.LiveEvidence) {
                        $Counters.LiveEvidencePreserved++
                        $Reason =
                            'Preserved because live WNF ' +
                            'evidence was present: ' +
                            $LiveResult.EvidenceSummary
                    }
                    elseif (-not $PerformDeletion) {
                        $Counters.WouldDelete++
                        $Action = 'WouldDelete'
                        $Reason =
                            'Exact target with no live evidence; ' +
                            'no deletion was requested.'
                    }
                    else {
                        try {
                            $WritableKey.DeleteValue(
                                $ValueName,
                                $true
                            )

                            $Counters.Deleted++
                            $DeletedSinceFlush++
                            $Action = 'Deleted'
                            $Reason =
                                'Exact target with no live evidence.'

                            if (
                                $DeletedSinceFlush -ge
                                $FlushInterval
                            ) {
                                $WritableKey.Flush()
                                $DeletedSinceFlush = 0
                            }
                        }
                        catch {
                            $Counters.DeleteFailure++
                            $Action = 'DeleteFailed'
                            $Reason =
                                'Registry deletion failed.'
                            $ErrorText =
                                $_.Exception.Message
                        }
                    }
                }
            }
            catch {
                $Action = 'EvaluationFailed'
                $Reason =
                    'Unexpected evaluation error; value preserved.'
                $ErrorText =
                    $_.Exception.Message
                $Counters.FilterMismatchOrMissing++
            }

            [void] $Batch.Add(
                [pscustomobject]@{
                    CheckedAt =
                        Get-Date
                    ValueName =
                        $ValueName
                    EnumerationIndex =
                        $Candidate.EnumerationIndex
                    UniqueId =
                        $Candidate.UniqueId
                    ExactTargetAtEvaluation =
                        $FilterMatch
                    DataLength =
                        $DataLength
                    PayloadHash =
                        $PayloadHash
                    StateNameExists =
                        $StateNameExists
                    SubscribersPresent =
                        $SubscribersPresent
                    IsQuiescent =
                        $IsQuiescent
                    StateDataRequiredSize =
                        $StateDataRequiredSize
                    ChangeStamp =
                        $ChangeStamp
                    EvidenceSummary =
                        $EvidenceSummary
                    ExistsStatus =
                        $ExistsStatus
                    SubscribersStatus =
                        $SubscribersStatus
                    QuiescentStatus =
                        $QuiescentStatus
                    StateDataStatus =
                        $StateDataStatus
                    Action =
                        $Action
                    Reason =
                        $Reason
                    Error =
                        $ErrorText
                }
            )

            if ($Batch.Count -ge $CsvBatchSize) {
                Flush-ActionBatch
            }

            if (
                $Counters.DeleteFailure -ge
                $MaximumDeleteFailures
            ) {
                Flush-ActionBatch

                throw (
                    "Deletion stopped after " +
                    "$($Counters.DeleteFailure) failures. " +
                    "Review $ActionLogPath and the rollback plan."
                )
            }
        }

        if ($PerformDeletion) {
            $WritableKey.Flush()
        }

        Flush-ActionBatch

        Write-Progress `
            -Activity $OperationLabel `
            -Completed

        return [pscustomobject]@{
            CompletedAt =
                Get-Date
            OperationLabel =
                $OperationLabel
            CandidateCount =
                $Counters.CandidateCount
            Evaluated =
                $Counters.Evaluated
            ExactAtEvaluation =
                $Counters.ExactAtEvaluation
            FilterMismatchOrMissing =
                $Counters.FilterMismatchOrMissing
            NativeQueryFailure =
                $Counters.NativeQueryFailure
            LiveEvidencePreserved =
                $Counters.LiveEvidencePreserved
            WouldDelete =
                $Counters.WouldDelete
            Deleted =
                $Counters.Deleted
            DeleteFailure =
                $Counters.DeleteFailure
            ActionLog =
                $ActionLogPath
        }
    }
    finally {
        try {
            if (
                $null -ne $WritableKey -and
                $PerformDeletion
            ) {
                $WritableKey.Flush()
            }
        }
        catch {
        }

        if ($Batch.Count -gt 0) {
            try {
                Flush-ActionBatch
            }
            catch {
            }
        }

        if ($null -ne $WritableKey) {
            $WritableKey.Dispose()
        }

        if ($null -ne $BaseKey) {
            $BaseKey.Dispose()
        }
    }
}


# ============================================================
# Preflight
# ============================================================

$Identity =
    [Security.Principal.WindowsIdentity]::
        GetCurrent()

$Principal =
    New-Object `
        -TypeName Security.Principal.WindowsPrincipal `
        -ArgumentList $Identity

$IsElevated =
    $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::
            Administrator
    )

$CurrentAccount =
    $Identity.Name

$CurrentSid =
    if ($null -ne $Identity.User) {
        $Identity.User.Value
    }
    else {
        ''
    }

$IsSystem =
    ($CurrentSid -eq 'S-1-5-18')

$IsLocalAccount =
    (
        $IsSystem -or
        $CurrentAccount.StartsWith(
            "$env:COMPUTERNAME\",
            [StringComparison]::OrdinalIgnoreCase
        )
    )

$SessionName =
    if (
        [string]::IsNullOrWhiteSpace(
            $env:SESSIONNAME
        )
    ) {
        '<unknown>'
    }
    else {
        $env:SESSIONNAME
    }

$IsConsoleSession =
    (
        $IsSystem -or
        $SessionName -eq 'Console'
    )

Write-RunLog "Computer: $env:COMPUTERNAME"
Write-RunLog "Account: $CurrentAccount"
Write-RunLog "Session: $SessionName"
Write-RunLog "Elevated: $IsElevated"
Write-RunLog "Local account or SYSTEM: $IsLocalAccount"
Write-RunLog "Console session or SYSTEM: $IsConsoleSession"
Write-RunLog "64-bit process: $([Environment]::Is64BitProcess)"
Write-RunLog "WhatIf requested: $([bool]$WhatIfPreference)"

if (-not [Environment]::Is64BitProcess) {
    throw (
        'Run this script from 64-bit Windows PowerShell.'
    )
}

if ($Mode -eq 'Cleanup' -and -not $IsElevated) {
    throw (
        'Cleanup mode requires an elevated PowerShell session.'
    )
}

if ($Mode -eq 'Audit' -and -not $IsElevated) {
    Write-RunLog (
        'Audit is not elevated. Registry reads or native ' +
        'queries may return access-denied results.'
    ) 'WARN'
}

$IsActualCleanup =
    (
        $Mode -eq 'Cleanup' -and
        -not [bool] $WhatIfPreference
    )

if ($IsActualCleanup) {
    if (-not $RollbackConfirmed) {
        throw (
            'Actual cleanup requires -RollbackConfirmed. ' +
            'Verify the VM snapshot or image-level rollback first.'
        )
    }

    if (-not $MaintenanceWindowConfirmed) {
        throw (
            'Actual cleanup requires ' +
            '-MaintenanceWindowConfirmed.'
        )
    }

    if (
        -not $IsConsoleSession -and
        -not $AllowNonConsoleSession
    ) {
        throw (
            'Cleanup is blocked because this is not a Console ' +
            'session. Use the physical, hypervisor, or out-of-band ' +
            'console. -AllowNonConsoleSession is available only as ' +
            'an explicit logged override.'
        )
    }

    if (
        -not $IsLocalAccount -and
        -not $AllowNonLocalAccount
    ) {
        throw (
            'Cleanup is blocked because the current account is not ' +
            'a local account. Use a local administrator. ' +
            '-AllowNonLocalAccount is available only as an explicit ' +
            'logged override.'
        )
    }

    if ($AllowNonConsoleSession) {
        Write-RunLog (
            'NON-CONSOLE CLEANUP OVERRIDE WAS USED.'
        ) 'WARN'
    }

    if ($AllowNonLocalAccount) {
        Write-RunLog (
            'NON-LOCAL-ACCOUNT CLEANUP OVERRIDE WAS USED.'
        ) 'WARN'
    }
}
elseif (
    $Mode -eq 'Cleanup' -and
    [bool] $WhatIfPreference
) {
    if (-not $IsConsoleSession) {
        Write-RunLog (
            'WhatIf cleanup is running outside a Console session. ' +
            'An actual cleanup would be blocked by default.'
        ) 'WARN'
    }

    if (-not $IsLocalAccount) {
        Write-RunLog (
            'WhatIf cleanup is running under a non-local account. ' +
            'An actual cleanup would be blocked by default.'
        ) 'WARN'
    }
}

try {
    & quser.exe 2>&1 |
        Out-File `
            -LiteralPath $SessionSnapshotPath `
            -Encoding UTF8 `
            -WhatIf:$false
}
catch {
    "Could not collect quser output: $($_.Exception.Message)" |
        Out-File `
            -LiteralPath $SessionSnapshotPath `
            -Encoding UTF8 `
            -WhatIf:$false
}


# ============================================================
# Pre-cleanup structural inventory
# ============================================================

Write-RunLog 'Starting structural inventory.'

$PreInventory =
    Get-NotificationsStructuralInventory `
        -Label 'PreCleanup'

$PreInventory.Summary |
    Export-Csv -LiteralPath $PreSummaryPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false

$PreInventory.Candidates |
    Export-Csv -LiteralPath $CandidateListPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false

$CandidateListHash =
    (Get-FileHash `
        -LiteralPath $CandidateListPath `
        -Algorithm SHA256
    ).Hash

Write-RunLog (
    'Structural inventory completed. ' +
    "Total root values: " +
    "$($PreInventory.Summary.TotalRootValues); " +
    "exact target family: " +
    "$($PreInventory.Summary.ExactTargetFamily); " +
    "136-byte user family: " +
    "$($PreInventory.Summary.User136Metadata091); " +
    "SequenceNumber: " +
    "$($PreInventory.Summary.SequenceNumberValues); " +
    "other root values: " +
    "$($PreInventory.Summary.OtherRootValues)."
)

Write-RunLog (
    "Candidate-list SHA-256: $CandidateListHash"
)

if ($Mode -eq 'Cleanup') {
    if ($PreInventory.Summary.ExactTargetFamily -le 0) {
        throw (
            'The immediate structural inventory found no exact members ' +
            'of the confirmed target family. No values were deleted.'
        )
    }

    if ($ExpectedCandidateCount -gt 0) {
        if (
            $PreInventory.Summary.ExactTargetFamily -ne
            $ExpectedCandidateCount
        ) {
            throw (
                'Candidate-count guard failed. Expected ' +
                "$ExpectedCandidateCount but found " +
                "$($PreInventory.Summary.ExactTargetFamily). " +
                'No values were deleted.'
            )
        }

        Write-RunLog (
            'Optional candidate-count guard matched: ' +
            "$ExpectedCandidateCount."
        )
    }
    else {
        Write-RunLog (
            'No external candidate-count guard was supplied. ' +
            'The immediate internal inventory is authoritative for this run.'
        )
    }

    if ($ExpectedUserScopedCount -ge 0) {
        if (
            $PreInventory.Summary.User136Metadata091 -ne
            $ExpectedUserScopedCount
        ) {
            throw (
                'User-family-count guard failed. Expected ' +
                "$ExpectedUserScopedCount but found " +
                "$($PreInventory.Summary.User136Metadata091). " +
                'No values were deleted.'
            )
        }

        Write-RunLog (
            'Optional user-family-count guard matched: ' +
            "$ExpectedUserScopedCount."
        )
    }

    if ($ExpectedTotalRootValues -gt 0) {
        if (
            $PreInventory.Summary.TotalRootValues -ne
            $ExpectedTotalRootValues
        ) {
            throw (
                'Total-root-value guard failed. Expected ' +
                "$ExpectedTotalRootValues but found " +
                "$($PreInventory.Summary.TotalRootValues). " +
                'No values were deleted.'
            )
        }

        Write-RunLog (
            'Optional total-root-value guard matched: ' +
            "$ExpectedTotalRootValues."
        )
    }

    if (
        $PreInventory.Summary.SequenceNumberValues -ne 1
    ) {
        throw (
            'Expected exactly one SequenceNumber value, but found ' +
            "$($PreInventory.Summary.SequenceNumberValues). " +
            'No values were deleted.'
        )
    }

    if (
        $PreInventory.Summary.PayloadReadFailures -ne 0
    ) {
        throw (
            'Structural inventory reported payload-read failures. ' +
            'No values were deleted.'
        )
    }
}


# ============================================================
# Audit-only completion or live-check audit
# ============================================================

if ($Mode -eq 'Audit' -and -not $IncludeLiveCheck) {
    Write-RunLog (
        'Audit mode completed. No registry values were changed.'
    )

    Write-Host
    Write-Host 'READ-ONLY AUDIT COMPLETED'
    Write-Host
    Write-Host (
        "Total root values:          " +
        $PreInventory.Summary.TotalRootValues
    )
    Write-Host (
        "Exact target family:        " +
        $PreInventory.Summary.ExactTargetFamily
    )
    Write-Host (
        "136-byte user family:       " +
        $PreInventory.Summary.User136Metadata091
    )
    Write-Host (
        "SequenceNumber values:      " +
        $PreInventory.Summary.SequenceNumberValues
    )
    Write-Host (
        "Other root values:          " +
        $PreInventory.Summary.OtherRootValues
    )
    Write-Host
    Write-Host "Summary:       $PreSummaryPath"
    Write-Host "Candidate list: $CandidateListPath"
    Write-Host "Run log:       $RunLogPath"

    $script:Sha256.Dispose()
    return
}


# ============================================================
# Decide whether deletion is authorized
# ============================================================

$PerformDeletion = $false

if ($Mode -eq 'Cleanup') {
    $PerformDeletion =
        $PSCmdlet.ShouldProcess(
            $RegistryDisplayPath,
            (
                'Delete up to ' +
                "$($PreInventory.Summary.ExactTargetFamily) exact " +
                '72-byte metadata-0x011 target-family values that ' +
                'pass immediate revalidation and live-state safety checks'
            )
        )

    if (
        -not $PerformDeletion -and
        -not [bool] $WhatIfPreference
    ) {
        Write-RunLog (
            'Cleanup was not confirmed. No registry values ' +
            'were changed.'
        ) 'WARN'

        $script:Sha256.Dispose()
        return
    }
}


# ============================================================
# Backup before actual cleanup
# ============================================================

$BackupManifest = $null

if ($PerformDeletion) {
    $BackupManifest =
        New-NotificationsRegistryBackup
}
elseif (
    $Mode -eq 'Cleanup' -and
    [bool] $WhatIfPreference
) {
    Write-RunLog (
        'WhatIf mode: registry backup was intentionally skipped.'
    )
}


# ============================================================
# Per-value evaluation / cleanup
# ============================================================

$OperationLabel =
    if ($PerformDeletion) {
        'Evaluating and deleting exact inactive WNF targets'
    }
    else {
        'Evaluating exact WNF targets without deletion'
    }

Write-RunLog (
    "$OperationLabel. This may take several hours."
)

$CleanupResult =
    Invoke-TargetCandidateEvaluation `
        -Candidates $PreInventory.Candidates `
        -PerformDeletion $PerformDeletion `
        -OperationLabel $OperationLabel

$CleanupResult |
    Export-Csv -LiteralPath $CleanupSummaryPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false

Write-RunLog (
    'Candidate evaluation completed. ' +
    "Evaluated: $($CleanupResult.Evaluated); " +
    "exact at evaluation: " +
    "$($CleanupResult.ExactAtEvaluation); " +
    "native-query failures: " +
    "$($CleanupResult.NativeQueryFailure); " +
    "preserved for live evidence: " +
    "$($CleanupResult.LiveEvidencePreserved); " +
    "would delete: " +
    "$($CleanupResult.WouldDelete); " +
    "deleted: $($CleanupResult.Deleted); " +
    "delete failures: " +
    "$($CleanupResult.DeleteFailure)."
)


# ============================================================
# Post-cleanup verification
# ============================================================

$PostInventory = $null

if ($PerformDeletion) {
    Write-RunLog 'Starting post-cleanup structural inventory.'

    $PostInventory =
        Get-NotificationsStructuralInventory `
            -Label 'PostCleanup'

    $PostInventory.Summary |
        Export-Csv -LiteralPath $PostSummaryPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false

    $PostInventory.Candidates |
        Export-Csv -LiteralPath $PostCandidatesPath -NoTypeInformation -Encoding UTF8 -WhatIf:$false

    Write-RunLog (
        'Post-cleanup inventory completed. ' +
        "Total root values: " +
        "$($PostInventory.Summary.TotalRootValues); " +
        "remaining exact target family: " +
        "$($PostInventory.Summary.ExactTargetFamily); " +
        "136-byte user family: " +
        "$($PostInventory.Summary.User136Metadata091); " +
        "SequenceNumber: " +
        "$($PostInventory.Summary.SequenceNumberValues); " +
        "other root values: " +
        "$($PostInventory.Summary.OtherRootValues)."
    )

    if (
        $PostInventory.Summary.User136Metadata091 -ne
        $PreInventory.Summary.User136Metadata091
    ) {
        Write-RunLog (
            'The 136-byte user-family count changed between ' +
            'the pre- and post-cleanup inventories. The script ' +
            'did not target that family; review concurrent system ' +
            'activity and the logs.'
        ) 'WARN'
    }

    if (
        $PostInventory.Summary.SequenceNumberValues -ne 1
    ) {
        Write-RunLog (
            'Post-cleanup inventory did not find exactly one ' +
            'SequenceNumber value. Review before returning the ' +
            'server to service.'
        ) 'WARN'
    }

    if (
        $CleanupResult.DeleteFailure -gt 0 -or
        $PostInventory.Summary.PayloadReadFailures -gt 0
    ) {
        Write-RunLog (
            'Cleanup completed with failures or post-inventory ' +
            'read errors. Do not return the server to service ' +
            'without review.'
        ) 'ERROR'
    }
}


# ============================================================
# Final output
# ============================================================

Write-Host
Write-Host 'WNF REMEDIATION RUN COMPLETED'
Write-Host
Write-Host "Mode:                     $Mode"
Write-Host "WhatIf:                   $([bool]$WhatIfPreference)"
Write-Host (
    "Pre-cleanup candidates:   " +
    $PreInventory.Summary.ExactTargetFamily
)
Write-Host (
    "Native-query failures:    " +
    $CleanupResult.NativeQueryFailure
)
Write-Host (
    "Preserved for live use:   " +
    $CleanupResult.LiveEvidencePreserved
)
Write-Host (
    "Would delete:             " +
    $CleanupResult.WouldDelete
)
Write-Host (
    "Deleted:                  " +
    $CleanupResult.Deleted
)
Write-Host (
    "Delete failures:          " +
    $CleanupResult.DeleteFailure
)

if ($PerformDeletion) {
    Write-Host (
        "Remaining candidates:     " +
        $PostInventory.Summary.ExactTargetFamily
    )

    Write-Host
    Write-Host 'A REBOOT IS REQUIRED BEFORE VALIDATION.'
    Write-Host (
        'Do not restore Gateway/RDS user access until the ' +
        'post-reboot checks are complete.'
    )
}
else {
    Write-Host
    Write-Host 'No registry values were deleted.'
}

Write-Host
Write-Host "Output directory: $OutputDirectory"
Write-Host "Run log:         $RunLogPath"
Write-Host "Action log:      $ActionLogPath"

Write-RunLog 'Script completed.'

$script:Sha256.Dispose()
