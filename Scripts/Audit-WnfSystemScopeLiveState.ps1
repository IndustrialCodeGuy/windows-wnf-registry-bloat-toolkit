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
    Audits live state information for the repeated 72-byte system-scoped WNF
    value family.

.DESCRIPTION
    Enumerates Windows Notifications values, identifies members of the
    observed 72-byte WNF family by name metadata, registry type, and length,
    and audits a distributed sample of 1,000 values by default.

    When -ReferenceValueName is omitted, the script automatically locates an
    exact member of the toolkit's confirmed target family by REG_BINARY type,
    decoded metadata 0x011, 72-byte length, and the fixed SHA-256 payload hash.
    That value's complete payload becomes the byte-for-byte reference for the
    audit. An explicitly supplied -ReferenceValueName must match the same fixed
    family boundary.

    Each selected value is re-read and compared with the reference payload,
    then queried through read-only native WNF routines for state-name
    existence, subscribers, quiescence, state-data size and status, change
    stamp, and a state-data SHA-256 hash when readable.

    Use -ReuseNamesFromCsv to re-audit the same names after a reboot or other
    test condition. Use -FullScan only after the sample audit has completed
    successfully.

    This script is read-only. It contains no registry-delete or WNF-delete
    operation.

.NOTES
    Run from elevated 64-bit Windows PowerShell 5.1 on Windows Server 2019.

    WNF is a private Windows mechanism. Treat these results as diagnostic
    evidence, not as an authoritative stale/not-stale determination.
#>

[CmdletBinding()]
param(
    # Optional exact member of the confirmed toolkit family. When omitted,
    # the script discovers one automatically from the current registry data.
    [string] $ReferenceValueName,

    [ValidateRange(3, 1000000)]
    [int] $SampleCount = 1000,

    [switch] $FullScan,

    # Re-audit the exact ValueName entries from a prior output CSV.
    [string] $ReuseNamesFromCsv,

    [string] $AuditLabel = 'Baseline',

    [string] $OutputDirectory = (
        Join-Path $env:ProgramData 'WindowsWnfRegistryBloatToolkit\LiveAudit'
    ),

    [ValidateRange(0, 16777216)]
    [int] $MaxStateDataBytes = 1048576,

    [ValidateRange(100, 100000)]
    [int] $ProgressInterval = 2500,

    [ValidateRange(10, 10000)]
    [int] $CsvBatchSize = 500
)

$ErrorActionPreference = 'Stop'

if ($FullScan -and $ReuseNamesFromCsv) {
    throw 'Use either -FullScan or -ReuseNamesFromCsv, not both.'
}

$RegistrySubKey =
    'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications'

$RegistryDisplayPath =
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications'

[uint64] $WnfXorMask =
    [uint64]::Parse(
        '41C64E6DA3BC0074',
        [Globalization.NumberStyles]::HexNumber
    )

# Fixed, investigation-specific family boundary. Keep these values aligned
# with Invoke-WnfNotificationsRemediation.ps1.
[uint64] $TargetMetadata = 0x011
[int] $TargetLength = 72
$TargetPayloadHash =
    'A847320A34E3ABD0F790D27CEF46D52CDD81E7B0F5257E8BE74FEF8FEE788840'

[uint32] $StatusSuccess = 0
[uint32] $NtFailureMask =
    [uint32]::Parse('80000000', [Globalization.NumberStyles]::HexNumber)
[uint32] $StatusBufferOverflow =
    [uint32]::Parse('80000005', [Globalization.NumberStyles]::HexNumber)
[uint32] $StatusBufferTooSmall =
    [uint32]::Parse('C0000023', [Globalization.NumberStyles]::HexNumber)


# ============================================================
# Native declarations
# ============================================================

if (-not ('WnfLiveAuditNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct WNF_STATE_NAME_AUDIT
{
    public UInt32 Data0;
    public UInt32 Data1;
}

public static class WnfLiveAuditNative
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
        ref WNF_STATE_NAME_AUDIT StateName,
        Int32 NameInfoClass,
        IntPtr ExplicitScope,
        out UInt32 InfoBuffer,
        UInt32 InfoBufferSize
    );

    [DllImport("ntdll.dll")]
    public static extern UInt32 NtQueryWnfStateData(
        ref WNF_STATE_NAME_AUDIT StateName,
        IntPtr TypeId,
        IntPtr ExplicitScope,
        out UInt32 ChangeStamp,
        IntPtr Buffer,
        ref UInt32 BufferSize
    );

    [DllImport("ntdll.dll")]
    public static extern UInt32 RtlNtStatusToDosError(
        UInt32 Status
    );
}
'@
}


# ============================================================
# Helpers
# ============================================================

function Test-NtSuccess {
    param(
        [Parameter(Mandatory)]
        [uint32] $Status
    )

    return (($Status -band $NtFailureMask) -eq 0)
}


$script:NtStatusCache = @{}

function Get-NtStatusText {
    param(
        [Parameter(Mandatory)]
        [uint32] $Status
    )

    $Hex = '0x{0:X8}' -f $Status

    if ($script:NtStatusCache.ContainsKey($Hex)) {
        return $script:NtStatusCache[$Hex]
    }

    $KnownName = switch ($Hex) {
        '0x00000000' { 'STATUS_SUCCESS' }
        '0x80000005' { 'STATUS_BUFFER_OVERFLOW' }
        '0xC000000D' { 'STATUS_INVALID_PARAMETER' }
        '0xC0000022' { 'STATUS_ACCESS_DENIED' }
        '0xC0000023' { 'STATUS_BUFFER_TOO_SMALL' }
        '0xC0000034' { 'STATUS_OBJECT_NAME_NOT_FOUND' }
        '0xC0000225' { 'STATUS_NOT_FOUND' }
        default      { '' }
    }

    [uint32] $DosError =
        [WnfLiveAuditNative]::RtlNtStatusToDosError($Status)

    $DosMessage = ''

    try {
        if ($DosError -ne 0) {
            $DosMessage =
                (New-Object `
                    -TypeName ComponentModel.Win32Exception `
                    -ArgumentList ([int] $DosError)
                ).Message
        }
    }
    catch {
        $DosMessage = ''
    }

    $Parts = New-Object 'System.Collections.Generic.List[string]'
    [void] $Parts.Add($Hex)

    if ($KnownName) {
        [void] $Parts.Add($KnownName)
    }

    if ($DosError -ne 0) {
        [void] $Parts.Add("Win32=$DosError")
    }

    if ($DosMessage) {
        [void] $Parts.Add($DosMessage)
    }

    $Text = $Parts -join ' | '
    $script:NtStatusCache[$Hex] = $Text

    return $Text
}


function Get-Sha256Hex {
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes
    )

    $Hasher = [Security.Cryptography.SHA256]::Create()

    try {
        return (
            [BitConverter]::ToString(
                $Hasher.ComputeHash($Bytes)
            ).Replace('-', '')
        )
    }
    finally {
        $Hasher.Dispose()
    }
}


function Test-ByteArrayEqual {
    param(
        [Parameter(Mandatory)]
        [byte[]] $First,

        [Parameter(Mandatory)]
        [byte[]] $Second
    )

    if ($First.Length -ne $Second.Length) {
        return $false
    }

    for ($Index = 0; $Index -lt $First.Length; $Index++) {
        if ($First[$Index] -ne $Second[$Index]) {
            return $false
        }
    }

    return $true
}


function Test-WnfToolkitFamilyValue {
    param(
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey] $RegistryKey,

        [Parameter(Mandatory)]
        [string] $ValueName
    )

    if ($ValueName -notmatch '^[0-9A-Fa-f]{16}$') {
        return [pscustomobject]@{
            Match    = $false
            Reason   = 'Value name is not 16 hexadecimal characters'
            Kind     = $null
            Data     = $null
            Length   = $null
            Metadata = $null
            Hash     = ''
        }
    }

    try {
        $Kind = $RegistryKey.GetValueKind($ValueName)
        $Data = $RegistryKey.GetValue(
            $ValueName,
            $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        )
    }
    catch {
        return [pscustomobject]@{
            Match    = $false
            Reason   = "Value was not found or could not be read: $($_.Exception.Message)"
            Kind     = $null
            Data     = $null
            Length   = $null
            Metadata = $null
            Hash     = ''
        }
    }

    if (
        $Kind -ne [Microsoft.Win32.RegistryValueKind]::Binary -or
        $Data -isnot [byte[]]
    ) {
        return [pscustomobject]@{
            Match    = $false
            Reason   = "Registry type is $Kind rather than REG_BINARY"
            Kind     = $Kind
            Data     = $null
            Length   = $null
            Metadata = $null
            Hash     = ''
        }
    }

    [byte[]] $Data = $Data

    [uint64] $Encoded = [Convert]::ToUInt64($ValueName, 16)
    [uint64] $Decoded = $Encoded -bxor $WnfXorMask
    [uint64] $Metadata = $Decoded -band [uint64]0x7FF
    $Hash = Get-Sha256Hex -Bytes $Data

    $Reasons = New-Object 'System.Collections.Generic.List[string]'

    if ($Data.Length -ne $TargetLength) {
        [void] $Reasons.Add(
            "Data length is $($Data.Length), expected $TargetLength"
        )
    }

    if ($Metadata -ne $TargetMetadata) {
        [void] $Reasons.Add(
            ('Metadata is 0x{0:X3}, expected 0x{1:X3}' -f
                $Metadata,
                $TargetMetadata)
        )
    }

    if ($Hash -ne $TargetPayloadHash) {
        [void] $Reasons.Add('Complete payload hash differs from target')
    }

    return [pscustomobject]@{
        Match    = ($Reasons.Count -eq 0)
        Reason   = $Reasons -join '; '
        Kind     = $Kind
        Data     = $Data
        Length   = $Data.Length
        Metadata = $Metadata
        Hash     = $Hash
    }
}


function Find-WnfToolkitFamilyReference {
    param(
        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryKey] $RegistryKey
    )

    $Handle = $RegistryKey.Handle.DangerousGetHandle()
    $InitialValueCount = $RegistryKey.ValueCount

    for ([uint32] $EnumerationIndex = 0; ; $EnumerationIndex++) {
        if (
            $EnumerationIndex -eq 0 -or
            ($EnumerationIndex % $ProgressInterval) -eq 0
        ) {
            $PercentComplete = 0

            if ($InitialValueCount -gt 0) {
                $PercentComplete = [Math]::Min(
                    100,
                    [Math]::Floor(
                        ($EnumerationIndex / $InitialValueCount) * 100
                    )
                )
            }

            Write-Progress `
                -Activity 'Locating exact WNF reference-family value' `
                -Status "$EnumerationIndex registry values examined" `
                -PercentComplete $PercentComplete
        }

        $NameCapacity = 16384
        $NameBuffer = New-Object Text.StringBuilder($NameCapacity)
        [uint32] $NameLength = $NameCapacity
        [uint32] $ValueType = 0
        [uint32] $DataLength = 0

        $EnumResult =
            [WnfLiveAuditNative]::RegEnumValue(
                $Handle,
                $EnumerationIndex,
                $NameBuffer,
                [ref] $NameLength,
                [IntPtr]::Zero,
                [ref] $ValueType,
                $null,
                [ref] $DataLength
            )

        if (
            $EnumResult -eq
            [WnfLiveAuditNative]::ERROR_NO_MORE_ITEMS
        ) {
            break
        }

        if (
            $EnumResult -ne [WnfLiveAuditNative]::ERROR_SUCCESS -and
            $EnumResult -ne [WnfLiveAuditNative]::ERROR_MORE_DATA
        ) {
            throw (
                "RegEnumValue failed at index $EnumerationIndex " +
                "with Win32 error $EnumResult while locating the reference."
            )
        }

        $ValueName = $NameBuffer.ToString()

        if (
            $ValueName -notmatch '^[0-9A-Fa-f]{16}$' -or
            $ValueType -ne 3 -or
            $DataLength -ne $TargetLength
        ) {
            continue
        }

        try {
            [uint64] $Encoded = [Convert]::ToUInt64($ValueName, 16)
            [uint64] $Decoded = $Encoded -bxor $WnfXorMask
            [uint64] $Metadata = $Decoded -band [uint64]0x7FF

            if ($Metadata -ne $TargetMetadata) {
                continue
            }
        }
        catch {
            continue
        }

        $Validation =
            Test-WnfToolkitFamilyValue `
                -RegistryKey $RegistryKey `
                -ValueName $ValueName

        if ($Validation.Match) {
            Write-Progress `
                -Activity 'Locating exact WNF reference-family value' `
                -Completed

            return [pscustomobject]@{
                ValueName  = $ValueName
                Data       = $Validation.Data
                Length     = $Validation.Length
                Metadata   = $Validation.Metadata
                Hash       = $Validation.Hash
            }
        }
    }

    Write-Progress `
        -Activity 'Locating exact WNF reference-family value' `
        -Completed

    return $null
}


function ConvertTo-WnfStateName {
    param(
        [Parameter(Mandatory)]
        [string] $ValueName
    )

    [uint64] $Encoded =
        [Convert]::ToUInt64(
            $ValueName,
            16
        )

    # Convert the 64-bit encoded WNF state name into its
    # low and high 32-bit components without signed-literal issues
    # in Windows PowerShell 5.1.
    [byte[]] $EncodedBytes =
        [BitConverter]::GetBytes($Encoded)

    $StateName =
        New-Object WNF_STATE_NAME_AUDIT

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


function Get-WnfNameInformation {
    param(
        [Parameter(Mandatory)]
        [WNF_STATE_NAME_AUDIT] $StateName,

        [Parameter(Mandatory)]
        [ValidateRange(0, 2)]
        [int] $InformationClass
    )

    [uint32] $Value = 0
    $LocalStateName = $StateName

    [uint32] $Status =
        [WnfLiveAuditNative]::NtQueryWnfStateNameInformation(
            [ref] $LocalStateName,
            $InformationClass,
            [IntPtr]::Zero,
            [ref] $Value,
            4
        )

    $LogicalValue = $null

    if (Test-NtSuccess -Status $Status) {
        $LogicalValue = [bool] ($Value -ne 0)
    }

    return [pscustomobject]@{
        Status       = $Status
        StatusText   = Get-NtStatusText -Status $Status
        LogicalValue = $LogicalValue
        RawValue     = $Value
    }
}


function Get-WnfStateDataInformation {
    param(
        [Parameter(Mandatory)]
        [WNF_STATE_NAME_AUDIT] $StateName,

        [Parameter(Mandatory)]
        [int] $MaximumBytes
    )

    $LocalStateName = $StateName
    [uint32] $ChangeStamp = 0
    [uint32] $RequiredSize = 0

    [uint32] $ProbeStatus =
        [WnfLiveAuditNative]::NtQueryWnfStateData(
            [ref] $LocalStateName,
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            [ref] $ChangeStamp,
            [IntPtr]::Zero,
            [ref] $RequiredSize
        )

    [uint32] $ReadStatus = $ProbeStatus
    [uint32] $ReadSize = 0
    $DataHash = ''
    $DataReadAttempted = $false
    $DataReadSkippedReason = ''

    if ($RequiredSize -gt 0) {
        if ($RequiredSize -gt [uint32] $MaximumBytes) {
            $DataReadSkippedReason =
                "Required size $RequiredSize exceeds MaxStateDataBytes $MaximumBytes"
        }
        else {
            $Capacity = [uint32] $RequiredSize

            for ($Attempt = 1; $Attempt -le 2; $Attempt++) {
                $DataReadAttempted = $true
                $Buffer = [Runtime.InteropServices.Marshal]::AllocHGlobal(
                    [int] $Capacity
                )

                try {
                    $LocalStateName = $StateName
                    [uint32] $CurrentStamp = 0
                    [uint32] $CurrentSize = $Capacity

                    $ReadStatus =
                        [WnfLiveAuditNative]::NtQueryWnfStateData(
                            [ref] $LocalStateName,
                            [IntPtr]::Zero,
                            [IntPtr]::Zero,
                            [ref] $CurrentStamp,
                            $Buffer,
                            [ref] $CurrentSize
                        )

                    $ChangeStamp = $CurrentStamp

                    if (
                        (
                            $ReadStatus -eq $StatusBufferTooSmall -or
                            $ReadStatus -eq $StatusBufferOverflow
                        ) -and
                        $CurrentSize -gt $Capacity -and
                        $Attempt -lt 2 -and
                        $CurrentSize -le [uint32] $MaximumBytes
                    ) {
                        $Capacity = $CurrentSize
                        continue
                    }

                    if (Test-NtSuccess -Status $ReadStatus) {
                        $ReadSize = $CurrentSize

                        if ($ReadSize -gt 0) {
                            [byte[]] $Bytes =
                                New-Object byte[] ([int] $ReadSize)

                            [Runtime.InteropServices.Marshal]::Copy(
                                $Buffer,
                                $Bytes,
                                0,
                                [int] $ReadSize
                            )

                            $DataHash = Get-Sha256Hex -Bytes $Bytes
                        }
                    }

                    break
                }
                finally {
                    [Runtime.InteropServices.Marshal]::FreeHGlobal($Buffer)
                }
            }
        }
    }

    return [pscustomobject]@{
        ProbeStatus           = $ProbeStatus
        ProbeStatusText       = Get-NtStatusText -Status $ProbeStatus
        ReadStatus            = $ReadStatus
        ReadStatusText        = Get-NtStatusText -Status $ReadStatus
        ChangeStamp           = $ChangeStamp
        RequiredSize          = $RequiredSize
        ReadSize              = $ReadSize
        DataHash              = $DataHash
        DataReadAttempted     = $DataReadAttempted
        DataReadSkippedReason = $DataReadSkippedReason
    }
}


function Get-SampleSelection {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IList] $Candidates,

        [Parameter(Mandatory)]
        [int] $RequestedCount
    )

    $CandidateCount = $Candidates.Count

    if ($RequestedCount -ge $CandidateCount) {
        return @(
            for ($Position = 0; $Position -lt $CandidateCount; $Position++) {
                [pscustomobject]@{
                    CandidatePosition = $Position
                    SampleRegion      = 'All'
                    EnumerationIndex  = $Candidates[$Position].EnumerationIndex
                    ValueName         = $Candidates[$Position].ValueName
                }
            }
        )
    }

    $StartCount = [int] [Math]::Ceiling($RequestedCount / 3.0)
    $MiddleCount = [int] [Math]::Floor($RequestedCount / 3.0)
    $EndCount = $RequestedCount - $StartCount - $MiddleCount

    $RegionByPosition = @{}

    function Add-SamplePosition {
        param(
            [int] $Position,
            [string] $Region
        )

        if ($Position -lt 0 -or $Position -ge $CandidateCount) {
            return
        }

        if ($RegionByPosition.ContainsKey($Position)) {
            $ExistingRegions =
                $RegionByPosition[$Position].Split('+')

            if ($ExistingRegions -notcontains $Region) {
                $RegionByPosition[$Position] += "+$Region"
            }
        }
        else {
            $RegionByPosition[$Position] = $Region
        }
    }

    for ($Offset = 0; $Offset -lt $StartCount; $Offset++) {
        Add-SamplePosition -Position $Offset -Region 'Beginning'
    }

    $MiddleStart =
        [int] [Math]::Floor(($CandidateCount - $MiddleCount) / 2.0)

    for ($Offset = 0; $Offset -lt $MiddleCount; $Offset++) {
        Add-SamplePosition `
            -Position ($MiddleStart + $Offset) `
            -Region 'Middle'
    }

    $EndStart = $CandidateCount - $EndCount

    for ($Offset = 0; $Offset -lt $EndCount; $Offset++) {
        Add-SamplePosition `
            -Position ($EndStart + $Offset) `
            -Region 'End'
    }

    return @(
        $RegionByPosition.Keys |
            Sort-Object { [int] $_ } |
            ForEach-Object {
                $Position = [int] $_

                [pscustomobject]@{
                    CandidatePosition = $Position
                    SampleRegion      = $RegionByPosition[$Position]
                    EnumerationIndex  = $Candidates[$Position].EnumerationIndex
                    ValueName         = $Candidates[$Position].ValueName
                }
            }
    )
}


# ============================================================
# Preliminary checks and paths
# ============================================================

if (-not [Environment]::Is64BitProcess) {
    throw 'Run this script from 64-bit Windows PowerShell.'
}

if (
    $ReferenceValueName -and
    $ReferenceValueName -notmatch '^[0-9A-Fa-f]{16}$'
) {
    throw (
        'ReferenceValueName must be a 16-character hexadecimal ' +
        'WNF state name.'
    )
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
        Write-Warning (
            'The script is not running elevated. Read-only queries may ' +
            'return access-denied results.'
        )
    }
}
catch {
    Write-Warning 'Could not determine elevation status.'
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$SafeLabel = $AuditLabel -replace '[^A-Za-z0-9._-]', '_'
$Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

$AuditCsv = Join-Path $OutputDirectory (
    "Wnf-SystemScope-LiveAudit-$SafeLabel-$Timestamp.csv"
)

$SummaryCsv = Join-Path $OutputDirectory (
    "Wnf-SystemScope-LiveAudit-$SafeLabel-$Timestamp-Summary.csv"
)


# ============================================================
# Open registry and establish the reference family
# ============================================================

$BaseKey = $null
$Key = $null

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

    $ReferenceSelectionSource = ''
    $Reference = $null

    if ($ReferenceValueName) {
        $Validation =
            Test-WnfToolkitFamilyValue `
                -RegistryKey $Key `
                -ValueName $ReferenceValueName

        if (-not $Validation.Match) {
            throw (
                "ReferenceValueName '$ReferenceValueName' does not match " +
                "the toolkit's exact target family: $($Validation.Reason)"
            )
        }

        $Reference = [pscustomobject]@{
            ValueName = $ReferenceValueName
            Data      = $Validation.Data
            Length    = $Validation.Length
            Metadata  = $Validation.Metadata
            Hash      = $Validation.Hash
        }

        $ReferenceSelectionSource = 'Explicit -ReferenceValueName'
    }
    else {
        Write-Host
        Write-Host (
            'No ReferenceValueName supplied; locating an exact member of ' +
            "the toolkit's confirmed target family..."
        )

        $Reference = Find-WnfToolkitFamilyReference -RegistryKey $Key

        if ($null -eq $Reference) {
            throw (
                'No exact toolkit target-family value was found. Expected ' +
                'a 16-character hexadecimal REG_BINARY value with decoded ' +
                ('metadata 0x{0:X3}, length {1} bytes, and SHA-256 {2}.' -f
                    $TargetMetadata,
                    $TargetLength,
                    $TargetPayloadHash)
            )
        }

        $ReferenceValueName = $Reference.ValueName
        $ReferenceSelectionSource =
            'Auto-discovered exact toolkit family member'
    }

    [byte[]] $ReferenceData = $Reference.Data
    [uint64] $ReferenceMetadata = $Reference.Metadata
    $ReferenceHash = [string] $Reference.Hash

    Write-Host
    Write-Host "Registry key:        $RegistryDisplayPath"
    Write-Host "Reference source:    $ReferenceSelectionSource"
    Write-Host "Reference value:     $ReferenceValueName"
    Write-Host (
        'Reference metadata:  0x{0:X3}' -f $ReferenceMetadata
    )
    Write-Host "Reference length:    $($ReferenceData.Length) bytes"
    Write-Host "Reference SHA-256:   $ReferenceHash"
    Write-Host


    # ========================================================
    # Select names to audit
    # ========================================================

    $SelectionSource = ''
    $FamilyCandidateCount = $null
    $SelectedItems = @()

    if ($ReuseNamesFromCsv) {
        if (-not (Test-Path -LiteralPath $ReuseNamesFromCsv -PathType Leaf)) {
            throw "Reuse CSV was not found: $ReuseNamesFromCsv"
        }

        $PreviousRows = @(Import-Csv -LiteralPath $ReuseNamesFromCsv)

        $SelectedItems = @(
            $PreviousRows |
                Where-Object {
                    $_.ValueName -match '^[0-9A-Fa-f]{16}$'
                } |
                Group-Object ValueName |
                ForEach-Object {
                    $Row = $_.Group[0]

                    [pscustomobject]@{
                        CandidatePosition =
                            if ($Row.CandidatePosition -ne '') {
                                [int64] $Row.CandidatePosition
                            }
                            else {
                                -1
                            }

                        SampleRegion =
                            if ($Row.SampleRegion) {
                                [string] $Row.SampleRegion
                            }
                            else {
                                'Reused'
                            }

                        EnumerationIndex =
                            if ($Row.EnumerationIndex -ne '') {
                                [int64] $Row.EnumerationIndex
                            }
                            else {
                                -1
                            }

                        ValueName = [string] $Row.ValueName
                    }
                }
        )

        if ($SelectedItems.Count -eq 0) {
            throw 'The reuse CSV contained no valid ValueName entries.'
        }

        $SelectionSource = "Reused names from $ReuseNamesFromCsv"
        $FamilyCandidateCount = $SelectedItems.Count
    }
    else {
        Write-Host 'Enumerating matching 72-byte WNF-family candidates...'

        $Handle = $Key.Handle.DangerousGetHandle()
        $InitialValueCount = $Key.ValueCount

        $Candidates =
            New-Object 'System.Collections.Generic.List[object]'

        for ([uint32] $EnumerationIndex = 0; ; $EnumerationIndex++) {
            if (
                $EnumerationIndex -eq 0 -or
                ($EnumerationIndex % $ProgressInterval) -eq 0
            ) {
                $PercentComplete = 0

                if ($InitialValueCount -gt 0) {
                    $PercentComplete = [Math]::Min(
                        100,
                        [Math]::Floor(
                            ($EnumerationIndex / $InitialValueCount) * 100
                        )
                    )
                }

                Write-Progress `
                    -Activity 'Enumerating Notifications registry values' `
                    -Status (
                        "$EnumerationIndex examined; " +
                        "$($Candidates.Count) family candidates"
                    ) `
                    -PercentComplete $PercentComplete
            }

            $NameCapacity = 16384
            $NameBuffer =
                New-Object Text.StringBuilder($NameCapacity)

            [uint32] $NameLength = $NameCapacity
            [uint32] $ValueType = 0
            [uint32] $DataLength = 0

            $EnumResult =
                [WnfLiveAuditNative]::RegEnumValue(
                    $Handle,
                    $EnumerationIndex,
                    $NameBuffer,
                    [ref] $NameLength,
                    [IntPtr]::Zero,
                    [ref] $ValueType,
                    $null,
                    [ref] $DataLength
                )

            if (
                $EnumResult -eq
                [WnfLiveAuditNative]::ERROR_NO_MORE_ITEMS
            ) {
                break
            }

            if (
                $EnumResult -ne
                    [WnfLiveAuditNative]::ERROR_SUCCESS -and
                $EnumResult -ne
                    [WnfLiveAuditNative]::ERROR_MORE_DATA
            ) {
                throw (
                    "RegEnumValue failed at index $EnumerationIndex " +
                    "with Win32 error $EnumResult."
                )
            }

            $ValueName = $NameBuffer.ToString()

            if (
                $ValueName -notmatch '^[0-9A-Fa-f]{16}$' -or
                $ValueType -ne 3 -or
                $DataLength -ne $ReferenceData.Length
            ) {
                continue
            }

            try {
                [uint64] $Encoded =
                    [Convert]::ToUInt64($ValueName, 16)

                [uint64] $Decoded =
                    $Encoded -bxor $WnfXorMask

                [uint64] $Metadata =
                    $Decoded -band [uint64]0x7FF

                if ($Metadata -ne $ReferenceMetadata) {
                    continue
                }
            }
            catch {
                continue
            }

            [void] $Candidates.Add(
                [pscustomobject]@{
                    EnumerationIndex = [int64] $EnumerationIndex
                    ValueName        = $ValueName
                }
            )
        }

        Write-Progress `
            -Activity 'Enumerating Notifications registry values' `
            -Completed

        $FamilyCandidateCount = $Candidates.Count

        if ($FamilyCandidateCount -eq 0) {
            throw 'No matching family candidates were found.'
        }

        if ($FullScan) {
            $SelectedItems = @(
                for (
                    $Position = 0;
                    $Position -lt $Candidates.Count;
                    $Position++
                ) {
                    [pscustomobject]@{
                        CandidatePosition = $Position
                        SampleRegion      = 'FullScan'
                        EnumerationIndex  =
                            $Candidates[$Position].EnumerationIndex
                        ValueName         =
                            $Candidates[$Position].ValueName
                    }
                }
            )

            $SelectionSource = 'Full family scan'
        }
        else {
            $SelectedItems = @(
                Get-SampleSelection `
                    -Candidates $Candidates `
                    -RequestedCount $SampleCount
            )

            $SelectionSource =
                'Beginning/middle/end sample'
        }
    }

    Write-Host "Selection source:    $SelectionSource"
    Write-Host "Family candidates:   $FamilyCandidateCount"
    Write-Host "Values selected:     $($SelectedItems.Count)"
    Write-Host "Audit label:         $AuditLabel"
    Write-Host


    # ========================================================
    # Audit selected names and stream results to CSV
    # ========================================================

    $Batch = New-Object 'System.Collections.Generic.List[object]'
    $script:WnfAuditCsvInitialized = $false

    $Counters = @{
        TotalSelected            = $SelectedItems.Count
        RegistryReadSuccess      = 0
        RegistryReadFailure      = 0
        ExactFamilyMatch         = 0
        FilterMismatch           = 0
        NativeQueryFailure       = 0
        StrongLiveEvidence       = 0
        ExistsNoStrongEvidence   = 0
        NotReportedExisting      = 0
        SubscribersPresent       = 0
        StateDataPresent         = 0
        NonZeroChangeStamp       = 0
        NotQuiescent             = 0
    }

    function Flush-AuditBatch {
        if ($Batch.Count -eq 0) {
            return
        }

        if (-not $script:WnfAuditCsvInitialized) {
            $Batch |
                Export-Csv -LiteralPath $AuditCsv -NoTypeInformation -Encoding UTF8

            $script:WnfAuditCsvInitialized = $true
        }
        else {
            $Batch |
                Export-Csv -LiteralPath $AuditCsv -NoTypeInformation -Encoding UTF8 `
                    -Append
        }

        $Batch.Clear()
    }

    $Processed = 0

    foreach ($Selected in $SelectedItems) {
        $Processed++

        if (
            $Processed -eq 1 -or
            ($Processed % 100) -eq 0
        ) {
            $PercentComplete = [Math]::Floor(
                ($Processed / $SelectedItems.Count) * 100
            )

            Write-Progress `
                -Activity 'Auditing live WNF state names' `
                -Status (
                    "$Processed of $($SelectedItems.Count); " +
                    "$($Counters.StrongLiveEvidence) with strong evidence"
                ) `
                -PercentComplete $PercentComplete
        }

        $ValueName = [string] $Selected.ValueName
        $RegistryReadStatus = 'Success'
        $RegistryType = ''
        $RegistryDataLength = $null
        $RegistryPayloadHash = ''
        $MetadataHex = ''
        $PayloadMatchesReference = $false
        $FilterMatch = $false
        $FilterFailureReason = ''

        $ExistsStatus = ''
        $StateExists = $null
        $SubscribersStatus = ''
        $SubscribersPresent = $null
        $QuiescentStatus = ''
        $IsQuiescent = $null
        $DataProbeStatus = ''
        $DataReadStatus = ''
        $ChangeStamp = $null
        $StateDataRequiredSize = $null
        $StateDataReadSize = $null
        $StateDataHash = ''
        $DataReadAttempted = $false
        $DataReadSkippedReason = ''
        $StrongEvidence = $false
        $EvidenceSummary = ''
        $Classification = ''

        try {
            $LiveKind = $Key.GetValueKind($ValueName)
            $RegistryType = [string] $LiveKind

            $LiveData = $Key.GetValue(
                $ValueName,
                $null,
                [Microsoft.Win32.RegistryValueOptions]::
                    DoNotExpandEnvironmentNames
            )

            if ($LiveData -isnot [byte[]]) {
                throw 'Live registry value did not return a byte array.'
            }

            [byte[]] $LiveData = $LiveData
            $RegistryDataLength = $LiveData.Length
            $RegistryPayloadHash = Get-Sha256Hex -Bytes $LiveData
            $Counters.RegistryReadSuccess++

            [uint64] $Encoded = [Convert]::ToUInt64($ValueName, 16)
            [uint64] $Decoded = $Encoded -bxor $WnfXorMask
            [uint64] $Metadata = $Decoded -band [uint64]0x7FF
            $MetadataHex = '0x{0:X3}' -f $Metadata

            $PayloadMatchesReference =
                Test-ByteArrayEqual `
                    -First $LiveData `
                    -Second $ReferenceData

            $FilterReasons =
                New-Object 'System.Collections.Generic.List[string]'

            if (
                $LiveKind -ne
                [Microsoft.Win32.RegistryValueKind]::Binary
            ) {
                [void] $FilterReasons.Add(
                    "Registry type is $LiveKind"
                )
            }

            if ($LiveData.Length -ne $ReferenceData.Length) {
                [void] $FilterReasons.Add(
                    "Length is $($LiveData.Length), expected " +
                    $ReferenceData.Length
                )
            }

            if ($Metadata -ne $ReferenceMetadata) {
                [void] $FilterReasons.Add(
                    "Metadata is $MetadataHex, expected " +
                    ('0x{0:X3}' -f $ReferenceMetadata)
                )
            }

            if (-not $PayloadMatchesReference) {
                [void] $FilterReasons.Add(
                    'Complete registry payload differs from reference'
                )
            }

            if ($FilterReasons.Count -eq 0) {
                $FilterMatch = $true
                $Counters.ExactFamilyMatch++

                $StateName = ConvertTo-WnfStateName -ValueName $ValueName

                $ExistResult =
                    Get-WnfNameInformation `
                        -StateName $StateName `
                        -InformationClass 0

                $SubscriberResult =
                    Get-WnfNameInformation `
                        -StateName $StateName `
                        -InformationClass 1

                $QuiescentResult =
                    Get-WnfNameInformation `
                        -StateName $StateName `
                        -InformationClass 2

                $DataResult =
                    Get-WnfStateDataInformation `
                        -StateName $StateName `
                        -MaximumBytes $MaxStateDataBytes

                $ExistsStatus = $ExistResult.StatusText
                $StateExists = $ExistResult.LogicalValue
                $SubscribersStatus = $SubscriberResult.StatusText
                $SubscribersPresent =
                    $SubscriberResult.LogicalValue
                $QuiescentStatus = $QuiescentResult.StatusText
                $IsQuiescent = $QuiescentResult.LogicalValue
                $DataProbeStatus = $DataResult.ProbeStatusText
                $DataReadStatus = $DataResult.ReadStatusText
                $ChangeStamp = $DataResult.ChangeStamp
                $StateDataRequiredSize = $DataResult.RequiredSize
                $StateDataReadSize = $DataResult.ReadSize
                $StateDataHash = $DataResult.DataHash
                $DataReadAttempted = $DataResult.DataReadAttempted
                $DataReadSkippedReason =
                    $DataResult.DataReadSkippedReason

                $Evidence =
                    New-Object 'System.Collections.Generic.List[string]'

                if ($SubscribersPresent -eq $true) {
                    [void] $Evidence.Add('SubscribersPresent')
                    $Counters.SubscribersPresent++
                }

                if ($StateDataReadSize -gt 0) {
                    [void] $Evidence.Add('StateDataPresent')
                    $Counters.StateDataPresent++
                }

                if ($ChangeStamp -gt 0) {
                    [void] $Evidence.Add('NonZeroChangeStamp')
                    $Counters.NonZeroChangeStamp++
                }

                if ($IsQuiescent -eq $false) {
                    [void] $Evidence.Add('NotQuiescent')
                    $Counters.NotQuiescent++
                }

                $StrongEvidence =
                    (
                        $SubscribersPresent -eq $true -or
                        $StateDataReadSize -gt 0 -or
                        $ChangeStamp -gt 0
                    )

                $EvidenceSummary = $Evidence -join '; '

                $AnyQueryFailed =
                    -not (Test-NtSuccess -Status $ExistResult.Status) -or
                    -not (Test-NtSuccess -Status $SubscriberResult.Status) -or
                    -not (Test-NtSuccess -Status $QuiescentResult.Status)

                if ($AnyQueryFailed) {
                    $Classification = 'NativeQueryFailure'
                    $Counters.NativeQueryFailure++
                }
                elseif ($StrongEvidence) {
                    $Classification = 'StrongLiveEvidence'
                    $Counters.StrongLiveEvidence++
                }
                elseif ($StateExists -eq $true) {
                    $Classification = 'ExistsNoStrongEvidence'
                    $Counters.ExistsNoStrongEvidence++
                }
                else {
                    $Classification = 'NotReportedExisting'
                    $Counters.NotReportedExisting++
                }
            }
            else {
                $FilterFailureReason = $FilterReasons -join '; '
                $Classification = 'FilterMismatch'
                $Counters.FilterMismatch++
            }
        }
        catch {
            $RegistryReadStatus =
                "ERROR: $($_.Exception.Message)"

            $Classification = 'RegistryReadFailure'
            $Counters.RegistryReadFailure++
        }

        [void] $Batch.Add(
            [pscustomobject]@{
                CheckedAt                   = Get-Date
                AuditLabel                  = $AuditLabel
                SelectionSource             = $SelectionSource
                CandidatePosition           =
                    $Selected.CandidatePosition
                SampleRegion                = $Selected.SampleRegion
                EnumerationIndex            =
                    $Selected.EnumerationIndex
                ValueName                   = $ValueName
                DecodedMetadata             = $MetadataHex
                RegistryReadStatus          = $RegistryReadStatus
                RegistryType                = $RegistryType
                RegistryDataLength          = $RegistryDataLength
                RegistryPayloadHash         = $RegistryPayloadHash
                ReferencePayloadHash        = $ReferenceHash
                PayloadMatchesReference     =
                    $PayloadMatchesReference
                ExactFamilyFilterMatch      = $FilterMatch
                FilterFailureReason         = $FilterFailureReason
                StateNameExistStatus        = $ExistsStatus
                StateNameExists             = $StateExists
                SubscribersQueryStatus      = $SubscribersStatus
                SubscribersPresent          =
                    $SubscribersPresent
                QuiescentQueryStatus        = $QuiescentStatus
                IsQuiescent                 = $IsQuiescent
                StateDataProbeStatus        = $DataProbeStatus
                StateDataReadStatus         = $DataReadStatus
                ChangeStamp                 = $ChangeStamp
                StateDataRequiredSize       =
                    $StateDataRequiredSize
                StateDataReadSize           = $StateDataReadSize
                StateDataHash               = $StateDataHash
                StateDataReadAttempted      = $DataReadAttempted
                StateDataReadSkippedReason  =
                    $DataReadSkippedReason
                StrongLiveEvidence          = $StrongEvidence
                EvidenceSummary             = $EvidenceSummary
                Classification              = $Classification
            }
        )

        if ($Batch.Count -ge $CsvBatchSize) {
            Flush-AuditBatch
        }
    }

    Flush-AuditBatch

    Write-Progress `
        -Activity 'Auditing live WNF state names' `
        -Completed


    # ========================================================
    # Summary
    # ========================================================

    $Summary = [pscustomobject]@{
        CheckedAt                  = Get-Date
        AuditLabel                 = $AuditLabel
        RegistryPath               = $RegistryDisplayPath
        SelectionSource            = $SelectionSource
        ReuseNamesFromCsv          = $ReuseNamesFromCsv
        ReferenceSelectionSource    = $ReferenceSelectionSource
        ReferenceValueName         = $ReferenceValueName
        ReferenceMetadata          =
            ('0x{0:X3}' -f $ReferenceMetadata)
        ReferenceLength            = $ReferenceData.Length
        ReferencePayloadHash       = $ReferenceHash
        FamilyCandidateCount       = $FamilyCandidateCount
        SelectedCount              = $Counters.TotalSelected
        RegistryReadSuccess        = $Counters.RegistryReadSuccess
        RegistryReadFailure        = $Counters.RegistryReadFailure
        ExactFamilyMatch           = $Counters.ExactFamilyMatch
        FilterMismatch             = $Counters.FilterMismatch
        NativeQueryFailure         = $Counters.NativeQueryFailure
        StrongLiveEvidence         = $Counters.StrongLiveEvidence
        ExistsNoStrongEvidence     =
            $Counters.ExistsNoStrongEvidence
        NotReportedExisting        = $Counters.NotReportedExisting
        SubscribersPresent         = $Counters.SubscribersPresent
        StateDataPresent           = $Counters.StateDataPresent
        NonZeroChangeStamp         = $Counters.NonZeroChangeStamp
        NotQuiescent               = $Counters.NotQuiescent
        OutputCsv                  = $AuditCsv
    }

    $Summary |
        Export-Csv -LiteralPath $SummaryCsv -NoTypeInformation -Encoding UTF8

    Write-Host
    Write-Host 'Live WNF audit completed.'
    Write-Host
    Write-Host "Selected:                 $($Counters.TotalSelected)"
    Write-Host "Exact family matches:     $($Counters.ExactFamilyMatch)"
    Write-Host "Registry read failures:   $($Counters.RegistryReadFailure)"
    Write-Host "Native query failures:    $($Counters.NativeQueryFailure)"
    Write-Host "Strong live evidence:     $($Counters.StrongLiveEvidence)"
    Write-Host "Exists, no strong evidence: $($Counters.ExistsNoStrongEvidence)"
    Write-Host "Not reported existing:    $($Counters.NotReportedExisting)"
    Write-Host "Subscribers present:      $($Counters.SubscribersPresent)"
    Write-Host "State data present:       $($Counters.StateDataPresent)"
    Write-Host "Nonzero change stamp:     $($Counters.NonZeroChangeStamp)"
    Write-Host "Not quiescent:            $($Counters.NotQuiescent)"
    Write-Host
    Write-Host "Audit CSV:   $AuditCsv"
    Write-Host "Summary CSV: $SummaryCsv"
}
finally {
    if ($null -ne $Key) {
        $Key.Dispose()
    }

    if ($null -ne $BaseKey) {
        $BaseKey.Dispose()
    }
}
