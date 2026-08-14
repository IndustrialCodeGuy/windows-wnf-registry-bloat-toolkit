# Copyright (C) 2026 Dan Michel
# SPDX-License-Identifier: GPL-3.0-only
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# See the LICENSE file in the project root for the full license text.

<#
.SYNOPSIS
    Performs a read-only structural inventory of the root values under the
    Windows VolatileNotifications registry key.

.DESCRIPTION
    Intended for comparison of Windows Server systems where WNF-related
    registry growth is under investigation.

    Enumerates root-level values under:

        HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\VolatileNotifications

    For 16-character hexadecimal value names, the script decodes the WNF state
    name using the standard WNF XOR mask and records the decoded metadata and
    unique-ID range.

    Because no investigation-specific VolatileNotifications family has yet
    been established, this script does not assume that the structures observed
    under the persistent Notifications key also apply here. Instead, it groups
    values by registry type, data length, and decoded WNF metadata, and groups
    readable REG_BINARY payloads by SHA-256 hash.

    The script is read-only. It does not create, update, or delete registry
    keys, values, or WNF state names.

.PARAMETER ServerLabel
    Friendly label stored in the output. Defaults to the local computer name.

.PARAMETER OutputDirectory
    Directory used for CSV output.

.PARAMETER ProgressInterval
    Number of enumerated values between progress updates.

.PARAMETER MaximumHashBytes
    Maximum REG_BINARY payload size that will be copied and SHA-256 hashed.
    Larger values are still structurally counted but are not hashed.

.NOTES
    Run from elevated 64-bit Windows PowerShell 5.1 for the most consistent
    comparison with the other toolkit inventory scripts.

    A missing VolatileNotifications key is treated as a valid inventory result:
    KeyPresent will be False and the summary will report zero values.
#>

[CmdletBinding()]
param(
    [string] $ServerLabel = $env:COMPUTERNAME,

    [string] $OutputDirectory = (
        Join-Path $env:ProgramData (
            'WindowsWnfRegistryBloatToolkit\VolatileStructuralInventory'
        )
    ),

    [ValidateRange(100, 1000000)]
    [int] $ProgressInterval = 2500,

    [ValidateRange(0, 16777216)]
    [int] $MaximumHashBytes = 4096
)

$ErrorActionPreference = 'Stop'

$RegistrySubKey =
    'SOFTWARE\Microsoft\Windows NT\CurrentVersion\VolatileNotifications'

$RegistryDisplayPath =
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\VolatileNotifications'

[uint64] $WnfXorMask =
    [uint64]::Parse(
        '41C64E6DA3BC0074',
        [Globalization.NumberStyles]::HexNumber
    )


# ============================================================
# Native registry declaration
# ============================================================

if (-not ('WnfVolatileStructuralNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class WnfVolatileStructuralNative
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
}
'@
}


# ============================================================
# Helper functions
# ============================================================

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


function Copy-ByteRange {
    param(
        [Parameter(Mandatory)]
        [byte[]] $Source,

        [Parameter(Mandatory)]
        [int] $Length
    )

    [byte[]] $Destination = New-Object byte[] $Length

    if ($Length -gt 0) {
        [Array]::Copy(
            $Source,
            0,
            $Destination,
            0,
            $Length
        )
    }

    return $Destination
}


function Get-RegistryTypeName {
    param(
        [Parameter(Mandatory)]
        [uint32] $Type
    )

    switch ($Type) {
        0  { return 'REG_NONE' }
        1  { return 'REG_SZ' }
        2  { return 'REG_EXPAND_SZ' }
        3  { return 'REG_BINARY' }
        4  { return 'REG_DWORD' }
        5  { return 'REG_DWORD_BIG_ENDIAN' }
        6  { return 'REG_LINK' }
        7  { return 'REG_MULTI_SZ' }
        8  { return 'REG_RESOURCE_LIST' }
        9  { return 'REG_FULL_RESOURCE_DESCRIPTOR' }
        10 { return 'REG_RESOURCE_REQUIREMENTS_LIST' }
        11 { return 'REG_QWORD' }
        default { return "REG_TYPE_$Type" }
    }
}


function Format-WnfMetadata {
    param(
        [Parameter(Mandatory)]
        [uint64] $Metadata
    )

    return ('0x{0:X3}' -f $Metadata)
}


# ============================================================
# Preliminary checks and output paths
# ============================================================

if (-not [Environment]::Is64BitProcess) {
    throw 'Run this script from 64-bit Windows PowerShell.'
}

New-Item `
    -ItemType Directory `
    -Path $OutputDirectory `
    -Force |
    Out-Null

$SafeLabel = $ServerLabel -replace '[^A-Za-z0-9._-]', '_'
$Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

$SummaryCsv = Join-Path $OutputDirectory (
    "Wnf-VolatileStructuralSummary-$SafeLabel-$Timestamp.csv"
)

$StructureGroupsCsv = Join-Path $OutputDirectory (
    "Wnf-VolatileStructureGroups-$SafeLabel-$Timestamp.csv"
)

$PayloadGroupsCsv = Join-Path $OutputDirectory (
    "Wnf-VolatilePayloadGroups-$SafeLabel-$Timestamp.csv"
)


# ============================================================
# Counters and collections
# ============================================================

$Counters = [ordered]@{
    TotalRootValues          = 0
    HexadecimalWnfNames      = 0
    NonHexadecimalNames      = 0
    RegBinaryValues          = 0
    PayloadsHashed           = 0
    PayloadHashSkippedLarge  = 0
    PayloadReadFailures      = 0
    EnumerationReadFailures  = 0
}

$StructureGroups = @{}
$PayloadGroups = @{}

$KeyPresent = $false
$SubKeyCount = 0
$InitialValueCount = 0


# ============================================================
# Enumerate root values
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

    if ($null -ne $Key) {
        $KeyPresent = $true
        $SubKeyCount = $Key.SubKeyCount
        $InitialValueCount = $Key.ValueCount

        $Handle = $Key.Handle.DangerousGetHandle()

        Write-Host
        Write-Host "Server:              $env:COMPUTERNAME"
        Write-Host "Label:               $ServerLabel"
        Write-Host "Registry key:        $RegistryDisplayPath"
        Write-Host "Initial value count: $InitialValueCount"
        Write-Host "Subkey count:         $SubKeyCount"
        Write-Host

        # Large enough for the small WNF payloads seen in the related
        # Notifications investigation while still bounding per-iteration
        # allocation. RegEnumValue reports the actual required length when the
        # payload is larger than this buffer.
        $BufferLength = [Math]::Max(512, $MaximumHashBytes)
        [byte[]] $DataBuffer = New-Object byte[] $BufferLength

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
                    -Activity 'Inventorying VolatileNotifications root values' `
                    -Status (
                        "$EnumerationIndex examined; " +
                        "$($Counters.HexadecimalWnfNames) hex WNF names; " +
                        "$($StructureGroups.Count) structural groups"
                    ) `
                    -PercentComplete $PercentComplete
            }

            $NameCapacity = 16384
            $NameBuffer = New-Object Text.StringBuilder($NameCapacity)

            [uint32] $NameLength = $NameCapacity
            [uint32] $ValueType = 0
            [uint32] $DataLength = $DataBuffer.Length

            $EnumResult =
                [WnfVolatileStructuralNative]::RegEnumValue(
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
                [WnfVolatileStructuralNative]::ERROR_NO_MORE_ITEMS
            ) {
                break
            }

            if (
                $EnumResult -ne
                    [WnfVolatileStructuralNative]::ERROR_SUCCESS -and
                $EnumResult -ne
                    [WnfVolatileStructuralNative]::ERROR_MORE_DATA
            ) {
                $Counters.EnumerationReadFailures++

                throw (
                    "RegEnumValue failed at index $EnumerationIndex " +
                    "with Win32 error $EnumResult."
                )
            }

            $Counters.TotalRootValues++

            $ValueName = $NameBuffer.ToString()
            $TypeName = Get-RegistryTypeName -Type $ValueType
            $IsHexWnfName = $ValueName -match '^[0-9A-Fa-f]{16}$'

            $MetadataHex = ''
            [uint64] $UniqueId = 0
            $HaveDecodedWnfName = $false

            if ($IsHexWnfName) {
                $Counters.HexadecimalWnfNames++

                try {
                    [uint64] $Encoded =
                        [Convert]::ToUInt64($ValueName, 16)

                    [uint64] $Decoded =
                        $Encoded -bxor $WnfXorMask

                    [uint64] $Metadata =
                        $Decoded -band [uint64] 0x7FF

                    $UniqueId = $Decoded -shr 11
                    $MetadataHex = Format-WnfMetadata -Metadata $Metadata
                    $HaveDecodedWnfName = $true
                }
                catch {
                    $MetadataHex = 'DecodeFailed'
                }
            }
            else {
                $Counters.NonHexadecimalNames++
                $MetadataHex = 'NonWnfName'
            }

            $StructureKey =
                "$ValueType|$DataLength|$MetadataHex"

            if (-not $StructureGroups.ContainsKey($StructureKey)) {
                $StructureGroups[$StructureKey] =
                    [pscustomobject]@{
                        RegistryTypeCode = $ValueType
                        RegistryType     = $TypeName
                        DataLength       = [int64] $DataLength
                        DecodedMetadata  = $MetadataHex
                        ValueCount       = [int64] 0
                        FirstValueName   = $ValueName
                        LastValueName    = $ValueName
                        MinimumUniqueId  = [uint64] 0
                        MaximumUniqueId  = [uint64] 0
                        HasUniqueIdRange = $false
                    }
            }

            $Structure = $StructureGroups[$StructureKey]
            $Structure.ValueCount = [int64] $Structure.ValueCount + 1
            $Structure.LastValueName = $ValueName

            if ($HaveDecodedWnfName) {
                if (-not $Structure.HasUniqueIdRange) {
                    $Structure.MinimumUniqueId = $UniqueId
                    $Structure.MaximumUniqueId = $UniqueId
                    $Structure.HasUniqueIdRange = $true
                }
                else {
                    if ($UniqueId -lt $Structure.MinimumUniqueId) {
                        $Structure.MinimumUniqueId = $UniqueId
                        $Structure.FirstValueName = $ValueName
                    }

                    if ($UniqueId -gt $Structure.MaximumUniqueId) {
                        $Structure.MaximumUniqueId = $UniqueId
                        $Structure.LastValueName = $ValueName
                    }
                }
            }

            # REG_BINARY = 3
            if ($ValueType -eq 3) {
                $Counters.RegBinaryValues++

                if ($DataLength -gt $MaximumHashBytes) {
                    $Counters.PayloadHashSkippedLarge++
                    continue
                }

                if (
                    $EnumResult -ne
                    [WnfVolatileStructuralNative]::ERROR_SUCCESS
                ) {
                    $Counters.PayloadReadFailures++
                    continue
                }

                try {
                    [byte[]] $Payload =
                        Copy-ByteRange `
                            -Source $DataBuffer `
                            -Length ([int] $DataLength)

                    $PayloadHash = Get-Sha256Hex -Bytes $Payload
                    $Counters.PayloadsHashed++

                    $PayloadKey =
                        "$DataLength|$MetadataHex|$PayloadHash"

                    if (-not $PayloadGroups.ContainsKey($PayloadKey)) {
                        $PayloadGroups[$PayloadKey] =
                            [pscustomobject]@{
                                DataLength      = [int64] $DataLength
                                DecodedMetadata = $MetadataHex
                                PayloadHash     = $PayloadHash
                                ValueCount      = [int64] 0
                                FirstValueName  = $ValueName
                                LastValueName   = $ValueName
                                MinimumUniqueId = [uint64] 0
                                MaximumUniqueId = [uint64] 0
                                HasUniqueIdRange = $false
                            }
                    }

                    $PayloadGroup = $PayloadGroups[$PayloadKey]
                    $PayloadGroup.ValueCount =
                        [int64] $PayloadGroup.ValueCount + 1

                    $PayloadGroup.LastValueName = $ValueName

                    if ($HaveDecodedWnfName) {
                        if (-not $PayloadGroup.HasUniqueIdRange) {
                            $PayloadGroup.MinimumUniqueId = $UniqueId
                            $PayloadGroup.MaximumUniqueId = $UniqueId
                            $PayloadGroup.HasUniqueIdRange = $true
                        }
                        else {
                            if ($UniqueId -lt $PayloadGroup.MinimumUniqueId) {
                                $PayloadGroup.MinimumUniqueId = $UniqueId
                                $PayloadGroup.FirstValueName = $ValueName
                            }

                            if ($UniqueId -gt $PayloadGroup.MaximumUniqueId) {
                                $PayloadGroup.MaximumUniqueId = $UniqueId
                                $PayloadGroup.LastValueName = $ValueName
                            }
                        }
                    }
                }
                catch {
                    $Counters.PayloadReadFailures++
                }
            }
        }

        Write-Progress `
            -Activity 'Inventorying VolatileNotifications root values' `
            -Completed
    }
    else {
        Write-Host
        Write-Host "Server:       $env:COMPUTERNAME"
        Write-Host "Label:        $ServerLabel"
        Write-Host "Registry key: $RegistryDisplayPath"
        Write-Host 'Key present:  False'
        Write-Host
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


# ============================================================
# Export structural groups
# ============================================================

$StructureGroupRows = @(
    $StructureGroups.Values |
        Sort-Object `
            @{ Expression = { $_.ValueCount }; Descending = $true }, `
            @{ Expression = { $_.RegistryTypeCode }; Descending = $false }, `
            @{ Expression = { $_.DataLength }; Descending = $false }, `
            @{ Expression = { $_.DecodedMetadata }; Descending = $false } |
        ForEach-Object {
            [pscustomobject]@{
                ServerName      = $env:COMPUTERNAME
                ServerLabel     = $ServerLabel
                RegistryType    = $_.RegistryType
                RegistryTypeCode = $_.RegistryTypeCode
                DataLength      = $_.DataLength
                DecodedMetadata = $_.DecodedMetadata
                ValueCount      = $_.ValueCount
                FirstValueName  = $_.FirstValueName
                LastValueName   = $_.LastValueName
                MinimumUniqueId =
                    if ($_.HasUniqueIdRange) {
                        ('0x{0:X}' -f $_.MinimumUniqueId)
                    }
                    else {
                        ''
                    }
                MaximumUniqueId =
                    if ($_.HasUniqueIdRange) {
                        ('0x{0:X}' -f $_.MaximumUniqueId)
                    }
                    else {
                        ''
                    }
            }
        }
)

if ($StructureGroupRows.Count -gt 0) {
    $StructureGroupRows |
        Export-Csv `
            -LiteralPath $StructureGroupsCsv `
            -NoTypeInformation `
            -Encoding UTF8
}


# ============================================================
# Export payload groups
# ============================================================

$PayloadGroupRows = @(
    $PayloadGroups.Values |
        Sort-Object `
            @{ Expression = { $_.ValueCount }; Descending = $true }, `
            @{ Expression = { $_.DataLength }; Descending = $false }, `
            @{ Expression = { $_.DecodedMetadata }; Descending = $false } |
        ForEach-Object {
            [pscustomobject]@{
                ServerName      = $env:COMPUTERNAME
                ServerLabel     = $ServerLabel
                DataLength      = $_.DataLength
                DecodedMetadata = $_.DecodedMetadata
                PayloadHash     = $_.PayloadHash
                ValueCount      = $_.ValueCount
                FirstValueName  = $_.FirstValueName
                LastValueName   = $_.LastValueName
                MinimumUniqueId =
                    if ($_.HasUniqueIdRange) {
                        ('0x{0:X}' -f $_.MinimumUniqueId)
                    }
                    else {
                        ''
                    }
                MaximumUniqueId =
                    if ($_.HasUniqueIdRange) {
                        ('0x{0:X}' -f $_.MaximumUniqueId)
                    }
                    else {
                        ''
                    }
            }
        }
)

if ($PayloadGroupRows.Count -gt 0) {
    $PayloadGroupRows |
        Export-Csv `
            -LiteralPath $PayloadGroupsCsv `
            -NoTypeInformation `
            -Encoding UTF8
}


# ============================================================
# Export one-row summary
# ============================================================

$Summary = [pscustomobject]@{
    CheckedAt                   = Get-Date
    ServerName                  = $env:COMPUTERNAME
    ServerLabel                 = $ServerLabel
    RegistryPath                = $RegistryDisplayPath
    KeyPresent                  = $KeyPresent
    SubKeyCount                 = $SubKeyCount
    InitialValueCount           = $InitialValueCount
    TotalRootValues             = $Counters.TotalRootValues
    HexadecimalWnfNames         = $Counters.HexadecimalWnfNames
    NonHexadecimalNames         = $Counters.NonHexadecimalNames
    RegBinaryValues             = $Counters.RegBinaryValues
    DistinctStructuralGroups    = $StructureGroups.Count
    DistinctPayloadGroups       = $PayloadGroups.Count
    PayloadsHashed              = $Counters.PayloadsHashed
    PayloadHashSkippedLarge     = $Counters.PayloadHashSkippedLarge
    PayloadReadFailures         = $Counters.PayloadReadFailures
    EnumerationReadFailures     = $Counters.EnumerationReadFailures
    MaximumHashBytes            = $MaximumHashBytes
    StructureGroupsCsv          =
        if ($StructureGroupRows.Count -gt 0) {
            $StructureGroupsCsv
        }
        else {
            ''
        }
    PayloadGroupsCsv            =
        if ($PayloadGroupRows.Count -gt 0) {
            $PayloadGroupsCsv
        }
        else {
            ''
        }
}

$Summary |
    Export-Csv `
        -LiteralPath $SummaryCsv `
        -NoTypeInformation `
        -Encoding UTF8


# ============================================================
# Console summary
# ============================================================

Write-Host
Write-Host 'VolatileNotifications structural inventory completed.'
Write-Host
Write-Host "Server:                      $env:COMPUTERNAME"
Write-Host "Key present:                 $KeyPresent"
Write-Host "Subkeys:                     $SubKeyCount"
Write-Host "Total root values:           $($Counters.TotalRootValues)"
Write-Host "16-character WNF names:      $($Counters.HexadecimalWnfNames)"
Write-Host "Non-WNF-style names:         $($Counters.NonHexadecimalNames)"
Write-Host "REG_BINARY values:           $($Counters.RegBinaryValues)"
Write-Host "Distinct structural groups:  $($StructureGroups.Count)"
Write-Host "Distinct payload groups:     $($PayloadGroups.Count)"
Write-Host "Payloads hashed:             $($Counters.PayloadsHashed)"
Write-Host "Payloads skipped as large:   $($Counters.PayloadHashSkippedLarge)"
Write-Host "Payload read failures:       $($Counters.PayloadReadFailures)"
Write-Host

if ($StructureGroupRows.Count -gt 0) {
    Write-Host 'Largest structural groups:'

    $StructureGroupRows |
        Select-Object -First 10 |
        Format-Table `
            ValueCount,
            RegistryType,
            DataLength,
            DecodedMetadata `
            -AutoSize |
        Out-Host
}

Write-Host "Summary CSV:                 $SummaryCsv"

if ($StructureGroupRows.Count -gt 0) {
    Write-Host "Structure groups CSV:        $StructureGroupsCsv"
}

if ($PayloadGroupRows.Count -gt 0) {
    Write-Host "Payload groups CSV:          $PayloadGroupsCsv"
}
