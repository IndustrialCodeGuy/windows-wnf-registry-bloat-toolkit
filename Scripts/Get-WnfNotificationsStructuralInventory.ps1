# Copyright 2026 Dan Michel
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0.
# See the LICENSE file in the project root for license information.

<#
.SYNOPSIS
    Inventories and classifies root-level values under the Windows
    Notifications registry key.

.DESCRIPTION
    Performs a complete structural inventory of:

    HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications

    The report includes total root values, SequenceNumber, the 72-byte
    metadata-0x011 system-scoped family, the 136-byte metadata-0x091
    user-scoped family, SHA-256 payload groups, matches to the known
    investigation payload, and unique-ID sequence statistics. The output is
    intended for comparison between Windows Server 2019 RDS systems.

    This script is read-only. It does not modify the registry.

.NOTES
    Run from elevated 64-bit Windows PowerShell 5.1 on Windows Server 2019.
#>

[CmdletBinding()]
param(
    [string] $ServerLabel = $env:COMPUTERNAME,

    [string] $OutputDirectory = (
        Join-Path $env:ProgramData 'WindowsWnfRegistryBloatToolkit\StructuralInventory'
    ),

    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string] $AffectedServerPayloadHash =
        'A847320A34E3ABD0F790D27CEF46D52CDD81E7B0F5257E8BE74FEF8FEE788840',

    [ValidateRange(100, 100000)]
    [int] $ProgressInterval = 2500
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

[uint64] $SystemMetadata = 0x011
[uint64] $UserMetadata   = 0x091

$AffectedServerPayloadHash =
    $AffectedServerPayloadHash.ToUpperInvariant()


# ============================================================
# Native registry declaration
# ============================================================

if (-not ('WnfStructuralNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class WnfStructuralNative
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

    [Array]::Copy(
        $Source,
        0,
        $Destination,
        0,
        $Length
    )

    return $Destination
}


function Get-SequenceStatistics {
    param(
        [Parameter(Mandatory)]
        [System.Collections.IEnumerable] $UniqueIds
    )

    [uint64[]] $Sorted = @(
        $UniqueIds |
            ForEach-Object { [uint64] $_ } |
            Sort-Object
    )

    if ($Sorted.Count -eq 0) {
        return [pscustomobject]@{
            TotalCount           = 0
            DistinctCount        = 0
            DuplicateCount       = 0
            MinimumUniqueId      = ''
            MaximumUniqueId      = ''
            ExpectedSpanCount    = 0
            MissingWithinRange   = 0
            GapCount             = 0
            LongestContiguousRun = 0
            FullyContiguous      = $false
        }
    }

    $Distinct =
        New-Object 'System.Collections.Generic.List[UInt64]'

    [uint64] $Previous = 0
    $HavePrevious = $false
    $DuplicateCount = 0

    foreach ($Id in $Sorted) {
        if ($HavePrevious -and $Id -eq $Previous) {
            $DuplicateCount++
            continue
        }

        [void] $Distinct.Add($Id)
        $Previous = $Id
        $HavePrevious = $true
    }

    [uint64] $Minimum = $Distinct[0]
    [uint64] $Maximum = $Distinct[$Distinct.Count - 1]

    [uint64] $ExpectedSpan =
        ($Maximum - $Minimum) + [uint64] 1

    [uint64] $Missing =
        $ExpectedSpan - [uint64] $Distinct.Count

    $GapCount = 0
    $CurrentRun = 1
    $LongestRun = 1

    for ($Index = 1; $Index -lt $Distinct.Count; $Index++) {
        if ($Distinct[$Index] -eq ($Distinct[$Index - 1] + [uint64] 1)) {
            $CurrentRun++

            if ($CurrentRun -gt $LongestRun) {
                $LongestRun = $CurrentRun
            }
        }
        else {
            $GapCount++
            $CurrentRun = 1
        }
    }

    return [pscustomobject]@{
        TotalCount           = $Sorted.Count
        DistinctCount        = $Distinct.Count
        DuplicateCount       = $DuplicateCount
        MinimumUniqueId      = ('0x{0:X}' -f $Minimum)
        MaximumUniqueId      = ('0x{0:X}' -f $Maximum)
        ExpectedSpanCount    = $ExpectedSpan
        MissingWithinRange   = $Missing
        GapCount             = $GapCount
        LongestContiguousRun = $LongestRun
        FullyContiguous      =
            ($DuplicateCount -eq 0 -and $Missing -eq 0)
    }
}


# ============================================================
# Preliminary checks and output paths
# ============================================================

if (-not [Environment]::Is64BitProcess) {
    throw 'Run this script from 64-bit Windows PowerShell.'
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$SafeLabel = $ServerLabel -replace '[^A-Za-z0-9._-]', '_'
$Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

$SummaryCsv = Join-Path $OutputDirectory (
    "Wnf-StructuralSummary-$SafeLabel-$Timestamp.csv"
)

$PayloadGroupsCsv = Join-Path $OutputDirectory (
    "Wnf-System72-PayloadGroups-$SafeLabel-$Timestamp.csv"
)


# ============================================================
# Counters and collections
# ============================================================

$Counters = [ordered]@{
    TotalRootValues              = 0
    SequenceNumberValues         = 0
    HexadecimalWnfNames          = 0
    NonHexadecimalNames          = 0
    System72Metadata011          = 0
    User136Metadata091           = 0
    OtherHexadecimalWnfValues    = 0
    OtherRootValues              = 0
    System72MatchingAffectedHash = 0
    System72DifferentPayloadHash = 0
    System72PayloadReadFailures  = 0
}

$SystemUniqueIds =
    New-Object 'System.Collections.Generic.List[UInt64]'

$UserUniqueIds =
    New-Object 'System.Collections.Generic.List[UInt64]'

$SystemPayloadGroups = @{}


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

    if ($null -eq $Key) {
        throw "Registry key was not found: $RegistryDisplayPath"
    }

    $Handle = $Key.Handle.DangerousGetHandle()
    $InitialValueCount = $Key.ValueCount

    Write-Host
    Write-Host "Server:              $env:COMPUTERNAME"
    Write-Host "Label:               $ServerLabel"
    Write-Host "Registry key:        $RegistryDisplayPath"
    Write-Host "Initial value count: $InitialValueCount"
    Write-Host

    # Large enough for all known 8-, 72-, and 136-byte values.
    [byte[]] $DataBuffer = New-Object byte[] 512

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
                -Activity 'Inventorying Notifications root values' `
                -Status (
                    "$EnumerationIndex examined; " +
                    "$($Counters.System72Metadata011) system-72; " +
                    "$($Counters.User136Metadata091) user-136"
                ) `
                -PercentComplete $PercentComplete
        }

        $NameCapacity = 16384
        $NameBuffer = New-Object Text.StringBuilder($NameCapacity)

        [uint32] $NameLength = $NameCapacity
        [uint32] $ValueType = 0
        [uint32] $DataLength = $DataBuffer.Length

        $EnumResult =
            [WnfStructuralNative]::RegEnumValue(
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
            [WnfStructuralNative]::ERROR_NO_MORE_ITEMS
        ) {
            break
        }

        if (
            $EnumResult -ne
                [WnfStructuralNative]::ERROR_SUCCESS -and
            $EnumResult -ne
                [WnfStructuralNative]::ERROR_MORE_DATA
        ) {
            throw (
                "RegEnumValue failed at index $EnumerationIndex " +
                "with Win32 error $EnumResult."
            )
        }

        $Counters.TotalRootValues++
        $ValueName = $NameBuffer.ToString()

        if ($ValueName -eq 'SequenceNumber') {
            $Counters.SequenceNumberValues++
        }

        if ($ValueName -notmatch '^[0-9A-Fa-f]{16}$') {
            $Counters.NonHexadecimalNames++
            continue
        }

        $Counters.HexadecimalWnfNames++

        try {
            [uint64] $Encoded =
                [Convert]::ToUInt64($ValueName, 16)

            [uint64] $Decoded =
                $Encoded -bxor $WnfXorMask

            [uint64] $Metadata =
                $Decoded -band [uint64] 0x7FF

            [uint64] $UniqueId =
                $Decoded -shr 11
        }
        catch {
            $Counters.OtherHexadecimalWnfValues++
            continue
        }

        # REG_BINARY = 3
        if (
            $ValueType -eq 3 -and
            $DataLength -eq 72 -and
            $Metadata -eq $SystemMetadata
        ) {
            $Counters.System72Metadata011++
            [void] $SystemUniqueIds.Add($UniqueId)

            if (
                $EnumResult -ne
                    [WnfStructuralNative]::ERROR_SUCCESS
            ) {
                $Counters.System72PayloadReadFailures++
                continue
            }

            try {
                [byte[]] $Payload =
                    Copy-ByteRange `
                        -Source $DataBuffer `
                        -Length 72

                $PayloadHash =
                    Get-Sha256Hex -Bytes $Payload

                if (-not $SystemPayloadGroups.ContainsKey($PayloadHash)) {
                    $SystemPayloadGroups[$PayloadHash] =
                        [pscustomobject]@{
                            PayloadHash      = $PayloadHash
                            ValueCount       = 0
                            FirstValueName   = $ValueName
                            LastValueName    = $ValueName
                            MinimumUniqueId  = $UniqueId
                            MaximumUniqueId  = $UniqueId
                            MatchesAffected  =
                                ($PayloadHash -eq
                                    $AffectedServerPayloadHash)
                        }
                }

                $Group = $SystemPayloadGroups[$PayloadHash]
                $Group.ValueCount =
                    [int64] $Group.ValueCount + 1

                if ($UniqueId -lt $Group.MinimumUniqueId) {
                    $Group.MinimumUniqueId = $UniqueId
                    $Group.FirstValueName = $ValueName
                }

                if ($UniqueId -gt $Group.MaximumUniqueId) {
                    $Group.MaximumUniqueId = $UniqueId
                    $Group.LastValueName = $ValueName
                }

                if ($PayloadHash -eq $AffectedServerPayloadHash) {
                    $Counters.System72MatchingAffectedHash++
                }
                else {
                    $Counters.System72DifferentPayloadHash++
                }
            }
            catch {
                $Counters.System72PayloadReadFailures++
            }

            continue
        }

        if (
            $ValueType -eq 3 -and
            $DataLength -eq 136 -and
            $Metadata -eq $UserMetadata
        ) {
            $Counters.User136Metadata091++
            [void] $UserUniqueIds.Add($UniqueId)
            continue
        }

        $Counters.OtherHexadecimalWnfValues++
    }

    Write-Progress `
        -Activity 'Inventorying Notifications root values' `
        -Completed
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
# Sequence analysis
# ============================================================

$SystemSequence =
    Get-SequenceStatistics -UniqueIds $SystemUniqueIds

$UserSequence =
    Get-SequenceStatistics -UniqueIds $UserUniqueIds

$Counters.OtherRootValues =
    $Counters.TotalRootValues -
    $Counters.System72Metadata011 -
    $Counters.User136Metadata091 -
    $Counters.SequenceNumberValues

$SystemMatchPercent = 0

if ($Counters.System72Metadata011 -gt 0) {
    $SystemMatchPercent = [Math]::Round(
        (
            $Counters.System72MatchingAffectedHash /
            $Counters.System72Metadata011
        ) * 100,
        4
    )
}


# ============================================================
# Export payload groups
# ============================================================

$PayloadGroupRows = @(
    $SystemPayloadGroups.Values |
        Sort-Object `
            @{ Expression = { $_.ValueCount }
               Descending = $true } |
        ForEach-Object {
            [pscustomobject]@{
                ServerName      = $env:COMPUTERNAME
                ServerLabel     = $ServerLabel
                PayloadHash     = $_.PayloadHash
                ValueCount      = $_.ValueCount
                MatchesAffected = $_.MatchesAffected
                FirstValueName  = $_.FirstValueName
                LastValueName   = $_.LastValueName
                MinimumUniqueId =
                    ('0x{0:X}' -f $_.MinimumUniqueId)
                MaximumUniqueId =
                    ('0x{0:X}' -f $_.MaximumUniqueId)
            }
        }
)

$PayloadGroupRows |
    Export-Csv -LiteralPath $PayloadGroupsCsv -NoTypeInformation -Encoding UTF8


# ============================================================
# Export one-row summary
# ============================================================

$Summary = [pscustomobject]@{
    CheckedAt                       = Get-Date
    ServerName                      = $env:COMPUTERNAME
    ServerLabel                     = $ServerLabel
    RegistryPath                    = $RegistryDisplayPath

    TotalRootValues                 =
        $Counters.TotalRootValues

    SequenceNumberValues            =
        $Counters.SequenceNumberValues

    HexadecimalWnfNames             =
        $Counters.HexadecimalWnfNames

    NonHexadecimalNames             =
        $Counters.NonHexadecimalNames

    System72Metadata011             =
        $Counters.System72Metadata011

    User136Metadata091              =
        $Counters.User136Metadata091

    OtherHexadecimalWnfValues       =
        $Counters.OtherHexadecimalWnfValues

    OtherRootValues                 =
        $Counters.OtherRootValues

    AffectedServerPayloadHash       =
        $AffectedServerPayloadHash

    System72MatchingAffectedHash    =
        $Counters.System72MatchingAffectedHash

    System72MatchingAffectedPercent =
        $SystemMatchPercent

    System72DifferentPayloadHash    =
        $Counters.System72DifferentPayloadHash

    System72DistinctPayloadHashes   =
        $SystemPayloadGroups.Count

    System72PayloadReadFailures     =
        $Counters.System72PayloadReadFailures

    System72DistinctUniqueIds       =
        $SystemSequence.DistinctCount

    System72DuplicateUniqueIds      =
        $SystemSequence.DuplicateCount

    System72MinimumUniqueId         =
        $SystemSequence.MinimumUniqueId

    System72MaximumUniqueId         =
        $SystemSequence.MaximumUniqueId

    System72ExpectedSpanCount       =
        $SystemSequence.ExpectedSpanCount

    System72MissingWithinRange      =
        $SystemSequence.MissingWithinRange

    System72GapCount                =
        $SystemSequence.GapCount

    System72LongestContiguousRun    =
        $SystemSequence.LongestContiguousRun

    System72FullyContiguous         =
        $SystemSequence.FullyContiguous

    User136DistinctUniqueIds        =
        $UserSequence.DistinctCount

    User136DuplicateUniqueIds       =
        $UserSequence.DuplicateCount

    User136MinimumUniqueId          =
        $UserSequence.MinimumUniqueId

    User136MaximumUniqueId          =
        $UserSequence.MaximumUniqueId

    User136ExpectedSpanCount        =
        $UserSequence.ExpectedSpanCount

    User136MissingWithinRange       =
        $UserSequence.MissingWithinRange

    User136GapCount                 =
        $UserSequence.GapCount

    User136LongestContiguousRun     =
        $UserSequence.LongestContiguousRun

    User136FullyContiguous          =
        $UserSequence.FullyContiguous

    PayloadGroupsCsv                =
        $PayloadGroupsCsv
}

$Summary |
    Export-Csv -LiteralPath $SummaryCsv -NoTypeInformation -Encoding UTF8


# ============================================================
# Console summary
# ============================================================

Write-Host
Write-Host 'Structural inventory completed.'
Write-Host
Write-Host "Server:                         $env:COMPUTERNAME"
Write-Host "Total root values:              $($Counters.TotalRootValues)"
Write-Host "SequenceNumber values:          $($Counters.SequenceNumberValues)"
Write-Host "72-byte metadata 0x011:         $($Counters.System72Metadata011)"
Write-Host "136-byte metadata 0x091:        $($Counters.User136Metadata091)"
Write-Host "Other root values:              $($Counters.OtherRootValues)"
Write-Host
Write-Host "72-byte distinct payload hashes: $($SystemPayloadGroups.Count)"
Write-Host (
    "72-byte matching affected hash: " +
    "$($Counters.System72MatchingAffectedHash) " +
    "($SystemMatchPercent%)"
)
Write-Host (
    "72-byte different payload hash:  " +
    "$($Counters.System72DifferentPayloadHash)"
)
Write-Host (
    "72-byte payload read failures:   " +
    "$($Counters.System72PayloadReadFailures)"
)
Write-Host
Write-Host (
    "72-byte unique-ID range:         " +
    "$($SystemSequence.MinimumUniqueId) - " +
    "$($SystemSequence.MaximumUniqueId)"
)
Write-Host (
    "72-byte distinct/duplicates:     " +
    "$($SystemSequence.DistinctCount) / " +
    "$($SystemSequence.DuplicateCount)"
)
Write-Host (
    "72-byte gaps/missing IDs:        " +
    "$($SystemSequence.GapCount) / " +
    "$($SystemSequence.MissingWithinRange)"
)
Write-Host (
    "72-byte longest contiguous run:  " +
    "$($SystemSequence.LongestContiguousRun)"
)
Write-Host (
    "72-byte fully contiguous:        " +
    "$($SystemSequence.FullyContiguous)"
)
Write-Host
Write-Host "Summary CSV:        $SummaryCsv"
Write-Host "Payload groups CSV: $PayloadGroupsCsv"
