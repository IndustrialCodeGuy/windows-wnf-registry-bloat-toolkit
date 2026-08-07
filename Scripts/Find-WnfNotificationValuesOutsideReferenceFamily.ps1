# Copyright 2026 Dan Michel
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0.
# See the LICENSE file in the project root for license information.

<#
.SYNOPSIS
    Identifies root-level Windows Notifications values outside a selected
    repeated WNF reference family.

.DESCRIPTION
    Enumerates root-level values under the Windows Notifications registry key
    and compares each value with the selected reference family.

    A value is considered part of the reference family only when its name is a
    16-character hexadecimal WNF state name, its decoded WNF metadata matches
    the reference value, it is REG_BINARY, its data length matches, and its
    complete binary payload is identical to the reference payload.

    Values outside the family are exported to CSV for additional analysis.

    This script is read-only. It does not modify or delete registry data.

.NOTES
    Run from elevated 64-bit Windows PowerShell 5.1 on Windows Server 2019.

    Large Notifications keys may take several minutes to scan.
#>

[CmdletBinding()]
param(
    # First value from the previously sampled sequence.
    [string] $ReferenceValueName = '41C64E6DA0000065',

    # Every nonmatching value is written here.
    [string] $ExportCsv = (
        Join-Path $env:ProgramData (
            'WindowsWnfRegistryBloatToolkit\Analysis\' +
            'Wnf-NotificationValues-OutsideReferenceFamily.csv'
        )
    ),

    # Maximum number of nonmatching values also displayed onscreen.
    [ValidateRange(0, 10000)]
    [int] $DisplayLimit = 100,

    # Frequency of progress updates.
    [ValidateRange(100, 100000)]
    [int] $ProgressInterval = 2500
)

$ErrorActionPreference = 'Stop'

$RegistrySubKey =
    'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications'

$RegistryDisplayPath =
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications'

# XOR key used to decode WNF state names.
[uint64] $WnfXorMask =
    [uint64]::Parse(
        '41C64E6DA3BC0074',
        [Globalization.NumberStyles]::HexNumber
    )


# ------------------------------------------------------------
# Native registry functions
# ------------------------------------------------------------

if (-not ('NotificationSequenceAuditNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class NotificationSequenceAuditNative
{
    public const int ERROR_SUCCESS       = 0;
    public const int ERROR_FILE_NOT_FOUND = 2;
    public const int ERROR_MORE_DATA     = 234;
    public const int ERROR_NO_MORE_ITEMS = 259;

    [DllImport(
        "advapi32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true
    )]
    public static extern int RegEnumValue(
        IntPtr hKey,
        uint dwIndex,
        StringBuilder lpValueName,
        ref uint lpcchValueName,
        IntPtr lpReserved,
        ref uint lpType,
        byte[] lpData,
        ref uint lpcbData
    );

    [DllImport(
        "advapi32.dll",
        CharSet = CharSet.Unicode,
        SetLastError = true
    )]
    public static extern int RegQueryValueEx(
        IntPtr hKey,
        string lpValueName,
        IntPtr lpReserved,
        ref uint lpType,
        byte[] lpData,
        ref uint lpcbData
    );
}
'@
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


function ConvertTo-HexPreview {
    param(
        [AllowNull()]
        [byte[]] $Data,

        [ValidateRange(1, 4096)]
        [int] $MaximumBytes = 64
    )

    if ($null -eq $Data -or $Data.Length -eq 0) {
        return ''
    }

    $BytesToShow = [Math]::Min(
        $Data.Length,
        $MaximumBytes
    )

    $Preview = [BitConverter]::ToString(
        $Data,
        0,
        $BytesToShow
    )

    if ($Data.Length -gt $BytesToShow) {
        $Preview += ' ...'
    }

    return $Preview
}


function ConvertTo-CsvField {
    param(
        [AllowNull()]
        [object] $Value
    )

    if ($null -eq $Value) {
        $Text = ''
    }
    else {
        $Text = [string] $Value
    }

    return '"' + $Text.Replace('"', '""') + '"'
}


function Write-ResultToCsv {
    param(
        [Parameter(Mandatory)]
        [System.IO.StreamWriter] $Writer,

        [Parameter(Mandatory)]
        [psobject] $Result
    )

    $Fields = @(
        $Result.EnumerationIndex
        $Result.ValueName
        $Result.RegistryType
        $Result.DataLength
        $Result.DecodedMetadata
        $Result.UniqueId
        $Result.Reason
        $Result.DataPreview
    )

    $CsvLine = (
        $Fields |
        ForEach-Object {
            ConvertTo-CsvField $_
        }
    ) -join ','

    $Writer.WriteLine($CsvLine)
}


# ------------------------------------------------------------
# Preliminary checks
# ------------------------------------------------------------

if (-not [Environment]::Is64BitProcess) {
    throw 'Run this script from 64-bit Windows PowerShell.'
}

if ($ReferenceValueName -notmatch '^[0-9A-Fa-f]{16}$') {
    throw (
        "The reference value name is not a valid 16-character " +
        "hexadecimal WNF state name: $ReferenceValueName"
    )
}

$ExportDirectory = Split-Path -Parent $ExportCsv

if (
    $ExportDirectory -and
    -not (Test-Path -LiteralPath $ExportDirectory)
) {
    New-Item -ItemType Directory -Path $ExportDirectory -Force | Out-Null
}


# ------------------------------------------------------------
# Open the registry key
# ------------------------------------------------------------

$BaseKey = $null
$Key     = $null
$Writer  = $null

try {
    $BaseKey =
        [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64
        )

    $Key = $BaseKey.OpenSubKey(
        $RegistrySubKey,
        $false
    )

    if ($null -eq $Key) {
        throw "Registry key was not found: $RegistryDisplayPath"
    }

    $Handle = $Key.Handle.DangerousGetHandle()

    # --------------------------------------------------------
    # Load and decode the reference value
    # --------------------------------------------------------

    try {
        $ReferenceKind =
            $Key.GetValueKind($ReferenceValueName)
    }
    catch {
        throw (
            "The reference value was not found: " +
            "$ReferenceValueName"
        )
    }

    if (
        $ReferenceKind -ne
        [Microsoft.Win32.RegistryValueKind]::Binary
    ) {
        throw (
            "The reference value is not REG_BINARY. Its type is " +
            "$ReferenceKind."
        )
    }

    [byte[]] $ReferenceData =
        $Key.GetValue($ReferenceValueName)

    if ($null -eq $ReferenceData) {
        throw 'The reference value data could not be read.'
    }

    [uint64] $ReferenceEncoded =
        [Convert]::ToUInt64(
            $ReferenceValueName,
            16
        )

    [uint64] $ReferenceDecoded =
        $ReferenceEncoded -bxor $WnfXorMask

    # The lower 11 decoded bits contain the WNF metadata fields.
    [uint64] $ReferenceMetadata =
        $ReferenceDecoded -band [uint64]0x7FF

    [uint64] $ReferenceUniqueId =
        $ReferenceDecoded -shr 11

    $ReferenceLength = $ReferenceData.Length

    Write-Host
    Write-Host "Registry key:       $RegistryDisplayPath"
    Write-Host "Reference value:    $ReferenceValueName"
    Write-Host (
        'Reference metadata: 0x{0:X3}' -f
        $ReferenceMetadata
    )
    Write-Host (
        'Reference unique ID: 0x{0:X}' -f
        $ReferenceUniqueId
    )
    Write-Host "Reference length:   $ReferenceLength bytes"
    Write-Host

    # --------------------------------------------------------
    # Prepare the output file
    # --------------------------------------------------------

    $Utf8Encoding =
        [System.Text.UTF8Encoding]::new($true)

    $Writer =
        [System.IO.StreamWriter]::new(
            $ExportCsv,
            $false,
            $Utf8Encoding
        )

    $Writer.WriteLine(
        '"EnumerationIndex","ValueName","RegistryType",' +
        '"DataLength","DecodedMetadata","UniqueId",' +
        '"Reason","DataPreview"'
    )

    # --------------------------------------------------------
    # Enumerate and classify every value
    # --------------------------------------------------------

    $TotalCount       = $Key.ValueCount
    $ScannedCount     = 0
    $MatchingCount    = 0
    $NonMatchingCount = 0

    $DisplayedResults =
        New-Object 'System.Collections.Generic.List[object]'

    for (
        [uint32] $EnumerationIndex = 0;
        $EnumerationIndex -lt $TotalCount;
        $EnumerationIndex++
    ) {
        if (
            $EnumerationIndex -eq 0 -or
            ($EnumerationIndex % $ProgressInterval) -eq 0
        ) {
            $PercentComplete =
                [Math]::Floor(
                    ($EnumerationIndex / $TotalCount) * 100
                )

            Write-Progress `
                -Activity 'Scanning Notifications registry values' `
                -Status (
                    "$EnumerationIndex of $TotalCount scanned; " +
                    "$NonMatchingCount outside the sequence"
                ) `
                -PercentComplete $PercentComplete
        }

        $NameCapacity = 16384

        $NameBuffer =
            [System.Text.StringBuilder]::new(
                $NameCapacity
            )

        [uint32] $NameLength = $NameCapacity
        [uint32] $ValueType  = 0
        [uint32] $DataLength = 0

        # Read the name, type, and required data length.
        $EnumResult =
            [NotificationSequenceAuditNative]::RegEnumValue(
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
            [NotificationSequenceAuditNative]::ERROR_NO_MORE_ITEMS
        ) {
            Write-Warning (
                'Registry enumeration ended before the original ' +
                'value count was reached. The key may have changed ' +
                'during the scan.'
            )

            break
        }

        if (
            $EnumResult -ne
            [NotificationSequenceAuditNative]::ERROR_SUCCESS
        ) {
            throw (
                "RegEnumValue failed at index " +
                "$EnumerationIndex with Win32 error $EnumResult."
            )
        }

        $ScannedCount++

        $ValueName = $NameBuffer.ToString()

        $Reasons =
            New-Object 'System.Collections.Generic.List[string]'

        $DecodedMetadata = $null
        $UniqueId        = $null
        $Data            = $null

        # ----------------------------------------------------
        # Check the encoded WNF name
        # ----------------------------------------------------

        if ($ValueName -notmatch '^[0-9A-Fa-f]{16}$') {
            [void] $Reasons.Add(
                'Name is not a 16-character hexadecimal WNF name'
            )
        }
        else {
            try {
                [uint64] $EncodedName =
                    [Convert]::ToUInt64(
                        $ValueName,
                        16
                    )

                [uint64] $DecodedName =
                    $EncodedName -bxor $WnfXorMask

                [uint64] $Metadata =
                    $DecodedName -band [uint64]0x7FF

                [uint64] $DecodedUniqueId =
                    $DecodedName -shr 11

                $DecodedMetadata =
                    '0x{0:X3}' -f $Metadata

                $UniqueId =
                    '0x{0:X}' -f $DecodedUniqueId

                if ($Metadata -ne $ReferenceMetadata) {
                    [void] $Reasons.Add(
                        'Decoded WNF metadata differs'
                    )
                }
            }
            catch {
                [void] $Reasons.Add(
                    "WNF name could not be decoded: " +
                    $_.Exception.Message
                )
            }
        }

        # ----------------------------------------------------
        # Check type and length
        # ----------------------------------------------------

        if ($ValueType -ne 3) {
            [void] $Reasons.Add(
                "Registry type is $ValueType rather than REG_BINARY"
            )
        }

        if ($DataLength -ne $ReferenceLength) {
            [void] $Reasons.Add(
                "Data length is $DataLength rather than " +
                "$ReferenceLength"
            )
        }

        # ----------------------------------------------------
        # Compare the complete payload when the basic shape matches
        # ----------------------------------------------------

        if (
            $ValueType -eq 3 -and
            $DataLength -eq $ReferenceLength
        ) {
            [byte[]] $Data =
                New-Object byte[] ([int] $DataLength)

            [uint32] $ReadType   = 0
            [uint32] $ReadLength = $DataLength

            $QueryResult =
                [NotificationSequenceAuditNative]::RegQueryValueEx(
                    $Handle,
                    $ValueName,
                    [IntPtr]::Zero,
                    [ref] $ReadType,
                    $Data,
                    [ref] $ReadLength
                )

            if (
                $QueryResult -ne
                [NotificationSequenceAuditNative]::ERROR_SUCCESS
            ) {
                [void] $Reasons.Add(
                    "Data read failed with Win32 error $QueryResult"
                )
            }
            elseif (
                -not (
                    Test-ByteArrayEqual `
                        -First $Data `
                        -Second $ReferenceData
                )
            ) {
                [void] $Reasons.Add(
                    'Binary payload differs from the reference'
                )
            }
        }

        # ----------------------------------------------------
        # Record matches or anomalies
        # ----------------------------------------------------

        if ($Reasons.Count -eq 0) {
            $MatchingCount++
            continue
        }

        $NonMatchingCount++

        $RegistryTypeName =
            switch ($ValueType) {
                0  { 'REG_NONE' }
                1  { 'REG_SZ' }
                2  { 'REG_EXPAND_SZ' }
                3  { 'REG_BINARY' }
                4  { 'REG_DWORD' }
                5  { 'REG_DWORD_BIG_ENDIAN' }
                6  { 'REG_LINK' }
                7  { 'REG_MULTI_SZ' }
                8  { 'REG_RESOURCE_LIST' }
                9  { 'REG_FULL_RESOURCE_DESCRIPTOR' }
                10 { 'REG_RESOURCE_REQUIREMENTS_LIST' }
                11 { 'REG_QWORD' }
                default { "Unknown ($ValueType)" }
            }

        $Result = [pscustomobject]@{
            EnumerationIndex = $EnumerationIndex
            ValueName        = $ValueName
            RegistryType     = $RegistryTypeName
            DataLength       = $DataLength
            DecodedMetadata  = $DecodedMetadata
            UniqueId         = $UniqueId
            Reason           = $Reasons -join '; '
            DataPreview      =
                ConvertTo-HexPreview -Data $Data
        }

        Write-ResultToCsv `
            -Writer $Writer `
            -Result $Result

        if ($DisplayedResults.Count -lt $DisplayLimit) {
            [void] $DisplayedResults.Add($Result)
        }
    }

    Write-Progress `
        -Activity 'Scanning Notifications registry values' `
        -Completed

    $Writer.Flush()

    Write-Host
    Write-Host 'Scan completed.'
    Write-Host "Initial value count: $TotalCount"
    Write-Host "Values scanned:      $ScannedCount"
    Write-Host "Sequence matches:    $MatchingCount"
    Write-Host "Outside sequence:    $NonMatchingCount"
    Write-Host "CSV output:          $ExportCsv"
    Write-Host

    if ($DisplayedResults.Count -gt 0) {
        Write-Host (
            "Displaying the first $($DisplayedResults.Count) " +
            'nonmatching values:'
        )

        $DisplayedResults |
            Format-Table `
                EnumerationIndex,
                ValueName,
                RegistryType,
                DataLength,
                DecodedMetadata,
                UniqueId,
                Reason `
                -Wrap `
                -AutoSize
    }
    else {
        Write-Host (
            'No values outside the observed sequence pattern ' +
            'were found.'
        )
    }

    if ($NonMatchingCount -gt $DisplayedResults.Count) {
        Write-Host
        Write-Host (
            "$($NonMatchingCount - $DisplayedResults.Count) " +
            'additional nonmatching values are in the CSV.'
        )
    }
}
finally {
    if ($null -ne $Writer) {
        $Writer.Dispose()
    }

    if ($null -ne $Key) {
        $Key.Dispose()
    }

    if ($null -ne $BaseKey) {
        $BaseKey.Dispose()
    }
}
