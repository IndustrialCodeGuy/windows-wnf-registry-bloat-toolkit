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
    Identifies root-level Windows Notifications values outside the toolkit's
    confirmed repeated WNF target family.

.DESCRIPTION
    Enumerates root-level values under the Windows Notifications registry key
    and compares each value with the toolkit's confirmed target family.

    When -ReferenceValueName is omitted, the script automatically locates an
    exact current member using the fixed family boundary: REG_BINARY, decoded
    metadata 0x011, 72-byte length, and the confirmed SHA-256 payload hash.
    That value's complete payload becomes the byte-for-byte reference for the
    scan. An explicitly supplied -ReferenceValueName must match the same fixed
    family.

    Values outside the family are exported to CSV for additional analysis.

    This script is read-only. It does not modify or delete registry data.

.NOTES
    Run from elevated 64-bit Windows PowerShell 5.1 on Windows Server 2019.

    Large Notifications keys may take several minutes to scan.
#>

[CmdletBinding()]
param(
    # Optional exact member of the toolkit's confirmed target family.
    # When omitted, the script discovers one from the current registry data.
    [string] $ReferenceValueName,

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

# Fixed, investigation-specific family boundary. Keep these values aligned
# with Audit-WnfSystemScopeLiveState.ps1 and
# Invoke-WnfNotificationsRemediation.ps1.
[uint64] $TargetMetadata = 0x011
[int] $TargetLength = 72
$TargetPayloadHash =
    'A847320A34E3ABD0F790D27CEF46D52CDD81E7B0F5257E8BE74FEF8FEE788840'


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
            break
        }

        if (
            $EnumResult -ne
                [NotificationSequenceAuditNative]::ERROR_SUCCESS -and
            $EnumResult -ne
                [NotificationSequenceAuditNative]::ERROR_MORE_DATA
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
                ValueName = $ValueName
                Data      = $Validation.Data
                Length    = $Validation.Length
                Metadata  = $Validation.Metadata
                Hash      = $Validation.Hash
            }
        }
    }

    Write-Progress `
        -Activity 'Locating exact WNF reference-family value' `
        -Completed

    return $null
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

if (
    $ReferenceValueName -and
    $ReferenceValueName -notmatch '^[0-9A-Fa-f]{16}$'
) {
    throw (
        'ReferenceValueName must be a 16-character hexadecimal ' +
        "WNF state name: $ReferenceValueName"
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
    # Establish the exact target-family reference
    # --------------------------------------------------------

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
    $ReferenceLength = $Reference.Length
    $ReferenceHash = [string] $Reference.Hash

    [uint64] $ReferenceEncoded =
        [Convert]::ToUInt64($ReferenceValueName, 16)
    [uint64] $ReferenceDecoded =
        $ReferenceEncoded -bxor $WnfXorMask
    [uint64] $ReferenceUniqueId =
        $ReferenceDecoded -shr 11

    Write-Host
    Write-Host "Registry key:        $RegistryDisplayPath"
    Write-Host "Reference source:    $ReferenceSelectionSource"
    Write-Host "Reference value:     $ReferenceValueName"
    Write-Host (
        'Reference metadata:  0x{0:X3}' -f
        $ReferenceMetadata
    )
    Write-Host (
        'Reference unique ID: 0x{0:X}' -f
        $ReferenceUniqueId
    )
    Write-Host "Reference length:    $ReferenceLength bytes"
    Write-Host "Reference SHA-256:   $ReferenceHash"
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
                    "$NonMatchingCount outside the target family"
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
    Write-Host "Target-family matches: $MatchingCount"
    Write-Host "Outside target family: $NonMatchingCount"
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
            'No values outside the exact target family ' +
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
