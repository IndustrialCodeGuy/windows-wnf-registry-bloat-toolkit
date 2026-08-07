# Copyright 2026 Dan Michel
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0.
# See the LICENSE file in the project root for license information.

<#
.SYNOPSIS
    Reads and optionally exports a selected range of root-level Windows
    Notifications registry values.

.DESCRIPTION
    Enumerates root-level values under:

    HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications

    Values are read by registry enumeration index. The script reports each
    value's name, registry type, data length, and a limited data preview. A
    range can be selected from a starting index or from the end of the key.
    Results are displayed in the console and exported to a timestamped CSV by
    default.

    This script is read-only. It does not create, modify, or delete registry
    keys or values.

.NOTES
    Run from elevated 64-bit Windows PowerShell 5.1 on Windows Server 2019.

    Registry enumeration order does not establish value age, creation order,
    or operational importance. This script also does not determine whether a
    WNF state is active, stale, or safe to remove.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 10000)]
    [int] $Count = 100,

    [ValidateRange(0, [int]::MaxValue)]
    [int] $StartIndex = 0,

    [switch] $FromEnd,

    [ValidateRange(0, 4096)]
    [int] $PreviewBytes = 64,

    [ValidateRange(1, 10485760)]
    [int] $MaximumValueSize = 1048576,

    [string] $ExportCsv = (
        Join-Path $env:ProgramData (
            'WindowsWnfRegistryBloatToolkit\Samples\' +
            'Wnf-NotificationValues-{0:yyyyMMdd-HHmmss}.csv' -f (Get-Date)
        )
    )
)

$ErrorActionPreference = 'Stop'

$RegistrySubKey =
    'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications'

if (-not ('NotificationValueReaderNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class NotificationValueReaderNative
{
    public const int ERROR_SUCCESS        = 0;
    public const int ERROR_MORE_DATA      = 234;
    public const int ERROR_NO_MORE_ITEMS  = 259;

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
}
'@
}

function Get-RegistryTypeName {
    param(
        [uint32] $Type
    )

    switch ($Type) {
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
        default { "Unknown ($Type)" }
    }
}

function Convert-RegistryDataPreview {
    param(
        [Parameter(Mandatory)]
        [byte[]] $Data,

        [Parameter(Mandatory)]
        [uint32] $Type,

        [Parameter(Mandatory)]
        [int] $PreviewLength
    )

    if ($Data.Length -eq 0) {
        return ''
    }

    try {
        switch ($Type) {
            # REG_SZ and REG_EXPAND_SZ
            { $_ -in 1, 2 } {
                return (
                    [Text.Encoding]::Unicode.GetString($Data)
                ).TrimEnd([char]0)
            }

            # REG_MULTI_SZ
            7 {
                return (
                    [Text.Encoding]::Unicode.GetString($Data).
                        TrimEnd([char]0) -split "`0"
                ) -join ' | '
            }

            # REG_DWORD
            4 {
                if ($Data.Length -ge 4) {
                    return [BitConverter]::ToUInt32($Data, 0)
                }
            }

            # REG_DWORD_BIG_ENDIAN
            5 {
                if ($Data.Length -ge 4) {
                    $Bytes = $Data[0..3]
                    [Array]::Reverse($Bytes)

                    return [BitConverter]::ToUInt32($Bytes, 0)
                }
            }

            # REG_QWORD
            11 {
                if ($Data.Length -ge 8) {
                    return [BitConverter]::ToUInt64($Data, 0)
                }
            }
        }

        $BytesToShow = [Math]::Min(
            $Data.Length,
            $PreviewLength
        )

        if ($BytesToShow -eq 0) {
            return ''
        }

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
    catch {
        return "<preview error: $($_.Exception.Message)>"
    }
}

$BaseKey =
    [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine,
        [Microsoft.Win32.RegistryView]::Registry64
    )

try {
    $Key = $BaseKey.OpenSubKey(
        $RegistrySubKey,
        $false
    )

    if ($null -eq $Key) {
        throw "Registry key was not found: HKLM:\$RegistrySubKey"
    }

    try {
        $TotalCount = $Key.ValueCount

        if ($FromEnd) {
            $StartIndex = [Math]::Max(
                0,
                $TotalCount - $Count
            )
        }

        if ($StartIndex -ge $TotalCount) {
            throw (
                "StartIndex $StartIndex is beyond the final value. " +
                "The key contains $TotalCount values."
            )
        }

        $EndIndex = [Math]::Min(
            $TotalCount - 1,
            $StartIndex + $Count - 1
        )

        $Handle = $Key.Handle.DangerousGetHandle()

        Write-Host "Total values:     $TotalCount"
        Write-Host "Starting index:   $StartIndex"
        Write-Host "Ending index:     $EndIndex"
        Write-Host "Values requested: $Count"
        Write-Host

        $Results = foreach ($Index in $StartIndex..$EndIndex) {
            $NameCapacity = 16384
            $NameBuffer =
                [System.Text.StringBuilder]::new($NameCapacity)

            [uint32] $NameLength = $NameCapacity
            [uint32] $ValueType  = 0
            [uint32] $DataLength = 0

            # First call obtains the name, type, and required data size.
            $Result =
                [NotificationValueReaderNative]::RegEnumValue(
                    $Handle,
                    [uint32] $Index,
                    $NameBuffer,
                    [ref] $NameLength,
                    [IntPtr]::Zero,
                    [ref] $ValueType,
                    $null,
                    [ref] $DataLength
                )

            if (
                $Result -ne
                [NotificationValueReaderNative]::ERROR_SUCCESS
            ) {
                [pscustomobject]@{
                    EnumerationIndex = $Index
                    ValueName        = $null
                    RegistryType     = $null
                    DataLength       = $null
                    DataPreview      =
                        "RegEnumValue failed with error $Result"
                }

                continue
            }

            $ValueName = $NameBuffer.ToString()

            if ([string]::IsNullOrEmpty($ValueName)) {
                $ValueName = '(Default)'
            }

            $DataPreview = ''

            if ($DataLength -gt $MaximumValueSize) {
                $DataPreview = (
                    "<not read; value exceeds " +
                    "$MaximumValueSize bytes>"
                )
            }
            elseif ($DataLength -gt 0) {
                [byte[]] $Data = New-Object byte[] $DataLength

                # Reset these values before enumerating the same item again.
                $NameBuffer.Clear() | Out-Null
                [uint32] $NameLength = $NameCapacity
                [uint32] $ReadLength = $DataLength
                [uint32] $ReadType   = 0

                $ReadResult =
                    [NotificationValueReaderNative]::RegEnumValue(
                        $Handle,
                        [uint32] $Index,
                        $NameBuffer,
                        [ref] $NameLength,
                        [IntPtr]::Zero,
                        [ref] $ReadType,
                        $Data,
                        [ref] $ReadLength
                    )

                if (
                    $ReadResult -eq
                    [NotificationValueReaderNative]::ERROR_SUCCESS
                ) {
                    $DataPreview =
                        Convert-RegistryDataPreview `
                            -Data $Data `
                            -Type $ReadType `
                            -PreviewLength $PreviewBytes
                }
                else {
                    $DataPreview =
                        "Data read failed with error $ReadResult"
                }
            }

            [pscustomobject]@{
                EnumerationIndex = $Index
                ValueName        = $ValueName
                RegistryType     =
                    Get-RegistryTypeName -Type $ValueType
                DataLength       = $DataLength
                DataPreview      = $DataPreview
            }
        }
    }
    finally {
        $Key.Dispose()
    }
}
finally {
    $BaseKey.Dispose()
}

$Results |
    Format-Table `
        EnumerationIndex,
        ValueName,
        RegistryType,
        DataLength,
        DataPreview `
        -Wrap `
        -AutoSize

if ($ExportCsv) {
    $ParentFolder = Split-Path -Parent $ExportCsv

    if (
        $ParentFolder -and
        -not (Test-Path -LiteralPath $ParentFolder)
    ) {
        New-Item -ItemType Directory -Path $ParentFolder -Force | Out-Null
    }

    $Results |
        Export-Csv -LiteralPath $ExportCsv -NoTypeInformation -Encoding UTF8

    Write-Host
    Write-Host "Exported to: $ExportCsv"
}
