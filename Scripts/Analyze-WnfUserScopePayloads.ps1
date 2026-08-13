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
    Analyzes the 136-byte user-scoped WNF value family under the Windows
    Notifications registry key.

.DESCRIPTION
    Imports the values outside the selected repeated WNF reference family,
    selects 136-byte REG_BINARY values with decoded metadata 0x091, and reads
    each matching live registry value by name.

    The script hashes and groups complete payloads, parses the security
    descriptor at the start of each distinct payload, extracts owner, group,
    DACL, and SACL SIDs, compares account-shaped SIDs with Win32_UserProfile,
    and optionally resolves SIDs to account names. Detailed CSV reports are
    written to the configured output directory.

    This script is read-only. It does not modify the registry.

.NOTES
    Run from elevated 64-bit Windows PowerShell 5.1 on Windows Server 2019.

    SequenceNumber is intentionally excluded because it is not part of the
    136-byte WNF family being analyzed.
#>

[CmdletBinding()]
param(
    [string] $InputCsv = (
        Join-Path $env:ProgramData (
            'WindowsWnfRegistryBloatToolkit\Analysis\' +
            'Wnf-NotificationValues-OutsideReferenceFamily.csv'
        )
    ),

    [string] $OutputDirectory = (
        Join-Path $env:ProgramData 'WindowsWnfRegistryBloatToolkit\Analysis\WnfUserScope'
    ),

    [switch] $ResolveSidNames
)

$ErrorActionPreference = 'Stop'

$RegistrySubKey =
    'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications'

$RegistryDisplayPath =
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications'


# ============================================================
# Helper functions
# ============================================================

function Get-Sha256Hex {
    param(
        [Parameter(Mandatory)]
        [byte[]] $Bytes
    )

    $Hasher = [System.Security.Cryptography.SHA256]::Create()

    try {
        $HashBytes = $Hasher.ComputeHash($Bytes)

        return (
            [BitConverter]::ToString($HashBytes).Replace('-', '')
        )
    }
    finally {
        $Hasher.Dispose()
    }
}


function ConvertTo-HexString {
    param(
        [AllowNull()]
        [byte[]] $Bytes
    )

    if ($null -eq $Bytes -or $Bytes.Length -eq 0) {
        return ''
    }

    return [BitConverter]::ToString($Bytes).Replace('-', '')
}


function Get-SidsFromAcl {
    param(
        [AllowNull()]
        [System.Security.AccessControl.RawAcl] $Acl
    )

    $Sids = @()

    if ($null -eq $Acl) {
        return $Sids
    }

    for ($Index = 0; $Index -lt $Acl.Count; $Index++) {
        $Ace = $Acl[$Index]

        if (
            $Ace -is
            [System.Security.AccessControl.KnownAce]
        ) {
            if ($null -ne $Ace.SecurityIdentifier) {
                $Sids += $Ace.SecurityIdentifier.Value
            }
        }
    }

    return @(
        $Sids |
            Where-Object { $_ } |
            Sort-Object -Unique
    )
}


$script:SidNameCache = @{}

function Resolve-SidToAccountName {
    param(
        [Parameter(Mandatory)]
        [string] $Sid
    )

    if ($script:SidNameCache.ContainsKey($Sid)) {
        return $script:SidNameCache[$Sid]
    }

    try {
        $SidObject =
            [System.Security.Principal.SecurityIdentifier]::new(
                $Sid
            )

        $AccountName =
            $SidObject.Translate(
                [System.Security.Principal.NTAccount]
            ).Value
    }
    catch {
        $AccountName = ''
    }

    $script:SidNameCache[$Sid] = $AccountName

    return $AccountName
}


function Copy-ByteRange {
    param(
        [Parameter(Mandatory)]
        [byte[]] $Source,

        [Parameter(Mandatory)]
        [int] $Offset,

        [Parameter(Mandatory)]
        [int] $Length
    )

    if ($Length -le 0) {
        return [byte[]] @()
    }

    [byte[]] $Destination =
        New-Object byte[] $Length

    [Array]::Copy(
        $Source,
        $Offset,
        $Destination,
        0,
        $Length
    )

    return $Destination
}


# ============================================================
# Preliminary checks
# ============================================================

if (-not [Environment]::Is64BitProcess) {
    throw 'Run this script from 64-bit Windows PowerShell.'
}

if (-not (Test-Path -LiteralPath $InputCsv -PathType Leaf)) {
    throw "Input CSV was not found: $InputCsv"
}

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null


# ============================================================
# Import and filter the previous scan results
# ============================================================

Write-Host
Write-Host "Importing: $InputCsv"

$ImportedRows =
    Import-Csv -LiteralPath $InputCsv

$CandidateRows = @(
    $ImportedRows |
        Where-Object {
            $_.RegistryType -eq 'REG_BINARY' -and
            [int] $_.DataLength -eq 136 -and
            $_.DecodedMetadata -eq '0x091' -and
            $_.ValueName -match '^[0-9A-Fa-f]{16}$'
        }
)

if ($CandidateRows.Count -eq 0) {
    throw (
        'No 136-byte REG_BINARY values with metadata 0x091 ' +
        'were found in the input CSV.'
    )
}

Write-Host "Candidate values: $($CandidateRows.Count)"
Write-Host


# ============================================================
# Read the live registry values and group by complete payload
# ============================================================

$BaseKey = $null
$Key     = $null

$ValueRows =
    New-Object 'System.Collections.Generic.List[object]'

$ErrorRows =
    New-Object 'System.Collections.Generic.List[object]'

$PayloadGroups = @{}

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

    $Processed = 0

    foreach ($Candidate in $CandidateRows) {
        $Processed++

        if (
            $Processed -eq 1 -or
            ($Processed % 100) -eq 0
        ) {
            $PercentComplete =
                [Math]::Floor(
                    ($Processed / $CandidateRows.Count) * 100
                )

            Write-Progress `
                -Activity 'Reading and hashing WNF values' `
                -Status (
                    "$Processed of $($CandidateRows.Count) processed"
                ) `
                -PercentComplete $PercentComplete
        }

        $ValueName = $Candidate.ValueName

        try {
            $ValueKind =
                $Key.GetValueKind($ValueName)

            if (
                $ValueKind -ne
                [Microsoft.Win32.RegistryValueKind]::Binary
            ) {
                throw (
                    "Live registry type is $ValueKind rather " +
                    'than REG_BINARY.'
                )
            }

            $Data =
                $Key.GetValue(
                    $ValueName,
                    $null,
                    [Microsoft.Win32.RegistryValueOptions]::
                        DoNotExpandEnvironmentNames
                )

            if ($Data -isnot [byte[]]) {
                throw 'The registry value did not return a byte array.'
            }

            [byte[]] $Data = $Data

            if ($Data.Length -ne 136) {
                throw (
                    "Live data length is $($Data.Length) rather " +
                    'than 136 bytes.'
                )
            }

            $PayloadHash =
                Get-Sha256Hex -Bytes $Data

            $EnumerationIndex = 0

            if (
                -not [int64]::TryParse(
                    [string] $Candidate.EnumerationIndex,
                    [ref] $EnumerationIndex
                )
            ) {
                $EnumerationIndex = -1
            }

            $UniqueId =
                [string] $Candidate.UniqueId

            $ValueRecord = [pscustomobject]@{
                EnumerationIndex = $EnumerationIndex
                ValueName        = $ValueName
                UniqueId         = $UniqueId
                PayloadHash      = $PayloadHash
                DataLength       = $Data.Length
            }

            [void] $ValueRows.Add($ValueRecord)

            if (-not $PayloadGroups.ContainsKey($PayloadHash)) {
                $PayloadGroups[$PayloadHash] =
                    [pscustomobject]@{
                        PayloadHash          = $PayloadHash
                        ValueCount           = 0
                        FirstEnumerationIndex = $EnumerationIndex
                        LastEnumerationIndex  = $EnumerationIndex
                        FirstValueName       = $ValueName
                        LastValueName        = $ValueName
                        SampleData           =
                            [byte[]] ($Data.Clone())
                    }
            }

            $Group = $PayloadGroups[$PayloadHash]

            $Group.ValueCount =
                [int] $Group.ValueCount + 1

            if (
                $Group.FirstEnumerationIndex -lt 0 -or
                (
                    $EnumerationIndex -ge 0 -and
                    $EnumerationIndex -lt
                        $Group.FirstEnumerationIndex
                )
            ) {
                $Group.FirstEnumerationIndex =
                    $EnumerationIndex

                $Group.FirstValueName =
                    $ValueName
            }

            if (
                $EnumerationIndex -gt
                $Group.LastEnumerationIndex
            ) {
                $Group.LastEnumerationIndex =
                    $EnumerationIndex

                $Group.LastValueName =
                    $ValueName
            }
        }
        catch {
            [void] $ErrorRows.Add(
                [pscustomobject]@{
                    EnumerationIndex =
                        $Candidate.EnumerationIndex

                    ValueName =
                        $ValueName

                    Error =
                        $_.Exception.Message
                }
            )
        }
    }

    Write-Progress `
        -Activity 'Reading and hashing WNF values' `
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
# Load current Windows profile information
# ============================================================

$ProfileMap = @{}

try {
    $Profiles =
        Get-CimInstance Win32_UserProfile `
            -ErrorAction Stop

    foreach ($Profile in $Profiles) {
        if ($Profile.SID) {
            $ProfileMap[$Profile.SID] =
                [pscustomobject]@{
                    SID       = $Profile.SID
                    LocalPath = $Profile.LocalPath
                    Loaded    = $Profile.Loaded
                    Special   = $Profile.Special
                }
        }
    }
}
catch {
    Write-Warning (
        'Win32_UserProfile could not be queried: ' +
        $_.Exception.Message
    )
}


# ============================================================
# Parse each distinct payload
# ============================================================

$GroupResults =
    New-Object 'System.Collections.Generic.List[object]'

$GroupAnalysisMap = @{}
$SidSummaryMap    = @{}

$GroupsToAnalyze = @(
    $PayloadGroups.Values |
        Sort-Object `
            @{ Expression = { $_.ValueCount }
               Descending = $true }
)

$GroupNumber = 0

foreach ($Group in $GroupsToAnalyze) {
    $GroupNumber++

    if (
        $GroupNumber -eq 1 -or
        ($GroupNumber % 25) -eq 0
    ) {
        $PercentComplete =
            [Math]::Floor(
                ($GroupNumber / $GroupsToAnalyze.Count) * 100
            )

        Write-Progress `
            -Activity 'Parsing distinct WNF payloads' `
            -Status (
                "$GroupNumber of $($GroupsToAnalyze.Count) groups"
            ) `
            -PercentComplete $PercentComplete
    }

    [byte[]] $Data = $Group.SampleData

    $ParseStatus             = 'Parsed'
    $SecurityDescriptorLength = $null
    $SecurityDescriptorHash   = ''
    $Sddl                     = ''
    $TrailingByteCount        = $null
    $TrailingHex              = ''
    $TrailingUInt32LE         = $null
    $OwnerSid                 = ''
    $GroupSid                 = ''
    $DaclSids                 = @()
    $SaclSids                 = @()
    $AllSids                  = @()
    $AccountSids              = @()
    $MatchedProfileSids       = @()
    $MatchedProfileDetails    = @()
    $UnmatchedAccountSids     = @()
    $ResolvedAccountDetails   = @()

    try {
        $RawDescriptor =
            [System.Security.AccessControl.RawSecurityDescriptor]::
                new(
                    $Data,
                    0
                )

        $SecurityDescriptorLength =
            $RawDescriptor.BinaryLength

        if (
            $SecurityDescriptorLength -le 0 -or
            $SecurityDescriptorLength -gt $Data.Length
        ) {
            throw (
                'Parsed security descriptor length was invalid: ' +
                $SecurityDescriptorLength
            )
        }

        [byte[]] $SecurityDescriptorBytes =
            Copy-ByteRange `
                -Source $Data `
                -Offset 0 `
                -Length $SecurityDescriptorLength

        $SecurityDescriptorHash =
            Get-Sha256Hex `
                -Bytes $SecurityDescriptorBytes

        $TrailingByteCount =
            $Data.Length - $SecurityDescriptorLength

        [byte[]] $TrailingBytes =
            Copy-ByteRange `
                -Source $Data `
                -Offset $SecurityDescriptorLength `
                -Length $TrailingByteCount

        $TrailingHex =
            ConvertTo-HexString -Bytes $TrailingBytes

        if ($TrailingBytes.Length -eq 4) {
            $TrailingUInt32LE =
                [BitConverter]::ToUInt32(
                    $TrailingBytes,
                    0
                )
        }

        $Sddl =
            $RawDescriptor.GetSddlForm(
                [System.Security.AccessControl.AccessControlSections]::
                    All
            )

        if ($null -ne $RawDescriptor.Owner) {
            $OwnerSid =
                $RawDescriptor.Owner.Value
        }

        if ($null -ne $RawDescriptor.Group) {
            $GroupSid =
                $RawDescriptor.Group.Value
        }

        $DaclSids = @(
            Get-SidsFromAcl `
                -Acl $RawDescriptor.DiscretionaryAcl
        )

        $SaclSids = @(
            Get-SidsFromAcl `
                -Acl $RawDescriptor.SystemAcl
        )

        $AllSids = @(
            @(
                $OwnerSid
                $GroupSid
            ) +
            $DaclSids +
            $SaclSids |
                Where-Object { $_ } |
                Sort-Object -Unique
        )

        # Domain and local account SIDs generally use this shape.
        $AccountSids = @(
            $AllSids |
                Where-Object {
                    $_ -match '^S-1-5-21-'
                } |
                Sort-Object -Unique
        )

        $MatchedProfileSids = @(
            $AccountSids |
                Where-Object {
                    $ProfileMap.ContainsKey($_)
                }
        )

        $UnmatchedAccountSids = @(
            $AccountSids |
                Where-Object {
                    -not $ProfileMap.ContainsKey($_)
                }
        )

        $MatchedProfileDetails = @(
            foreach ($Sid in $MatchedProfileSids) {
                $Profile = $ProfileMap[$Sid]

                (
                    "$Sid=$($Profile.LocalPath)" +
                    ";Loaded=$($Profile.Loaded)" +
                    ";Special=$($Profile.Special)"
                )
            }
        )

        if ($ResolveSidNames) {
            $ResolvedAccountDetails = @(
                foreach ($Sid in $AllSids) {
                    $AccountName =
                        Resolve-SidToAccountName -Sid $Sid

                    if ($AccountName) {
                        "$Sid=$AccountName"
                    }
                    else {
                        "$Sid=<unresolved>"
                    }
                }
            )
        }
    }
    catch {
        $ParseStatus =
            "ERROR: $($_.Exception.Message)"
    }

    $GroupResult = [pscustomobject]@{
        PayloadHash              = $Group.PayloadHash
        PayloadHashPrefix        =
            $Group.PayloadHash.Substring(0, 16)

        ValueCount               = $Group.ValueCount
        FirstEnumerationIndex    =
            $Group.FirstEnumerationIndex

        LastEnumerationIndex     =
            $Group.LastEnumerationIndex

        FirstValueName           = $Group.FirstValueName
        LastValueName            = $Group.LastValueName
        DataLength               = $Data.Length
        SecurityDescriptorLength =
            $SecurityDescriptorLength

        SecurityDescriptorHash   =
            $SecurityDescriptorHash

        TrailingByteCount        =
            $TrailingByteCount

        TrailingHex              =
            $TrailingHex

        TrailingUInt32LE         =
            $TrailingUInt32LE

        OwnerSid                 =
            $OwnerSid

        GroupSid                 =
            $GroupSid

        DaclSids                 =
            $DaclSids -join '; '

        SaclSids                 =
            $SaclSids -join '; '

        AllSids                  =
            $AllSids -join '; '

        AccountSids              =
            $AccountSids -join '; '

        MatchedProfileSids       =
            $MatchedProfileSids -join '; '

        MatchedProfileDetails    =
            $MatchedProfileDetails -join ' | '

        UnmatchedAccountSids     =
            $UnmatchedAccountSids -join '; '

        ResolvedAccounts         =
            $ResolvedAccountDetails -join ' | '

        Sddl                     =
            $Sddl

        PayloadHex               =
            ConvertTo-HexString -Bytes $Data

        ParseStatus              =
            $ParseStatus
    }

    [void] $GroupResults.Add($GroupResult)

    $GroupAnalysisMap[$Group.PayloadHash] =
        $GroupResult

    # Build the SID summary. Each SID is counted only once per
    # distinct payload group.
    foreach ($Sid in $AllSids) {
        if (-not $SidSummaryMap.ContainsKey($Sid)) {
            $ProfilePath    = ''
            $ProfileLoaded  = $null
            $ProfileSpecial = $null

            if ($ProfileMap.ContainsKey($Sid)) {
                $ProfilePath =
                    $ProfileMap[$Sid].LocalPath

                $ProfileLoaded =
                    $ProfileMap[$Sid].Loaded

                $ProfileSpecial =
                    $ProfileMap[$Sid].Special
            }

            $AccountName = ''

            if ($ResolveSidNames) {
                $AccountName =
                    Resolve-SidToAccountName -Sid $Sid
            }

            $SidSummaryMap[$Sid] =
                [pscustomobject]@{
                    SID               = $Sid
                    AccountName       = $AccountName
                    ProfilePath       = $ProfilePath
                    ProfileLoaded     = $ProfileLoaded
                    ProfileSpecial    = $ProfileSpecial
                    PayloadGroupCount = 0
                    RegistryValueCount = 0
                }
        }

        $SidRecord =
            $SidSummaryMap[$Sid]

        $SidRecord.PayloadGroupCount =
            [int] $SidRecord.PayloadGroupCount + 1

        $SidRecord.RegistryValueCount =
            [int] $SidRecord.RegistryValueCount +
            [int] $Group.ValueCount
    }
}

Write-Progress `
    -Activity 'Parsing distinct WNF payloads' `
    -Completed


# ============================================================
# Build value-to-payload report
# ============================================================

$ValueResults = foreach ($ValueRecord in $ValueRows) {
    $Analysis =
        $GroupAnalysisMap[$ValueRecord.PayloadHash]

    [pscustomobject]@{
        EnumerationIndex       =
            $ValueRecord.EnumerationIndex

        ValueName              =
            $ValueRecord.ValueName

        UniqueId               =
            $ValueRecord.UniqueId

        PayloadHash            =
            $ValueRecord.PayloadHash

        SecurityDescriptorHash =
            $Analysis.SecurityDescriptorHash

        SecurityDescriptorLength =
            $Analysis.SecurityDescriptorLength

        TrailingHex            =
            $Analysis.TrailingHex

        TrailingUInt32LE       =
            $Analysis.TrailingUInt32LE

        AccountSids            =
            $Analysis.AccountSids

        MatchedProfileSids     =
            $Analysis.MatchedProfileSids

        ParseStatus            =
            $Analysis.ParseStatus
    }
}


# ============================================================
# Export reports
# ============================================================

$PayloadGroupsCsv = Join-Path $OutputDirectory 'Wnf-UserScope-PayloadGroups.csv'

$ValueMapCsv = Join-Path $OutputDirectory 'Wnf-UserScope-ValueMap.csv'

$SidSummaryCsv = Join-Path $OutputDirectory 'Wnf-UserScope-SidSummary.csv'

$ReadErrorsCsv = Join-Path $OutputDirectory 'Wnf-UserScope-ReadErrors.csv'

$SummaryCsv = Join-Path $OutputDirectory 'Wnf-UserScope-Summary.csv'


$GroupResults |
    Sort-Object `
        @{ Expression = { $_.ValueCount }
           Descending = $true } |
    Export-Csv -LiteralPath $PayloadGroupsCsv -NoTypeInformation -Encoding UTF8


$ValueResults |
    Sort-Object EnumerationIndex |
    Export-Csv -LiteralPath $ValueMapCsv -NoTypeInformation -Encoding UTF8


$SidSummaryResults = @(
    $SidSummaryMap.Values |
        Sort-Object `
            @{ Expression = { $_.RegistryValueCount }
               Descending = $true }
)

$SidSummaryResults |
    Export-Csv -LiteralPath $SidSummaryCsv -NoTypeInformation -Encoding UTF8


if ($ErrorRows.Count -gt 0) {
    $ErrorRows |
        Export-Csv -LiteralPath $ReadErrorsCsv -NoTypeInformation -Encoding UTF8
}


$ParsedGroups = @(
    $GroupResults |
        Where-Object {
            $_.ParseStatus -eq 'Parsed'
        }
)

$GroupsWithProfileSids = @(
    $GroupResults |
        Where-Object {
            $_.MatchedProfileSids
        }
)

$DistinctSecurityDescriptors = @(
    $ParsedGroups |
        Where-Object {
            $_.SecurityDescriptorHash
        } |
        Select-Object -ExpandProperty SecurityDescriptorHash -Unique
).Count


$Summary = [pscustomobject]@{
    CheckedAt                   = Get-Date
    InputCsv                    = $InputCsv
    RegistryPath               = $RegistryDisplayPath
    CandidateValuesFromCsv      = $CandidateRows.Count
    LiveValuesReadSuccessfully  = $ValueRows.Count
    ReadErrors                  = $ErrorRows.Count
    DistinctCompletePayloads    = $PayloadGroups.Count
    ParsedPayloadGroups         = $ParsedGroups.Count
    ParseErrorGroups            =
        $PayloadGroups.Count - $ParsedGroups.Count

    DistinctSecurityDescriptors =
        $DistinctSecurityDescriptors

    GroupsContainingProfileSids =
        $GroupsWithProfileSids.Count

    DistinctSidsFound           =
        $SidSummaryResults.Count

    SidNameResolutionEnabled    =
        [bool] $ResolveSidNames
}

$Summary |
    Export-Csv -LiteralPath $SummaryCsv -NoTypeInformation -Encoding UTF8


# ============================================================
# Display summary
# ============================================================

Write-Host
Write-Host 'Analysis completed.'
Write-Host
Write-Host (
    "Candidate values:             $($CandidateRows.Count)"
)
Write-Host (
    "Live values read:             $($ValueRows.Count)"
)
Write-Host (
    "Read errors:                  $($ErrorRows.Count)"
)
Write-Host (
    "Distinct complete payloads:   $($PayloadGroups.Count)"
)
Write-Host (
    "Parsed payload groups:        $($ParsedGroups.Count)"
)
Write-Host (
    "Distinct security descriptors: " +
    $DistinctSecurityDescriptors
)
Write-Host (
    "Groups matching profiles:     " +
    $GroupsWithProfileSids.Count
)
Write-Host (
    "Distinct SIDs found:          " +
    $SidSummaryResults.Count
)
Write-Host
Write-Host "Output directory: $OutputDirectory"
Write-Host
Write-Host 'Reports:'
Write-Host "  $PayloadGroupsCsv"
Write-Host "  $ValueMapCsv"
Write-Host "  $SidSummaryCsv"
Write-Host "  $SummaryCsv"

if ($ErrorRows.Count -gt 0) {
    Write-Host "  $ReadErrorsCsv"
}

Write-Host
Write-Host 'Largest payload groups:'

$GroupResults |
    Sort-Object `
        @{ Expression = { $_.ValueCount }
           Descending = $true } |
    Select-Object -First 20 `
        ValueCount,
        PayloadHashPrefix,
        SecurityDescriptorLength,
        TrailingUInt32LE,
        AccountSids,
        MatchedProfileSids,
        ParseStatus |
    Format-Table -Wrap -AutoSize
