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
    Collects a best-effort redacted AppX and AppReadiness diagnostic package
    from Windows Server 2019.

.DESCRIPTION
    Collects AppReadiness, AppX deployment, AppModel, shell, Search,
    authentication, StateRepository, User Profile Service, OneDrive updater,
    Application, and System event data when available. It also records
    event-log retention,
    relevant service state, AppX and provisioned-package state, per-profile
    LocalAppData\Packages counts, and AppRepository resiliency-file details.

    The exported data is redacted on a best-effort basis. SIDs, GUIDs, computer
    and domain names, profile names and paths, and UPN/email-style account names
    are replaced or omitted where supported. Token mappings are not exported,
    and a post-export validation scan checks CSV output for identifiers that
    should have been removed.

    This script is read-only. It does not modify services, packages, profiles,
    registry values, event-log settings, or files outside its output directory.

.NOTES
    Run from elevated 64-bit Windows PowerShell 5.1 on Windows Server 2019.

    Redaction is best-effort. Review generated output before sharing it outside
    the intended server or support team.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 90)]
    [int] $Days = 7,

    [string] $OutputRoot = (
        Join-Path $env:ProgramData 'WindowsWnfRegistryBloatToolkit'
    )
)

$ErrorActionPreference = 'Stop'
$StartTime = (Get-Date).AddDays(-$Days)
$OperatingSystem = Get-CimInstance Win32_OperatingSystem
$LastBootUpTime = [datetime] $OperatingSystem.LastBootUpTime
$LastBootWithinRequestedWindow = ($LastBootUpTime -ge $StartTime)
$PostBootStartTime = if ($LastBootWithinRequestedWindow) {
    $LastBootUpTime
}
else {
    $StartTime
}
$Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$OutputDirectory = Join-Path $OutputRoot "AppX-Readiness-Audit-Redacted-$Timestamp"

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null


# ============================================================
# Redaction setup
# ============================================================

$script:SidTokens = @{}
$script:NextUnknownSidToken = 1
$script:GuidTokens = @{}
$script:NextGuidTokenByType = @{
    'GUID'             = 1
    'TENANT-GUID'      = 1
    'CLIENT-GUID'      = 1
    'CORRELATION-GUID' = 1
    'ACTIVITY-GUID'    = 1
    'RELATED-GUID'     = 1
}
$script:ProfilePathTokens = @{}
$script:ProfileNameTokens = @{}
$script:QualifiedAccountTokens = @{}
$script:AmbiguousProfileNames = @{}
$script:EnvironmentIdentifierTokens = @{}
$script:HostTokens = @{}
$script:NextHostToken = 1
$script:UnknownProfileTokens = @{}
$script:NextUnknownProfileToken = 1

function Add-ProfileNameToken {
    param(
        [AllowNull()][string] $Name,
        [Parameter(Mandatory)][string] $Token
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return
    }

    if ($script:AmbiguousProfileNames.ContainsKey($Name)) {
        return
    }

    if ($script:ProfileNameTokens.ContainsKey($Name)) {
        if ([string] $script:ProfileNameTokens[$Name] -ne $Token) {
            $script:ProfileNameTokens.Remove($Name)
            $script:AmbiguousProfileNames[$Name] = $true
        }
        return
    }

    $script:ProfileNameTokens[$Name] = $Token
}

function Get-UnmappedProfileToken {
    param([Parameter(Mandatory)][string] $Name)

    $Normalized = $Name.ToUpperInvariant()

    if ($script:UnknownProfileTokens.ContainsKey($Normalized)) {
        return [string] $script:UnknownProfileTokens[$Normalized]
    }

    $Token =
        'PROFILE-UNK-{0:D3}' -f $script:NextUnknownProfileToken

    $script:NextUnknownProfileToken++
    $script:UnknownProfileTokens[$Normalized] = $Token

    return $Token
}

function Get-RedactedHostToken {
    param([Parameter(Mandatory)][string] $HostName)

    $Normalized = $HostName.ToUpperInvariant()

    if ($script:HostTokens.ContainsKey($Normalized)) {
        return [string] $script:HostTokens[$Normalized]
    }

    $Token = 'HOST-{0:D3}' -f $script:NextHostToken
    $script:NextHostToken++
    $script:HostTokens[$Normalized] = $Token

    return $Token
}

$KnownProfiles = @(
    Get-CimInstance Win32_UserProfile |
        Where-Object {
            -not $_.Special -and
            -not [string]::IsNullOrWhiteSpace($_.LocalPath)
        } |
        Sort-Object SID, LocalPath
)

$ProfileNumber = 1

foreach ($Profile in $KnownProfiles) {
    $ProfileToken = $null

    if (
        -not [string]::IsNullOrWhiteSpace($Profile.SID) -and
        $script:SidTokens.ContainsKey([string] $Profile.SID)
    ) {
        $ProfileToken = [string] $script:SidTokens[[string] $Profile.SID]
    }
    else {
        $ProfileToken = 'PROFILE-{0:D3}' -f $ProfileNumber
        $ProfileNumber++

        if (-not [string]::IsNullOrWhiteSpace($Profile.SID)) {
            $script:SidTokens[[string] $Profile.SID] = $ProfileToken
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($Profile.LocalPath)) {
        $script:ProfilePathTokens[[string] $Profile.LocalPath] =
            $ProfileToken

        Add-ProfileNameToken `
            -Name (Split-Path -Leaf $Profile.LocalPath) `
            -Token $ProfileToken
    }

    # Link the SID to its translated DOMAIN\user representation when Windows
    # can resolve it. This keeps PackageUserInformation, profile paths, and
    # event-log account references on the same PROFILE token.
    if (-not [string]::IsNullOrWhiteSpace($Profile.SID)) {
        try {
            $SidObject = New-Object `
                System.Security.Principal.SecurityIdentifier `
                -ArgumentList ([string] $Profile.SID)

            $NtAccount = $SidObject.Translate(
                [System.Security.Principal.NTAccount]
            ).Value

            if (-not [string]::IsNullOrWhiteSpace($NtAccount)) {
                $script:QualifiedAccountTokens[$NtAccount] = $ProfileToken

                $AccountLeaf = ($NtAccount -split '\\', 2)[-1]
                Add-ProfileNameToken `
                    -Name $AccountLeaf `
                    -Token $ProfileToken
            }
        }
        catch {
        }
    }
}

# Typed environment tokens retain useful context without publishing values.
foreach ($EnvironmentIdentifier in @(
    [pscustomobject]@{
        Value = $env:COMPUTERNAME
        Token = 'SERVER-001'
    }
    [pscustomobject]@{
        Value = $env:USERDNSDOMAIN
        Token = 'DNS-DOMAIN-001'
    }
    [pscustomobject]@{
        Value = $env:USERDOMAIN
        Token = 'DOMAIN-001'
    }
)) {
    if (
        -not [string]::IsNullOrWhiteSpace($EnvironmentIdentifier.Value) -and
        -not $script:EnvironmentIdentifierTokens.ContainsKey(
            [string] $EnvironmentIdentifier.Value
        )
    ) {
        $script:EnvironmentIdentifierTokens[
            [string] $EnvironmentIdentifier.Value
        ] = [string] $EnvironmentIdentifier.Token
    }
}

function Get-RedactedSidToken {
    param(
        [AllowNull()]
        [string] $Sid
    )

    if ([string]::IsNullOrWhiteSpace($Sid)) {
        return ''
    }

    if ($script:SidTokens.ContainsKey($Sid)) {
        return [string] $script:SidTokens[$Sid]
    }

    $Token =
        'SID-{0:D3}' -f $script:NextUnknownSidToken

    $script:NextUnknownSidToken++
    $script:SidTokens[$Sid] = $Token

    return $Token
}

function Get-RedactedGuidToken {
    param(
        [AllowNull()][string] $GuidText,
        [string] $TokenType = 'GUID'
    )

    if ([string]::IsNullOrWhiteSpace($GuidText)) {
        return ''
    }

    $Normalized =
        $GuidText.Trim().Trim([char[]] '{}').ToUpperInvariant()

    if ($script:GuidTokens.ContainsKey($Normalized)) {
        return [string] $script:GuidTokens[$Normalized]
    }

    if (-not $script:NextGuidTokenByType.ContainsKey($TokenType)) {
        $script:NextGuidTokenByType[$TokenType] = 1
    }

    $Token = '{0}-{1:D5}' -f `
        $TokenType, `
        ([int] $script:NextGuidTokenByType[$TokenType])

    $script:NextGuidTokenByType[$TokenType] =
        [int] $script:NextGuidTokenByType[$TokenType] + 1

    $script:GuidTokens[$Normalized] = $Token

    return $Token
}

function Protect-DiagnosticText {
    param(
        [AllowNull()]
        [string] $Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $Text
    }

    $Protected = [string] $Text

    # Replace longest profile paths first. This prevents C:\Users\user from
    # partially replacing C:\Users\user.DOMAIN and breaking correlation.
    foreach (
        $ProfilePath in $script:ProfilePathTokens.Keys |
            Sort-Object { $_.Length } -Descending
    ) {
        $Token = $script:ProfilePathTokens[$ProfilePath]

        $Protected = [regex]::Replace(
            $Protected,
            [regex]::Escape($ProfilePath),
            ('C:\Users\<{0}>' -f $Token),
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    }

    # Replace exact translated DOMAIN\user accounts before leaf-name matching.
    foreach (
        $QualifiedAccount in $script:QualifiedAccountTokens.Keys |
            Sort-Object { $_.Length } -Descending
    ) {
        $Token = $script:QualifiedAccountTokens[$QualifiedAccount]

        $Protected = [regex]::Replace(
            $Protected,
            '(?<![A-Za-z0-9._-])' +
                [regex]::Escape($QualifiedAccount) +
                '(?![A-Za-z0-9._-])',
            ('<{0}>' -f $Token),
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    }

    # Replace known account/profile leaf names with the profile token linked
    # to their SID. Ambiguous names are intentionally excluded from this map.
    foreach (
        $ProfileName in $script:ProfileNameTokens.Keys |
            Sort-Object { $_.Length } -Descending
    ) {
        $Token = $script:ProfileNameTokens[$ProfileName]

        $AccountPattern =
            '(?<![A-Za-z0-9._-])' +
            '(?:[A-Za-z0-9._-]+\\)?' +
            [regex]::Escape($ProfileName) +
            '(?![A-Za-z0-9._-])'

        $Protected = [regex]::Replace(
            $Protected,
            $AccountPattern,
            ('<{0}>' -f $Token),
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    }

    # Redact qualified accounts for the current domain or computer even if
    # the account does not have a local Win32_UserProfile entry.
    foreach (
        $AccountAuthority in @(
            $env:USERDOMAIN
            $env:COMPUTERNAME
        )
    ) {
        if (-not [string]::IsNullOrWhiteSpace($AccountAuthority)) {
            $QualifiedAccountPattern =
                '(?<![A-Za-z0-9._-])' +
                [regex]::Escape($AccountAuthority) +
                '\\[A-Za-z0-9._$-]+' +
                '(?![A-Za-z0-9._-])'

            $Protected = [regex]::Replace(
                $Protected,
                $QualifiedAccountPattern,
                '<ACCOUNT>',
                [Text.RegularExpressions.RegexOptions]::IgnoreCase
            )
        }
    }

    # Package/event data sometimes contains qualified accounts inside square
    # brackets from authorities other than the collector's current domain.
    $Protected = [regex]::Replace(
        $Protected,
        '\[(?<Account>[A-Za-z0-9._-]+\\[A-Za-z0-9._$-]+)\]',
        '[<ACCOUNT>]',
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    # Do not require a trailing word boundary: AppRepository filenames place
    # an underscore immediately after the SID, and underscore is a word char.
    $SidPattern =
        '(?<![A-Za-z0-9])S-\d-\d+(?:-\d+){1,}(?!\d)'

    $Protected = [regex]::Replace(
        $Protected,
        $SidPattern,
        {
            param($Match)

            return '<{0}>' -f (
                Get-RedactedSidToken -Sid $Match.Value
            )
        },
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    $GuidPattern =
        '(?<![0-9A-Fa-f])\{?' +
        '[0-9A-Fa-f]{8}-' +
        '[0-9A-Fa-f]{4}-' +
        '[0-9A-Fa-f]{4}-' +
        '[0-9A-Fa-f]{4}-' +
        '[0-9A-Fa-f]{12}' +
        '\}?(?![0-9A-Fa-f])'

    # Preserve the semantic role of common AAD GUIDs where the surrounding
    # text identifies it, while keeping stable tokens for repeated values.
    $Protected = [regex]::Replace(
        $Protected,
        '(?<Prefix>https://login\.microsoftonline\.com/)(?<Guid>' +
            $GuidPattern + ')',
        {
            param($Match)

            return $Match.Groups['Prefix'].Value + (
                '<{0}>' -f (
                    Get-RedactedGuidToken `
                        -GuidText $Match.Groups['Guid'].Value `
                        -TokenType 'TENANT-GUID'
                )
            )
        },
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    foreach ($GuidContext in @(
        [pscustomobject]@{
            Pattern = '(?<Prefix>\bclient(?:\s+id)?\s*[:=]\s*)(?<Guid>' +
                $GuidPattern + ')'
            Type = 'CLIENT-GUID'
        }
        [pscustomobject]@{
            Pattern = '(?<Prefix>\bcorrelation(?:\s+id)?\s*[:=]\s*)(?<Guid>' +
                $GuidPattern + ')'
            Type = 'CORRELATION-GUID'
        }
    )) {
        $TokenType = $GuidContext.Type

        $Protected = [regex]::Replace(
            $Protected,
            $GuidContext.Pattern,
            {
                param($Match)

                return $Match.Groups['Prefix'].Value + (
                    '<{0}>' -f (
                        Get-RedactedGuidToken `
                            -GuidText $Match.Groups['Guid'].Value `
                            -TokenType $TokenType
                    )
                )
            },
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    }

    # Replace any remaining GUIDs consistently.
    $Protected = [regex]::Replace(
        $Protected,
        $GuidPattern,
        {
            param($Match)

            return '<{0}>' -f (
                Get-RedactedGuidToken -GuidText $Match.Value
            )
        },
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    $Protected = [regex]::Replace(
        $Protected,
        '\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b',
        '<ACCOUNT>',
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    # Redact unknown user-profile paths that were not represented by
    # Win32_UserProfile at collection time, while preserving stable correlation.
    $Protected = [regex]::Replace(
        $Protected,
        '(?i)C:\\Users\\(?<Name>(?!Public(?:\\|$)|Default(?: User)?(?:\\|$)|All Users(?:\\|$))[^\\\s"''<>|,;]+)',
        {
            param($Match)

            $Token = Get-UnmappedProfileToken `
                -Name $Match.Groups['Name'].Value

            return 'C:\Users\<{0}>' -f $Token
        }
    )

    # Redact UNC host names not already covered by known environment tokens.
    $Protected = [regex]::Replace(
        $Protected,
        '(?<!\\)\\\\(?<Host>[A-Za-z0-9][A-Za-z0-9._-]{0,252})\\',
        {
            param($Match)

            $Token = Get-RedactedHostToken `
                -HostName $Match.Groups['Host'].Value

            return '\\<{0}>\' -f $Token
        },
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    # Replace known machine/domain identifiers with typed tokens. Sort by
    # length so a DNS domain is not partially replaced by a shorter domain.
    foreach (
        $Identifier in $script:EnvironmentIdentifierTokens.Keys |
            Sort-Object { $_.Length } -Descending
    ) {
        $Protected = [regex]::Replace(
            $Protected,
            [regex]::Escape($Identifier),
            ('<{0}>' -f $script:EnvironmentIdentifierTokens[$Identifier]),
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    }

    return $Protected
}

function ConvertTo-SafeFileName {
    param([Parameter(Mandatory)][string] $Text)
    return ($Text -replace '[\\/:*?"<>|]', '_')
}

function Get-FirstRegexMatch {
    param(
        [AllowNull()][string] $Text,
        [Parameter(Mandatory)][string] $Pattern
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $null
    }

    $Match = [regex]::Match(
        $Text,
        $Pattern,
        [Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    if ($Match.Success) {
        return $Match.Value
    }

    return $null
}

function Get-AllRegexMatches {
    param(
        [AllowNull()][string] $Text,
        [Parameter(Mandatory)][string] $Pattern
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    return (
        [regex]::Matches(
            $Text,
            $Pattern,
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        ) |
        ForEach-Object { $_.Value.ToUpperInvariant() } |
        Sort-Object -Unique
    ) -join ';'
}

function Get-EventErrorCodes {
    param(
        [AllowNull()][string] $Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $Codes = New-Object 'System.Collections.Generic.List[string]'

    foreach (
        $Match in [regex]::Matches(
            $Text,
            '\b0x[0-9A-Fa-f]{8}\b',
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    ) {
        [void] $Codes.Add($Match.Value.ToUpperInvariant())
    }

    foreach (
        $Match in [regex]::Matches(
            $Text,
            '\b(?:hr|hresult)\s*[:=]?\s*(?<Code>[0-9A-Fa-f]{8})\b',
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
    ) {
        [void] $Codes.Add(
            ('0X{0}' -f $Match.Groups['Code'].Value.ToUpperInvariant())
        )
    }

    return (
        $Codes |
        Sort-Object -Unique
    ) -join ';'
}

function Convert-EventRecord {
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Eventing.Reader.EventRecord] $Event
    )

    $Message = $null

    try {
        $Message = Protect-DiagnosticText -Text $Event.Message
    }
    catch {
        $Message = '<Message rendering failed>'
    }

    $ActivityId = $null
    $RelatedActivityId = $null
    $ProcessId = $null
    $ThreadId = $null

    try {
        $Xml = [xml] $Event.ToXml()

        $Correlation = $Xml.Event.System.Correlation

        if ($null -ne $Correlation) {
            $RawActivityId = [string] $Correlation.ActivityID
            $RawRelatedActivityId = [string] $Correlation.RelatedActivityID

            if (-not [string]::IsNullOrWhiteSpace($RawActivityId)) {
                $ActivityId = '<{0}>' -f (
                    Get-RedactedGuidToken `
                        -GuidText $RawActivityId `
                        -TokenType 'ACTIVITY-GUID'
                )
            }

            if (-not [string]::IsNullOrWhiteSpace($RawRelatedActivityId)) {
                $RelatedActivityId = '<{0}>' -f (
                    Get-RedactedGuidToken `
                        -GuidText $RawRelatedActivityId `
                        -TokenType 'RELATED-GUID'
                )
            }
        }

        $Execution = $Xml.Event.System.Execution

        if ($null -ne $Execution) {
            $ProcessId = [string] $Execution.ProcessID
            $ThreadId = [string] $Execution.ThreadID
        }
    }
    catch {
    }

    $PackageName = Get-FirstRegexMatch `
        -Text $Message `
        -Pattern '\bMicrosoft\.[A-Za-z0-9.-]+(?:_[A-Za-z0-9.\-]+)*\b'

    $ErrorCodes = Get-EventErrorCodes -Text $Message

    [pscustomobject]@{
        TimeCreated        = $Event.TimeCreated
        RecordId          = $Event.RecordId
        LogName           = $Event.LogName
        ProviderName      = $Event.ProviderName
        EventId           = $Event.Id
        Level             = $Event.LevelDisplayName
        TaskDisplayName   = $Event.TaskDisplayName
        OpcodeDisplayName = $Event.OpcodeDisplayName
        ActivityId        = $ActivityId
        RelatedActivityId = $RelatedActivityId
        ProcessId         = $ProcessId
        ThreadId          = $ThreadId
        PackageName       = $PackageName
        ErrorCodes        = $ErrorCodes
        Message           = $Message
    }
}

function Export-EventChannel {
    param(
        [Parameter(Mandatory)][string] $LogName,
        [Parameter(Mandatory)][datetime] $FromTime,
        [Parameter(Mandatory)][string] $DestinationDirectory
    )

    $LogInfo = Get-WinEvent -ListLog $LogName -ErrorAction SilentlyContinue

    if ($null -eq $LogInfo) {
        return [pscustomobject]@{
            LogName       = $LogName
            Exists        = $false
            Enabled       = $false
            RecordCount   = $null
            ExportedCount = 0
            CsvPath       = ''
            Error         = 'Channel not present'
        }
    }

    $Events = @()

    try {
        $Events = @(
            Get-WinEvent -FilterHashtable @{
                LogName   = $LogName
                StartTime = $FromTime
            } -ErrorAction Stop
        )
    }
    catch {
        if (
            $_.Exception.Message -notmatch
                'No events were found that match the specified selection criteria'
        ) {
            return [pscustomobject]@{
                LogName       = $LogName
                Exists        = $true
                Enabled       = $LogInfo.IsEnabled
                RecordCount   = $LogInfo.RecordCount
                ExportedCount = 0
                CsvPath       = ''
                Error         = Protect-DiagnosticText -Text $_.Exception.Message
            }
        }
    }

    $Rows = @(
        foreach ($Event in $Events) {
            Convert-EventRecord -Event $Event
        }
    )

    $SafeName = ConvertTo-SafeFileName -Text $LogName
    $CsvPath = Join-Path $DestinationDirectory "$SafeName.csv"

    $Rows |
        Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8

    foreach ($Row in $Rows) {
        [void] $script:AllEventRows.Add($Row)
    }

    return [pscustomobject]@{
        LogName       = $LogName
        Exists        = $true
        Enabled       = $LogInfo.IsEnabled
        RecordCount   = $LogInfo.RecordCount
        ExportedCount = $Rows.Count
        CsvPath       = Split-Path -Leaf $CsvPath
        Error         = ''
    }
}

function Get-OldestNewestEvent {
    param([Parameter(Mandatory)][string] $LogName)

    $Oldest = $null
    $Newest = $null

    try {
        $Oldest = Get-WinEvent -LogName $LogName -Oldest -MaxEvents 1 -ErrorAction Stop
    }
    catch {
    }

    try {
        $Newest = Get-WinEvent -LogName $LogName -MaxEvents 1 -ErrorAction Stop
    }
    catch {
    }

    [pscustomobject]@{
        OldestRetained = if ($null -ne $Oldest) { $Oldest.TimeCreated } else { $null }
        NewestRetained = if ($null -ne $Newest) { $Newest.TimeCreated } else { $null }
    }
}

$TargetLogs = @(
    'Microsoft-Windows-AppReadiness/Admin'
    'Microsoft-Windows-AppReadiness/Operational'
    'Microsoft-Windows-AppXDeployment/Operational'
    'Microsoft-Windows-AppXDeploymentServer/Operational'
    'Microsoft-Windows-AppModel-Runtime/Admin'
    'Microsoft-Windows-AppModel-State/Admin'
    'Microsoft-Windows-TWinUI/Operational'
    'Microsoft-Windows-Shell-Core/Operational'
    'Microsoft-Windows-Search/Operational'
    'Microsoft-Windows-StateRepository/Operational'
    'Microsoft-Windows-AAD/Operational'
    'Microsoft-Windows-WebAuth/Operational'
    'Microsoft-Windows-CloudExperienceHost/Operational'
    'Microsoft-Windows-User Profile Service/Operational'
)

$script:AllEventRows = New-Object 'System.Collections.Generic.List[object]'
$ChannelResults = New-Object 'System.Collections.Generic.List[object]'

foreach ($LogName in $TargetLogs) {
    Write-Host "Collecting: $LogName"

    $Result = Export-EventChannel `
        -LogName $LogName `
        -FromTime $StartTime `
        -DestinationDirectory $OutputDirectory

    [void] $ChannelResults.Add($Result)
}

$RelevantPattern =
    'AppReadiness|' +
    'AppX|' +
    'AppContainer|' +
    'Cortana|' +
    'SearchUI|' +
    'SearchIndexer|' +
    'ShellExperienceHost|' +
    'StartMenuExperienceHost|' +
    'AAD\.BrokerPlugin|' +
    'TokenBroker|' +
    'RuntimeBroker|' +
    'backgroundTaskHost|' +
    'BrokerInfrastructure|' +
    'SystemEventsBroker|' +
    'StateRepository|' +
    'OneDriveUpdaterService|' +
    'OneDrive(?:\.exe)?'

foreach ($StandardLog in @('Application', 'System')) {
    Write-Host "Collecting relevant events from: $StandardLog"

    $MatchingEvents = @()

    try {
        $MatchingEvents = @(
            Get-WinEvent -FilterHashtable @{
                LogName   = $StandardLog
                StartTime = $StartTime
            } -ErrorAction Stop |
            Where-Object {
                $_.ProviderName -match $RelevantPattern -or
                $_.Message -match $RelevantPattern
            }
        )
    }
    catch {
        if (
            $_.Exception.Message -notmatch
                'No events were found that match the specified selection criteria'
        ) {
            Write-Warning "Could not fully query $StandardLog`: $($_.Exception.Message)"
        }
    }

    $Rows = @(
        foreach ($Event in $MatchingEvents) {
            Convert-EventRecord -Event $Event
        }
    )

    $CsvPath = Join-Path $OutputDirectory "$StandardLog-Relevant.csv"

    $Rows |
        Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8

    foreach ($Row in $Rows) {
        [void] $script:AllEventRows.Add($Row)
    }

    [void] $ChannelResults.Add(
        [pscustomobject]@{
            LogName       = "$StandardLog (filtered)"
            Exists        = $true
            Enabled       = $true
            RecordCount   = $null
            ExportedCount = $Rows.Count
            CsvPath       = Split-Path -Leaf $CsvPath
            Error         = ''
        }
    )
}

# Windows PowerShell 5.1 can throw "Argument types do not match" when
# the array-subexpression operator is used directly against a generic List[object].
# ToArray() performs the conversion without invoking that binder path.
$AllEvents = $script:AllEventRows.ToArray()

$AllEvents |
    Sort-Object TimeCreated |
    Export-Csv -LiteralPath (
        Join-Path $OutputDirectory 'All-Relevant-Events.csv'
    ) -NoTypeInformation -Encoding UTF8

$AllEvents |
    Group-Object LogName, ProviderName, EventId, Level |
    ForEach-Object {
        $Example = $_.Group | Select-Object -First 1
        $Ordered = $_.Group | Sort-Object TimeCreated

        [pscustomobject]@{
            LogName       = $Example.LogName
            ProviderName  = $Example.ProviderName
            EventId       = $Example.EventId
            Level         = $Example.Level
            Count         = $_.Count
            FirstObserved = $Ordered[0].TimeCreated
            LastObserved  = $Ordered[-1].TimeCreated
        }
    } |
    Sort-Object Count -Descending |
    Export-Csv -LiteralPath (
        Join-Path $OutputDirectory 'Summary-ByLog-EventId.csv'
    ) -NoTypeInformation -Encoding UTF8

$ErrorCodeRows = foreach ($Event in $AllEvents) {
    if ([string]::IsNullOrWhiteSpace($Event.ErrorCodes)) {
        continue
    }

    foreach ($Code in $Event.ErrorCodes -split ';') {
        [pscustomobject]@{
            ErrorCode    = $Code
            LogName      = $Event.LogName
            ProviderName = $Event.ProviderName
            EventId      = $Event.EventId
            PackageName = $Event.PackageName
            TimeCreated = $Event.TimeCreated
        }
    }
}

$ErrorCodeRows |
    Group-Object ErrorCode, LogName, ProviderName, EventId |
    ForEach-Object {
        $Example = $_.Group | Select-Object -First 1
        $Ordered = $_.Group | Sort-Object TimeCreated

        [pscustomobject]@{
            ErrorCode     = $Example.ErrorCode
            LogName       = $Example.LogName
            ProviderName  = $Example.ProviderName
            EventId       = $Example.EventId
            Count         = $_.Count
            FirstObserved = $Ordered[0].TimeCreated
            LastObserved  = $Ordered[-1].TimeCreated
        }
    } |
    Sort-Object Count -Descending |
    Export-Csv -LiteralPath (
        Join-Path $OutputDirectory 'Summary-ByErrorCode.csv'
    ) -NoTypeInformation -Encoding UTF8

$AllEvents |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_.PackageName) } |
    Group-Object PackageName, EventId, ErrorCodes |
    ForEach-Object {
        $Example = $_.Group | Select-Object -First 1
        $Ordered = $_.Group | Sort-Object TimeCreated

        [pscustomobject]@{
            PackageName   = $Example.PackageName
            EventId       = $Example.EventId
            ErrorCodes    = $Example.ErrorCodes
            Count         = $_.Count
            FirstObserved = $Ordered[0].TimeCreated
            LastObserved  = $Ordered[-1].TimeCreated
        }
    } |
    Sort-Object Count -Descending |
    Export-Csv -LiteralPath (
        Join-Path $OutputDirectory 'Summary-ByPackage.csv'
    ) -NoTypeInformation -Encoding UTF8

# Keep the original requested-window summaries above, and also emit a second
# view bounded by the most recent boot. When the boot predates the requested
# collection window, the post-boot view is necessarily truncated to StartTime.
$PostBootEvents = @(
    $AllEvents |
        Where-Object { $_.TimeCreated -ge $PostBootStartTime }
)

$PostBootEvents |
    Sort-Object TimeCreated |
    Export-Csv -LiteralPath (
        Join-Path $OutputDirectory 'PostBoot-Relevant-Events.csv'
    ) -NoTypeInformation -Encoding UTF8

$PostBootEvents |
    Group-Object LogName, ProviderName, EventId, Level |
    ForEach-Object {
        $Example = $_.Group | Select-Object -First 1
        $Ordered = $_.Group | Sort-Object TimeCreated

        [pscustomobject]@{
            LogName       = $Example.LogName
            ProviderName  = $Example.ProviderName
            EventId       = $Example.EventId
            Level         = $Example.Level
            Count         = $_.Count
            FirstObserved = $Ordered[0].TimeCreated
            LastObserved  = $Ordered[-1].TimeCreated
        }
    } |
    Sort-Object Count -Descending |
    Export-Csv -LiteralPath (
        Join-Path $OutputDirectory 'Summary-PostBoot-ByLog-EventId.csv'
    ) -NoTypeInformation -Encoding UTF8

$PostBootErrorCodeRows = foreach ($Event in $PostBootEvents) {
    if ([string]::IsNullOrWhiteSpace($Event.ErrorCodes)) {
        continue
    }

    foreach ($Code in $Event.ErrorCodes -split ';') {
        [pscustomobject]@{
            ErrorCode    = $Code
            LogName      = $Event.LogName
            ProviderName = $Event.ProviderName
            EventId      = $Event.EventId
            PackageName  = $Event.PackageName
            TimeCreated  = $Event.TimeCreated
        }
    }
}

$PostBootErrorCodeRows |
    Group-Object ErrorCode, LogName, ProviderName, EventId |
    ForEach-Object {
        $Example = $_.Group | Select-Object -First 1
        $Ordered = $_.Group | Sort-Object TimeCreated

        [pscustomobject]@{
            ErrorCode     = $Example.ErrorCode
            LogName       = $Example.LogName
            ProviderName  = $Example.ProviderName
            EventId       = $Example.EventId
            Count         = $_.Count
            FirstObserved = $Ordered[0].TimeCreated
            LastObserved  = $Ordered[-1].TimeCreated
        }
    } |
    Sort-Object Count -Descending |
    Export-Csv -LiteralPath (
        Join-Path $OutputDirectory 'Summary-PostBoot-ByErrorCode.csv'
    ) -NoTypeInformation -Encoding UTF8

$PostBootEvents |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_.PackageName) } |
    Group-Object PackageName, EventId, ErrorCodes |
    ForEach-Object {
        $Example = $_.Group | Select-Object -First 1
        $Ordered = $_.Group | Sort-Object TimeCreated

        [pscustomobject]@{
            PackageName   = $Example.PackageName
            EventId       = $Example.EventId
            ErrorCodes    = $Example.ErrorCodes
            Count         = $_.Count
            FirstObserved = $Ordered[0].TimeCreated
            LastObserved  = $Ordered[-1].TimeCreated
        }
    } |
    Sort-Object Count -Descending |
    Export-Csv -LiteralPath (
        Join-Path $OutputDirectory 'Summary-PostBoot-ByPackage.csv'
    ) -NoTypeInformation -Encoding UTF8

@(
    [pscustomobject]@{
        Scope            = 'RequestedWindow'
        WindowStart      = $StartTime
        WindowEnd        = Get-Date
        EventCount       = $AllEvents.Count
        BoundaryComplete = $true
        Note             = 'Full requested collection window.'
    }
    [pscustomobject]@{
        Scope            = 'PostBoot'
        WindowStart      = $PostBootStartTime
        WindowEnd        = Get-Date
        EventCount       = $PostBootEvents.Count
        BoundaryComplete = $LastBootWithinRequestedWindow
        Note             = if ($LastBootWithinRequestedWindow) {
            'Complete from the most recent boot.'
        }
        else {
            'Most recent boot predates StartTime; post-boot view is truncated to the requested collection window.'
        }
    }
) |
    Export-Csv -LiteralPath (
        Join-Path $OutputDirectory 'Event-Window-Summary.csv'
    ) -NoTypeInformation -Encoding UTF8

$LogRetentionRows = foreach ($LogName in $TargetLogs) {
    $Info = Get-WinEvent -ListLog $LogName -ErrorAction SilentlyContinue

    if ($null -eq $Info) {
        [pscustomobject]@{
            LogName        = $LogName
            Present        = $false
            Enabled        = $false
            RecordCount    = $null
            MaximumSizeMB  = $null
            LogMode        = ''
            OldestRetained = $null
            NewestRetained = $null
        }
        continue
    }

    $Range = Get-OldestNewestEvent -LogName $LogName

    [pscustomobject]@{
        LogName        = $LogName
        Present        = $true
        Enabled        = $Info.IsEnabled
        RecordCount    = $Info.RecordCount
        MaximumSizeMB  = [Math]::Round($Info.MaximumSizeInBytes / 1MB, 2)
        LogMode        = $Info.LogMode
        OldestRetained = $Range.OldestRetained
        NewestRetained = $Range.NewestRetained
    }
}

$LogRetentionRows |
    Export-Csv -LiteralPath (
        Join-Path $OutputDirectory 'EventLog-Retention.csv'
    ) -NoTypeInformation -Encoding UTF8

$ChannelResults |
    Export-Csv -LiteralPath (
        Join-Path $OutputDirectory 'EventLog-CollectionStatus.csv'
    ) -NoTypeInformation -Encoding UTF8

$RelevantServiceNames = @(
    'AppReadiness'
    'AppXSvc'
    'StateRepository'
    'TokenBroker'
    'BrokerInfrastructure'
    'SystemEventsBroker'
    'WSearch'
    'ClipSVC'
    'UserManager'
    'ProfSvc'
    'OneDriveUpdaterService'
)

$ServiceRows = foreach ($ServiceName in $RelevantServiceNames) {
    $Service = Get-CimInstance `
        -ClassName Win32_Service `
        -Filter "Name='$ServiceName'" `
        -ErrorAction SilentlyContinue

    if ($null -eq $Service) {
        [pscustomobject]@{
            Name        = $ServiceName
            Present     = $false
            DisplayName = ''
            State       = ''
            StartMode   = ''
            ServiceAccount = ''
            ProcessId   = ''
            PathName    = ''
        }
        continue
    }

    [pscustomobject]@{
        Name        = $Service.Name
        Present     = $true
        DisplayName = $Service.DisplayName
        State       = $Service.State
        StartMode   = $Service.StartMode
        ServiceAccount =
            if (
                $Service.StartName -match
                    '^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\)'
            ) {
                $Service.StartName
            }
            else {
                '<CUSTOM OR DOMAIN ACCOUNT>'
            }
        ProcessId   = $Service.ProcessId
        PathName    =
            Protect-DiagnosticText -Text $Service.PathName
    }
}

$ServiceRows |
    Export-Csv -LiteralPath (
        Join-Path $OutputDirectory 'Relevant-Services.csv'
    ) -NoTypeInformation -Encoding UTF8

$RelevantPackagePattern =
    'Cortana|' +
    'AAD\.BrokerPlugin|' +
    'ShellExperienceHost|' +
    'StartMenuExperienceHost|' +
    'CloudExperienceHost|' +
    'AccountsControl|' +
    'SecHealthUI'

$PackageRows = @()

try {
    $PackageRows = @(
        Get-AppxPackage -AllUsers -ErrorAction Stop |
        Where-Object { $_.Name -match $RelevantPackagePattern } |
        ForEach-Object {
            [pscustomobject]@{
                Name                   =
                    Protect-DiagnosticText -Text $_.Name
                PackageFullName        =
                    Protect-DiagnosticText -Text $_.PackageFullName
                PackageFamilyName      =
                    Protect-DiagnosticText -Text $_.PackageFamilyName
                Version                = $_.Version
                Architecture           = $_.Architecture
                Publisher              =
                    Protect-DiagnosticText -Text $_.Publisher
                InstallLocation        =
                    Protect-DiagnosticText -Text $_.InstallLocation
                Status                 = $_.Status
                IsFramework            = $_.IsFramework
                NonRemovable           = $_.NonRemovable
                PackageUserInformation =
                    Protect-DiagnosticText -Text (
                        (
                            $_.PackageUserInformation |
                            ForEach-Object { [string] $_ }
                        ) -join '; '
                    )
            }
        }
    )
}
catch {
    Write-Warning "Get-AppxPackage -AllUsers failed: $($_.Exception.Message)"
}

$PackageRows |
    Export-Csv -LiteralPath (
        Join-Path $OutputDirectory 'Relevant-AppxPackages-AllUsers.csv'
    ) -NoTypeInformation -Encoding UTF8

$ProvisionedRows = @()

try {
    $ProvisionedRows = @(
        Get-AppxProvisionedPackage -Online -ErrorAction Stop |
        Where-Object {
            $_.DisplayName -match $RelevantPackagePattern -or
            $_.PackageName -match $RelevantPackagePattern
        } |
        ForEach-Object {
            [pscustomobject]@{
                DisplayName  =
                    Protect-DiagnosticText -Text $_.DisplayName
                Version      = $_.Version
                Architecture = $_.Architecture
                ResourceId   =
                    Protect-DiagnosticText -Text $_.ResourceId
                PackageName  =
                    Protect-DiagnosticText -Text $_.PackageName
                Regions      =
                    Protect-DiagnosticText -Text (
                        ($_.Regions -join ';')
                    )
            }
        }
    )
}
catch {
    Write-Warning "Get-AppxProvisionedPackage failed: $($_.Exception.Message)"
}

$ProvisionedRows |
    Export-Csv -LiteralPath (
        Join-Path $OutputDirectory 'Relevant-ProvisionedPackages.csv'
    ) -NoTypeInformation -Encoding UTF8

$ProfileRows = foreach ($Profile in $KnownProfiles) {
    $PackagesPath =
        Join-Path $Profile.LocalPath 'AppData\Local\Packages'

    $PackageDirectories = @()

    if (Test-Path -LiteralPath $PackagesPath) {
        try {
            $PackageDirectories = @(
                Get-ChildItem `
                    -LiteralPath $PackagesPath `
                    -Directory `
                    -Force `
                    -ErrorAction Stop
            )
        }
        catch {
            $PackageDirectories = @()
        }
    }

    [pscustomobject]@{
        ProfileToken           =
            Get-RedactedSidToken -Sid $Profile.SID
        Loaded                 = $Profile.Loaded
        LastUseTime            = $Profile.LastUseTime
        PackagesFolderExists   =
            Test-Path -LiteralPath $PackagesPath
        PackageDirectoryCount  = $PackageDirectories.Count
        CortanaFolderPresent   = [bool](
            $PackageDirectories.Name -match
                '^Microsoft\.Windows\.Cortana_'
        )
        AADBrokerFolderPresent = [bool](
            $PackageDirectories.Name -match
                '^Microsoft\.AAD\.BrokerPlugin_'
        )
        ShellFolderPresent     = [bool](
            $PackageDirectories.Name -match
                'ShellExperienceHost'
        )
    }
}

$ProfileRows |
    Export-Csv -LiteralPath (
        Join-Path $OutputDirectory 'Profile-Packages-Inventory.csv'
    ) -NoTypeInformation -Encoding UTF8

$AppRepositoryPath = Join-Path $env:ProgramData 'Microsoft\Windows\AppRepository'
    $ResiliencyRows = @()

if (Test-Path -LiteralPath $AppRepositoryPath) {
    $ResiliencyRows = @(
        Get-ChildItem `
            -LiteralPath $AppRepositoryPath `
            -Filter '*.rslc' `
            -File `
            -Force `
            -ErrorAction SilentlyContinue |
        ForEach-Object {
            $Sid = Get-FirstRegexMatch `
                -Text $_.Name `
                -Pattern '(?<![A-Za-z0-9])S-\d-\d+(?:-\d+){1,}(?!\d)'

            [pscustomobject]@{
                Name          =
                    Protect-DiagnosticText -Text $_.Name
                Length        = $_.Length
                CreationTime  = $_.CreationTime
                LastWriteTime = $_.LastWriteTime
                UserToken     =
                    Get-RedactedSidToken -Sid $Sid
            }
        }
    )
}

$ResiliencyRows |
    Export-Csv -LiteralPath (
        Join-Path $OutputDirectory 'AppRepository-ResiliencyFiles.csv'
    ) -NoTypeInformation -Encoding UTF8

$ResiliencyRows |
    Group-Object UserToken |
    ForEach-Object {
        $Ordered = $_.Group | Sort-Object CreationTime

        [pscustomobject]@{
            UserToken  = $_.Name
            FileCount  = $_.Count
            TotalBytes = ($_.Group | Measure-Object Length -Sum).Sum
            OldestFile = $Ordered[0].CreationTime
            NewestFile = $Ordered[-1].CreationTime
        }
    } |
    Sort-Object FileCount -Descending |
    Export-Csv -LiteralPath (
        Join-Path $OutputDirectory 'AppRepository-ResiliencySummary.csv'
    ) -NoTypeInformation -Encoding UTF8


# ============================================================
# Post-export redaction validation
# ============================================================

$ValidationChecks = New-Object 'System.Collections.Generic.List[object]'

$ValidationPatterns = @(
    [pscustomobject]@{
        CheckName = 'Raw SID'
        Pattern   =
            '(?<![A-Za-z0-9])S-\d-\d+(?:-\d+){1,}(?!\d)'
    }
    [pscustomobject]@{
        CheckName = 'Raw GUID'
        Pattern   =
            '(?<![0-9A-Fa-f])\{?' +
            '[0-9A-Fa-f]{8}-' +
            '[0-9A-Fa-f]{4}-' +
            '[0-9A-Fa-f]{4}-' +
            '[0-9A-Fa-f]{4}-' +
            '[0-9A-Fa-f]{12}' +
            '\}?(?![0-9A-Fa-f])'
    }
    [pscustomobject]@{
        CheckName = 'Email or UPN'
        Pattern   =
            '\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b'
    }
    [pscustomobject]@{
        CheckName = 'Raw user profile path'
        Pattern   =
            'C:\\Users\\' +
            '(?!<PROFILE-(?:\d{3}|UNK-\d{3})>)' +
            '(?!Public(?:\\|$)|Default(?: User)?(?:\\|$)|All Users(?:\\|$))' +
            '[^\\\s"'',;]+'
    }
    [pscustomobject]@{
        CheckName = 'Raw UNC host'
        Pattern   =
            '(?<!\\)\\\\' +
            '(?!<HOST-\d{3}>\\)' +
            '[A-Za-z0-9][A-Za-z0-9._-]{0,252}\\'
    }
)

foreach ($Identifier in @(
    $env:COMPUTERNAME
    $env:USERDOMAIN
    $env:USERDNSDOMAIN
)) {
    if (-not [string]::IsNullOrWhiteSpace($Identifier)) {
        $ValidationPatterns += [pscustomobject]@{
            CheckName = 'Environment identifier'
            Pattern   = [regex]::Escape($Identifier)
        }
    }
}

foreach ($ProfilePath in $script:ProfilePathTokens.Keys) {
    $ValidationPatterns += [pscustomobject]@{
        CheckName = 'Raw profile path'
        Pattern   = [regex]::Escape($ProfilePath)
    }
}

foreach ($QualifiedAccount in $script:QualifiedAccountTokens.Keys) {
    $ValidationPatterns += [pscustomobject]@{
        CheckName = 'Raw qualified account'
        Pattern   = [regex]::Escape($QualifiedAccount)
    }
}

foreach (
    $CsvFile in Get-ChildItem `
        -LiteralPath $OutputDirectory `
        -Filter '*.csv' `
        -File
) {
    foreach ($Check in $ValidationPatterns) {
        $MatchCount = 0
        $Examples = New-Object 'System.Collections.Generic.List[string]'
        $Reader = $null

        try {
            $Reader = [IO.StreamReader]::new(
                $CsvFile.FullName,
                [Text.Encoding]::UTF8,
                $true
            )

            while (-not $Reader.EndOfStream) {
                $Line = $Reader.ReadLine()

                foreach (
                    $Match in [regex]::Matches(
                        $Line,
                        $Check.Pattern,
                        [Text.RegularExpressions.RegexOptions]::IgnoreCase
                    )
                ) {
                    $MatchCount++

                    if ($Examples.Count -lt 3) {
                        [void] $Examples.Add($Match.Value)
                    }
                }
            }
        }
        finally {
            if ($null -ne $Reader) {
                $Reader.Dispose()
            }
        }

        if ($MatchCount -gt 0) {
            [void] $ValidationChecks.Add(
                [pscustomobject]@{
                    FileName   = $CsvFile.Name
                    CheckName  = $Check.CheckName
                    MatchCount = $MatchCount
                    Examples   = ($Examples -join '; ')
                }
            )
        }
    }
}

$ValidationIssueCount =
    ($ValidationChecks | Measure-Object MatchCount -Sum).Sum

if ($null -eq $ValidationIssueCount) {
    $ValidationIssueCount = 0
}

$ValidationPassed = ($ValidationIssueCount -eq 0)

if ($ValidationChecks.Count -eq 0) {
    [pscustomobject]@{
        FileName   = ''
        CheckName  = 'Validation passed'
        MatchCount = 0
        Examples   = ''
    } |
        Export-Csv -LiteralPath (
            Join-Path $OutputDirectory 'Redaction-Validation.csv'
        ) -NoTypeInformation -Encoding UTF8
}
else {
    $ValidationChecks.ToArray() |
        Export-Csv -LiteralPath (
            Join-Path $OutputDirectory 'Redaction-Validation.csv'
        ) -NoTypeInformation -Encoding UTF8
}

$ComputerSystem = Get-CimInstance Win32_ComputerSystem

$SystemSummary = [pscustomobject]@{
    CollectedAt         = Get-Date
    ServerLabel         = '<SERVER-001>'
    StartTime           = $StartTime
    DaysRequested       = $Days
    Caption             = $OperatingSystem.Caption
    Version             = $OperatingSystem.Version
    BuildNumber         = $OperatingSystem.BuildNumber
    LastBootUpTime      = $LastBootUpTime
    LastBootWithinRequestedWindow = $LastBootWithinRequestedWindow
    PostBootWindowStart  = $PostBootStartTime
    PostBootEventsExported = $PostBootEvents.Count
    UptimeDays          = [Math]::Round(
        ((Get-Date) - $OperatingSystem.LastBootUpTime).TotalDays,
        2
    )
    TotalPhysicalGB     = [Math]::Round(
        $ComputerSystem.TotalPhysicalMemory / 1GB,
        2
    )
    TotalEventsExported = $AllEvents.Count
    ResiliencyFileCount = $ResiliencyRows.Count
    RedactionValidationPassed = $ValidationPassed
    ResidualIdentifierMatches     = $ValidationIssueCount
    OutputFolderName    = Split-Path -Leaf $OutputDirectory
}

$SystemSummary |
    Export-Csv -LiteralPath (
        Join-Path $OutputDirectory 'System-Summary.csv'
    ) -NoTypeInformation -Encoding UTF8

Write-Host
Write-Host 'Read-only AppX/AppReadiness audit completed.'
Write-Host "Events exported: $($AllEvents.Count)"
Write-Host "Redaction validation passed: $ValidationPassed"
Write-Host "Residual identifier matches:     $ValidationIssueCount"
Write-Host "Output folder:   $OutputDirectory"
