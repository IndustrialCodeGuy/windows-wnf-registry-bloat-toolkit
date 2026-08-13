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
    Builds and exports a chronological inventory of AppX package-folder
    population across local Windows user profiles.

.DESCRIPTION
    Enumerates local profile folders and examines each profile's
    AppData\Local\Packages folder. The report includes profile-folder creation
    time, NTUSER.DAT and UsrClass.dat creation times, package-folder status and
    count, first and last package-folder creation times, and the presence of
    selected core AppX package families.

    Each profile folder is also compared with Win32_UserProfile so current,
    loaded, special, and stale profile folders can be distinguished without
    discarding older evidence. Results are sorted by profile creation time,
    displayed in the console, and exported to a timestamped CSV by default.

    This script is read-only. It does not modify profiles, packages, registry
    values, files, or folders.

.NOTES
    Run from elevated 64-bit Windows PowerShell 5.1 on Windows Server 2019.

    File and folder creation times are useful timeline evidence but are not
    authoritative account-creation or first-logon timestamps. Missing,
    unreadable, and successfully read empty Packages folders are reported
    separately.
#>

[CmdletBinding()]
param(
    [string] $ProfileRoot = (
        Join-Path $env:SystemDrive 'Users'
    ),

    [string] $ExportCsv = (
        Join-Path $env:ProgramData (
            'WindowsWnfRegistryBloatToolkit\ProfileTimeline\' +
            'AppX-ProfilePackageTimeline-{0:yyyyMMdd-HHmmss}.csv' -f (Get-Date)
        )
    )
)

$ErrorActionPreference = 'Stop'

$CorePackageFamilies = [ordered]@{
    Cortana             = 'Microsoft.Windows.Cortana_*'
    AadBrokerPlugin     = 'Microsoft.AAD.BrokerPlugin_*'
    ShellExperienceHost = 'Microsoft.Windows.ShellExperienceHost_*'
    CloudExperienceHost = 'Microsoft.Windows.CloudExperienceHost_*'
}

function Get-CreationTimeOrNull {
    param(
        [Parameter(Mandatory)]
        [string] $LiteralPath
    )

    try {
        if (Test-Path -LiteralPath $LiteralPath -PathType Leaf) {
            return (Get-Item -LiteralPath $LiteralPath -Force).CreationTime
        }
    }
    catch {
        return $null
    }

    return $null
}

if (-not (Test-Path -LiteralPath $ProfileRoot -PathType Container)) {
    throw "Profile root was not found: $ProfileRoot"
}

$RegisteredPaths = @{}

Get-CimInstance Win32_UserProfile -ErrorAction Stop |
    Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.LocalPath)
    } |
    ForEach-Object {
        $NormalizedPath = $_.LocalPath.TrimEnd('\').ToLowerInvariant()
        $RegisteredPaths[$NormalizedPath] = $_
    }

$ProfileFolders = Get-ChildItem -LiteralPath $ProfileRoot -Directory -Force -ErrorAction Stop

$Results = foreach ($ProfileFolder in $ProfileFolders) {
    $ProfilePath = $ProfileFolder.FullName.TrimEnd('\')
    $ProfileKey = $ProfilePath.ToLowerInvariant()
    $RegisteredProfile = $RegisteredPaths[$ProfileKey]

    $PackagesPath =
        Join-Path $ProfilePath 'AppData\Local\Packages'

    $NtUserPath =
        Join-Path $ProfilePath 'NTUSER.DAT'

    $UsrClassPath = Join-Path $ProfilePath 'AppData\Local\Microsoft\Windows\UsrClass.dat'

    $PackagesStatus = 'Missing'
    $PackageCount = $null
    $FirstPackageCreated = $null
    $LastPackageCreated = $null
    $PackageNames = @()
    $ReadError = $null

    if (Test-Path -LiteralPath $PackagesPath -PathType Container) {
        try {
            $PackageFolders = @(
                Get-ChildItem -LiteralPath $PackagesPath -Directory -Force -ErrorAction Stop
            )

            $PackagesStatus = 'Found'
            $PackageCount = $PackageFolders.Count
            $PackageNames = @($PackageFolders.Name)

            if ($PackageFolders.Count -gt 0) {
                $SortedCreationTimes =
                    $PackageFolders |
                    Sort-Object CreationTime |
                    Select-Object -ExpandProperty CreationTime

                $FirstPackageCreated = $SortedCreationTimes[0]
                $LastPackageCreated =
                    $SortedCreationTimes[$SortedCreationTimes.Count - 1]
            }
        }
        catch [System.UnauthorizedAccessException] {
            $PackagesStatus = 'AccessDenied'
            $ReadError = $_.Exception.Message
        }
        catch {
            $PackagesStatus = 'ReadError'
            $ReadError = $_.Exception.Message
        }
    }

    $CorePresence = [ordered]@{}

    foreach ($Family in $CorePackageFamilies.GetEnumerator()) {
        $CorePresence[$Family.Key] = [bool](
            $PackageNames |
                Where-Object { $_ -like $Family.Value } |
                Select-Object -First 1
        )
    }

    $MissingCorePackages = @(
        foreach ($Family in $CorePresence.GetEnumerator()) {
            if (-not $Family.Value) {
                $Family.Key
            }
        }
    )

    $CorePackageCount = @(
        $CorePresence.GetEnumerator() |
            Where-Object { $_.Value }
    ).Count

    [pscustomobject]@{
        User                   = $ProfileFolder.Name
        ProfilePath            = $ProfilePath
        ProfileCreated         = $ProfileFolder.CreationTime
        NtUserCreated          = Get-CreationTimeOrNull -LiteralPath $NtUserPath
        UsrClassCreated        = Get-CreationTimeOrNull -LiteralPath $UsrClassPath
        RegisteredProfile      = $null -ne $RegisteredProfile
        Loaded                 = if ($RegisteredProfile) {
            [bool] $RegisteredProfile.Loaded
        }
        else {
            $false
        }
        Special                = if ($RegisteredProfile) {
            [bool] $RegisteredProfile.Special
        }
        else {
            $false
        }
        LastUseTime            = if ($RegisteredProfile) {
            $RegisteredProfile.LastUseTime
        }
        else {
            $null
        }
        PackagesStatus         = $PackagesStatus
        PackageCount           = $PackageCount
        FirstPackageCreated    = $FirstPackageCreated
        LastPackageCreated     = $LastPackageCreated
        HasCortana             = $CorePresence.Cortana
        HasAadBrokerPlugin     = $CorePresence.AadBrokerPlugin
        HasShellExperienceHost = $CorePresence.ShellExperienceHost
        HasCloudExperienceHost = $CorePresence.CloudExperienceHost
        CorePackageCount       = $CorePackageCount
        MissingCorePackages    = $MissingCorePackages -join ', '
        ReadError              = $ReadError
    }
}

$Results = @(
    $Results |
        Sort-Object ProfileCreated, User
)

if ($ExportCsv) {
    if (Test-Path -LiteralPath $ExportCsv -PathType Container) {
        $ExportCsv = Join-Path $ExportCsv (
            'AppX-ProfilePackageTimeline-{0:yyyyMMdd-HHmmss}.csv' -f (Get-Date)
        )
    }

    $ExportDirectory = Split-Path -Parent $ExportCsv

    if ($ExportDirectory -and -not (Test-Path -LiteralPath $ExportDirectory)) {
        New-Item -ItemType Directory -Path $ExportDirectory -Force | Out-Null
    }

    $Results |
        Export-Csv -LiteralPath $ExportCsv -NoTypeInformation -Encoding UTF8
}

$TableProperties = @(
    'User'
    'ProfileCreated'
    'PackageCount'
    'PackagesStatus'
    'CorePackageCount'
    'RegisteredProfile'
    'Loaded'
)

$Results |
    Format-Table -Property $TableProperties -AutoSize

Write-Host
Write-Host "Profiles examined: $($Results.Count)"

if ($ExportCsv) {
    Write-Host "Exported to: $ExportCsv"
}
else {
    Write-Host 'CSV export suppressed.'
}
