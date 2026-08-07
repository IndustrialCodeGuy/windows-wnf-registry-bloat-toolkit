# Windows WNF Registry Bloat Toolkit

PowerShell tools for identifying, analyzing, and carefully remediating excessive Windows Notification Facility (WNF) registrations under:

```text
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications
```

The toolkit is intended primarily for Windows Server 2019 systems showing a combination of unusually large `Notifications` registry data, AppX/AppContainer registration failures, broken per-user Windows features, slow logons, or resource-related errors.

It grew out of an RDS investigation, but the read-only tools are designed to help administrators determine whether a different server shows the same structural and operational pattern before considering remediation.

> [!CAUTION]
> The remediation script performs low-level registry changes only when explicitly placed in cleanup mode. Its target is intentionally narrow: one exact WNF value family established through structural analysis and live-state auditing. Review the source, complete the read-only checks, test with `-WhatIf`, maintain a verified rollback path, and use a controlled maintenance window before production cleanup.

## Project status

This is an operational troubleshooting toolkit developed and tested primarily on Windows Server 2019.

- Most tools are read-only and can be used for comparison and diagnosis.
- The remediation logic recognizes one exact 72-byte system-scoped WNF family.
- The scripts have not been validated across every Windows version, RDS design, profile technology, or application stack.
- WNF is a private Windows mechanism. Native WNF results are diagnostic evidence, not an official Microsoft stale-state determination.
- A large `Notifications` key alone is not enough to justify cleanup.

## When this toolkit may be useful

A server may warrant investigation when several of these appear together:

- Slow or inconsistent RDS logons.
- High CPU activity associated with user sign-in or AppX processing.
- Registry Editor becoming slow or unresponsive when opening the `Notifications` key.
- Start menu or taskbar Search failures.
- Microsoft authentication or OneDrive sign-in problems.
- OneDrive Files On-Demand failing to initialize.
- Newly created profiles with unusually few folders under `%LOCALAPPDATA%\Packages`.
- Repeated AppX/AppReadiness failures across multiple users and packages.
- Errors such as `0x800705AA`, `0x80070003`, `0x80073CF6`, or `0x800703FA`.
- Very large quantities of one repeated WNF registration family that persist through reboot.

No single symptom or count is a universal indicator. The toolkit is intended to combine registry structure, profile evidence, AppX events, live WNF state, and comparison-server data.

## Included tools

| Script | Purpose | Changes the system |
| --- | --- | --- |
| `Get-WnfNotificationsStructuralInventory.ps1` | Inventories and classifies the complete root-level `Notifications` key, including WNF metadata, payload groups, and sequence statistics. | No |
| `Get-WnfNotificationValues.ps1` | Reads and exports a selected range of root-level `Notifications` values for inspection. | No |
| `Find-WnfNotificationValuesOutsideReferenceFamily.ps1` | Identifies values outside the selected repeated reference family for further analysis. | No |
| `Analyze-WnfUserScopePayloads.ps1` | Analyzes the 136-byte user-scoped WNF family and its user/AppContainer security-descriptor structure. | No |
| `Audit-WnfSystemScopeLiveState.ps1` | Queries selected or all members of the repeated 72-byte system-scoped family for observable live-state evidence. | No |
| `Get-AppXProfilePackageTimeline.ps1` | Builds a chronological inventory of per-profile AppX package-folder population and core package presence. | No |
| `Collect-AppXReadinessAudit-Raw.ps1` | Collects detailed AppX, AppReadiness, shell, authentication, StateRepository, profile, service, and event-log evidence. | No |
| `Collect-AppXReadinessAudit-Redacted.ps1` | Collects similar evidence with best-effort redaction of environment-specific identifiers. | No |
| `Export-CortanaAppXEvents.ps1` | Exports AppX deployment events related to Cortana/SearchUI for focused analysis. | No |
| `Export-AadBrokerPluginAppXEvents.ps1` | Exports AppX deployment events related to AAD BrokerPlugin for focused analysis. | No |
| `Invoke-WnfNotificationsRemediation.ps1` | Audits by default. In confirmed cleanup mode, backs up the key, revalidates and live-checks each candidate, and deletes only exact qualifying matches. | Read-only by default; registry changes only in cleanup mode |

## Requirements

- Windows Server 2019 is the primary tested platform.
- 64-bit Windows PowerShell 5.1.
- Administrator rights for complete registry, package, service, profile, and event-log access.
- A local administrator and physical, hypervisor, or out-of-band console session for production cleanup.
- Sufficient local storage for CSV output, event exports, and registry backup files.
- A verified VM snapshot, image-level backup, or equivalent rollback method before cleanup.

The scripts use built-in Windows and PowerShell functionality. No third-party PowerShell modules are required.

Generated output is written under:

```text
%ProgramData%\WindowsWnfRegistryBloatToolkit
```

unless a script-specific output path is supplied.

## Repository layout

```text
windows-wnf-registry-bloat-toolkit/
├── README.md
├── LICENSE
├── NOTICE
├── .gitignore
├── scripts/
│   ├── Analyze-WnfUserScopePayloads.ps1
│   ├── Audit-WnfSystemScopeLiveState.ps1
│   ├── Collect-AppXReadinessAudit-Raw.ps1
│   ├── Collect-AppXReadinessAudit-Redacted.ps1
│   ├── Export-AadBrokerPluginAppXEvents.ps1
│   ├── Export-CortanaAppXEvents.ps1
│   ├── Find-WnfNotificationValuesOutsideReferenceFamily.ps1
│   ├── Get-AppXProfilePackageTimeline.ps1
│   ├── Get-WnfNotificationsStructuralInventory.ps1
│   ├── Get-WnfNotificationValues.ps1
│   └── Invoke-WnfNotificationsRemediation.ps1
└── docs/
    ├── investigation-overview.md
    ├── findings.md
    └── remediation.md
```

Do not publish production logs, registry exports, hive backups, user SIDs, server names, tenant identifiers, or unreviewed event data.

## Documentation

- [Investigation overview](docs/investigation-overview.md) — signs and symptoms, how to determine whether a server may be affected, and the recommended diagnostic workflow.
- [Technical findings](docs/findings.md) — WNF structures, live-state interpretation, AppX/AppContainer failure patterns, and preservation boundaries.
- [Remediation procedure](docs/remediation.md) — audit, `-WhatIf`, maintenance-window cleanup, backup, validation, and recurrence monitoring.

## Quick start

Open an elevated **64-bit Windows PowerShell 5.1** window from the repository root.

If the downloaded files are blocked:

```powershell
Get-ChildItem .\scripts\*.ps1 | Unblock-File
```

### 1. Check the user-profile timeline

```powershell
.\scripts\Get-AppXProfilePackageTimeline.ps1
```

This can reveal a chronological transition from normally populated AppX profiles to newer profiles with very few package folders or missing core package families.

Stale profile folders are retained in the report and identified separately so they can be excluded from timeline interpretation without losing the evidence.

### 2. Inventory the Notifications key

```powershell
.\scripts\Get-WnfNotificationsStructuralInventory.ps1
```

The inventory reports:

- Total root-level values.
- `SequenceNumber`.
- 72-byte metadata-`0x011` system-scoped values.
- 136-byte metadata-`0x091` user-scoped values.
- Other root values.
- Distinct SHA-256 payload groups.
- Matches to the toolkit's reference payload.
- Unique-ID ranges, gaps, duplicates, and contiguous runs.

There is no universal safe value count. Compare the structure with the server's symptoms and, when possible, with similar systems.

### 3. Run a live WNF sample

```powershell
.\scripts\Audit-WnfSystemScopeLiveState.ps1
```

The audit checks for:

- Native WNF query success.
- Subscribers.
- Quiescence.
- State data.
- Change stamp.

After validating a sample, a full scan can be run:

```powershell
.\scripts\Audit-WnfSystemScopeLiveState.ps1 -FullScan
```

A complete scan of a heavily populated family may take several hours.

The absence of subscribers, state data, nonzero change stamps, and non-quiescent states is strong evidence that the states were dormant during the scan. It is not an absolute guarantee of future non-use.

### 4. Collect AppX and AppReadiness evidence

For full local diagnostic output:

```powershell
.\scripts\Collect-AppXReadinessAudit-Raw.ps1
```

For best-effort redacted output:

```powershell
.\scripts\Collect-AppXReadinessAudit-Redacted.ps1
```

The collectors gather available evidence from AppReadiness, AppX deployment, AppModel Runtime, TWinUI, Search, shell, authentication, StateRepository, profile, Application, and System sources.

> [!IMPORTANT]
> Redaction is best-effort. Event messages are free-form, and no automated process can guarantee that every environment-specific identifier was removed. Review generated output before sharing it outside the intended administrative team.

### 5. Run the remediation script in read-only mode

Audit is the default:

```powershell
.\scripts\Invoke-WnfNotificationsRemediation.ps1
```

The script performs an immediate structural inventory and exports its fixed candidate list without making registry changes.

### 6. Simulate cleanup

```powershell
.\scripts\Invoke-WnfNotificationsRemediation.ps1 `
    -Mode Cleanup `
    -WhatIf
```

The simulation performs the same per-candidate structural and live-state checks used by actual cleanup, but records qualifying values as `WouldDelete` instead of removing them.

For a large candidate family, this can take several hours.

## Production cleanup

> [!WARNING]
> Do not run cleanup until the read-only evidence has been reviewed and a verified rollback path is available.

Recommended maintenance sequence:

1. Disable new RDS logons.
2. Log off ordinary user sessions.
3. Reboot the server.
4. Sign in through the physical, hypervisor, or out-of-band console with a local administrator.
5. Verify the VM snapshot or image-level rollback.
6. Run cleanup mode.
7. Reboot after successful cleanup.
8. Validate the server before restoring normal RDS/Gateway access.

Production command:

```powershell
.\scripts\Invoke-WnfNotificationsRemediation.ps1 `
    -Mode Cleanup `
    -RollbackConfirmed `
    -MaintenanceWindowConfirmed
```

The script performs another immediate structural inventory and presents a high-impact confirmation before deletion.

### Automatic backup and safeguards

Before actual deletion, the script:

- Requires elevation.
- Requires a local account and console session by default.
- Requires explicit maintenance-window and rollback acknowledgements.
- Performs its own current structural inventory.
- Captures a fixed pre-cleanup candidate list.
- Saves the complete `Notifications` key with `reg save`.
- Verifies that the backup exists and is non-empty.
- Records the backup SHA-256 hash.
- Attempts a separate export of `Notifications\Data`.

For every candidate, it immediately rechecks:

- 16-character hexadecimal value name.
- `REG_BINARY` type.
- WNF metadata `0x011`.
- Data length of exactly 72 bytes.
- Exact reference payload hash.
- Native query success.
- Subscriber state.
- State-data size.
- Change stamp.
- Quiescent state.

A candidate is preserved if its structure changes, a native query fails, observable live-state evidence appears, or deletion fails.

The script does not rely on deletion failure to determine whether a state is in use.

### Explicitly preserved

Cleanup does not target:

- The `Notifications` key itself.
- Any subkey.
- `Notifications\Data`.
- `SequenceNumber`.
- The 136-byte metadata-`0x091` user/AppContainer family.
- Any root value with a different type, length, metadata, or payload.
- Values created after the fixed candidate list was captured.

The script does not reboot automatically.

## Remediation target

The current cleanup logic intentionally recognizes the family established during the original investigation:

```text
Registry path:
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications

Decoded metadata:
0x011

Registry type:
REG_BINARY

Data length:
72 bytes

Payload SHA-256:
A847320A34E3ABD0F790D27CEF46D52CDD81E7B0F5257E8BE74FEF8FEE788840
```

The exact hash is part of the remediation safety boundary, not a general Windows WNF signature.

Do not change the hash or broaden the filter merely to make another server produce candidates. A different payload or structure requires separate analysis.

The 136-byte metadata-`0x091` family observed during analysis contained structured per-user/AppContainer security descriptors and is deliberately preserved.

## Origin of the toolkit

The project grew out of a Windows Server 2019 RDS investigation where the `Notifications` key had grown to roughly **260,000** root values, with **more than 250,000** belonging to one repeated 72-byte system-scoped family.

The same server showed:

- Registry Editor becoming unresponsive when opening the key.
- Slow logons and periods of high CPU.
- Broken Start and taskbar Search.
- Microsoft/OneDrive authentication and Files On-Demand problems.
- Newer profiles with nearly empty `%LOCALAPPDATA%\Packages` trees.
- Repeated AppX/AppReadiness failures involving built-in shell and authentication packages.
- Resource and package-registration errors including `0x800705AA`.

A complete live scan of **more than 250,000** matching values found no subscribers, state data, nonzero change stamps, non-quiescent states, or native-query failures during the scan.

Comparison systems in the same environment helped show that the repeated family was associated with the interactive RDS workload, but those comparisons did not establish a universal healthy count or identify the creating process.

The project documentation intentionally focuses on the repeatable diagnostic pattern rather than treating those originating counts as thresholds.

## Post-cleanup validation

Before returning a server to normal production use, verify:

- The `Notifications` key opens without Registry Editor hanging or causing an abnormal CPU spike.
- Start works.
- Taskbar Search works.
- Settings and ShellExperienceHost activate normally.
- A new test profile receives an appropriately populated package tree.
- Cortana/SearchUI and AAD BrokerPlugin register and activate normally.
- Microsoft/OneDrive authentication works.
- OneDrive Files On-Demand works.
- AppX/AppReadiness registration loops stop.
- StateRepository lock/retry activity returns to normal background levels.
- Known Scheduled Tasks execute normally.
- Server Manager remains functional.
- RDS logon time and CPU behavior improve.

Monitor the Notifications structure after cleanup, reboot, controlled user logons, and during the initial production period.

Cleanup removes accumulated state. It may not identify or permanently stop the process that created it.

## What this project does not do

- It does not define a universal safe maximum number of registry values.
- It does not assume that keeping an arbitrary number of values is a Windows-supported baseline.
- It does not delete and recreate the complete `Notifications` key.
- It does not delete the `Data` subkey.
- It does not modify WindowsApps permissions.
- It does not disable AppReadiness, SystemEventsBroker, or BrokerInfrastructure.
- It does not run Microsoft's historical `wnfcleanup.exe`.
- It does not include or wrap the community `clnotifications` executable.
- It does not identify the process that originally created each WNF state.
- It does not guarantee that the originating accumulation will not recur.
- It does not replace normal backup, change-control, incident-management, or vendor-support decisions.

## Data handling

Treat collected output as operationally sensitive.

The remediation output can contain system, account, session, registry, and backup information. Structural and live-audit output includes WNF state names and hashes. Redacted AppX output should still be manually reviewed before publication or external sharing.

Do not commit production diagnostic output such as:

```text
*.hiv
*.reg
*.evtx
production CSV exports
production ZIP archives
server-specific handoff documents
screenshots containing server or account information
```

## Related work and references

### Microsoft

- [Registry bloat causes slow logons or insufficient system resources error 0x800705AA in Windows 8.1 — KB3063843](https://support.microsoft.com/en-us/topic/registry-bloat-causes-slow-logons-or-insufficient-system-resources-error-0x800705aa-in-windows-8-1-82a985fb-df27-abda-440b-f3f81a2c949d)
- [Troubleshooting packaging, deployment, and query of Windows apps](https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting)
- [Fix problems in Windows Search](https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/fix-problems-in-windows-search)
- [Issues with AppX, MSIX, or Microsoft Store applications — FSLogix](https://learn.microsoft.com/en-us/fslogix/troubleshooting-appx-issues)

Microsoft KB3063843 documents a WNF registration leak in the same registry area and a matching slow-logon/high-CPU/`0x800705AA` symptom pattern on Windows 8.1 and Windows Server 2012 R2. It is useful historical precedent, but it does not establish that its cleanup utility is supported on Windows Server 2019.

### Community investigations

- [Windows Server AppX Installation Failures — Joel Leach](https://joelleach.net/2024/12/30/windows-server-appx-installation-failures/)
- [Lazy-256/clnotifications](https://github.com/Lazy-256/clnotifications)

These community sources document similar Server 2019 behavior and prior cleanup approaches. This toolkit uses structural classification, live-state auditing, backup, dry-run, and per-value safety checks rather than an arbitrary retained-value threshold.

## Contributing

Issues and pull requests are welcome, especially for:

- Read-only testing on additional Windows Server versions.
- Additional anonymized comparison results.
- Safer output and redaction.
- Improved profile-timeline analysis.
- Better post-remediation monitoring.
- Additional native-query validation.
- Documentation corrections.

Do not submit production registry exports or logs containing identifiable information.

Changes to remediation filters should include a documented structural basis, read-only evidence, test results, preservation rules, a dry-run path, and rollback considerations.

## Security and responsible use

Do not publish sensitive diagnostic output or environment details in a public issue.

The tools are intended for authorized administration of systems you own or manage.

## License

Licensed under the [Apache License 2.0](LICENSE).

```text
Copyright 2026 Dan Michel
```

See [NOTICE](NOTICE) for attribution and project-independence information.

## Independence and trademarks

Windows WNF Registry Bloat Toolkit is an independent third-party project. It is not affiliated with, endorsed by, or distributed by Microsoft.

Windows and Windows Server are trademarks of the Microsoft group of companies. Their names are used only to identify the operating environments for which this software was developed.

## Disclaimer

The software is provided on an “AS IS” basis, without warranties or conditions of any kind. Registry cleanup and low-level Windows troubleshooting can cause service interruption or data loss when used incorrectly. Review the scripts, test in a non-production environment, maintain verified backups, and follow your organization's change-control procedures.
