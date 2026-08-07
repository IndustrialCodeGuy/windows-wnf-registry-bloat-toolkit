# Windows WNF Registry Bloat Toolkit

PowerShell tools for identifying, analyzing, and carefully remediating excessive Windows Notification Facility (WNF) registrations under:

```text
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications
```

The toolkit was developed during an investigation of a Windows Server 2019 Remote Desktop Session Host experiencing severe registry-key growth, slow logons, high CPU usage, broad AppX/AppContainer registration failures, broken Start and taskbar Search, and Microsoft authentication/OneDrive failures.

> [!CAUTION]
> `Invoke-WnfNotificationsRemediation.ps1` performs low-level registry changes only when explicitly placed in cleanup mode. Its current target is one exact WNF value family established during the originating investigation. Review the source, complete the read-only audits, test with `-WhatIf`, maintain a verified rollback path, and use a controlled maintenance window before considering production cleanup.

## Project status

This is an early operational toolkit based on a specific Windows Server 2019 investigation.

- Read-only collection and audit tools can be useful for broader comparison and troubleshooting.
- The remediation logic is intentionally narrow and currently recognizes one exact 72-byte WNF family.
- The scripts have not been validated across every Windows version, RDS design, profile technology, or application stack.
- WNF is a private Windows mechanism. Native WNF results are diagnostic evidence, not an official Microsoft stale-state determination.
- A large `Notifications` key by itself is not sufficient evidence that this remediation applies.

## Documentation

- [Investigation Overview](docs/investigation-overview.md) — symptoms, evidence collection, and how to determine whether a server resembles the originating case.
- [Technical Findings](docs/findings.md) — WNF structures, live-state interpretation, AppX evidence, and cross-server observations.
- [Remediation](docs/remediation.md) — audit, `-WhatIf`, maintenance-window cleanup, rollback, validation, and recurrence monitoring.

## Included tools

| Script | Purpose | Changes the system |
|---|---|---|
| `Get-AppXProfilePackageTimeline.ps1` | Builds a chronological inventory of per-profile `%LOCALAPPDATA%\Packages` population and selected core AppX package families. | No |
| `Get-WnfNotificationsStructuralInventory.ps1` | Counts and classifies root-level Notifications values, groups payload hashes, identifies the investigation-specific 72-byte family, and reports unique-ID sequence statistics. | No |
| `Audit-WnfSystemScopeLiveState.ps1` | Queries a sample or the full repeated 72-byte family for state-name existence, subscribers, state data, change stamps, and quiescence. | No |
| `Get-WnfNotificationValues.ps1` | Reads and exports a selected registry-enumeration range for low-level inspection. Enumeration order is not treated as age or importance. | No |
| `Find-WnfNotificationValuesOutsideReferenceFamily.ps1` | Exports root-level values that do not exactly match a selected reference-family value for follow-up analysis. | No |
| `Analyze-WnfUserScopePayloads.ps1` | Analyzes the observed 136-byte metadata-`0x091` user-scoped family, including security-descriptor/SID structure and payload grouping. | No |
| `Collect-AppXReadinessAudit-Raw.ps1` | Collects unredacted AppX, AppReadiness, shell, authentication, StateRepository, profile, package, service, and event-log evidence. | No |
| `Collect-AppXReadinessAudit-Redacted.ps1` | Collects similar evidence with best-effort redaction and post-export validation. | No |
| `Invoke-WnfNotificationsRemediation.ps1` | Performs a structural audit by default. In confirmed cleanup mode, backs up the key, revalidates and live-checks every candidate, and deletes only exact matches with no observed live-state evidence. | Read-only by default; registry changes only in confirmed cleanup mode |

## Requirements

- Windows Server 2019 is the currently investigated and tested platform.
- 64-bit Windows PowerShell 5.1.
- Administrator rights for complete registry, package, service, and event-log access.
- A local administrator and physical, hypervisor, or out-of-band console session for production cleanup.
- Sufficient local storage for CSV output, event exports, and the registry backup.
- A verified VM snapshot, image-level backup, or equivalent rollback method before cleanup.

The scripts use built-in Windows and PowerShell functionality and require no third-party PowerShell modules. The toolkit contains no telemetry or diagnostic-upload functionality; generated output is written locally. Optional SID-to-account resolution in `Analyze-WnfUserScopePayloads.ps1 -ResolveSidNames` may use normal Windows/domain name-resolution services.

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
│   ├── Find-WnfNotificationValuesOutsideReferenceFamily.ps1
│   ├── Get-AppXProfilePackageTimeline.ps1
│   ├── Get-WnfNotificationValues.ps1
│   ├── Get-WnfNotificationsStructuralInventory.ps1
│   └── Invoke-WnfNotificationsRemediation.ps1
└── docs/
    ├── findings.md
    ├── investigation-overview.md
    └── remediation.md
```

Do not publish production logs, registry exports, hive backups, user SIDs, server names, tenant identifiers, or unreviewed event data in the repository.

## Quick start

Open an elevated **64-bit Windows PowerShell 5.1** window from the repository root. If the ZIP or scripts were downloaded from the Internet, remove the downloaded-file zone marker before running them:

```powershell
Get-ChildItem .\scripts\*.ps1 |
    Unblock-File
```

Run scripts in accordance with your organization's PowerShell execution-policy requirements. If a process-scoped execution-policy override is permitted and required for testing, apply it deliberately rather than changing machine-wide policy.

### 1. Check the profile package timeline

```powershell
.\scripts\Get-AppXProfilePackageTimeline.ps1
```

Default CSV:

```text
%ProgramData%\WindowsWnfRegistryBloatToolkit\ProfileTimeline\AppX-ProfilePackageTimeline-<timestamp>.csv
```

Look for a chronological transition where newer **registered** profiles suddenly have sparse `%LOCALAPPDATA%\Packages` trees or are missing core package families such as Cortana/SearchUI, AAD BrokerPlugin, ShellExperienceHost, and CloudExperienceHost.

### 2. Inventory the Notifications key

```powershell
.\scripts\Get-WnfNotificationsStructuralInventory.ps1 `
    -ServerLabel 'RDS-Comparison-01'
```

Default output directory:

```text
%ProgramData%\WindowsWnfRegistryBloatToolkit\StructuralInventory
```

The script reports:

- Total root-level values.
- `SequenceNumber`.
- 72-byte, metadata-`0x011` system-scoped values.
- 136-byte, metadata-`0x091` user-scoped values.
- Other root values.
- Distinct SHA-256 payload groups.
- Matches to the known investigation payload.
- Unique-ID ranges, gaps, duplicates, and contiguous runs.

This is the preferred first registry step when comparing affected and unaffected systems.

### 3. Run a live WNF sample

```powershell
.\scripts\Audit-WnfSystemScopeLiveState.ps1 `
    -AuditLabel 'Baseline'
```

Default output directory:

```text
%ProgramData%\WindowsWnfRegistryBloatToolkit\LiveAudit
```

The default run audits a distributed sample of 1,000 values. It records:

- Whether the live WNF namespace reports the state name as existing.
- Whether subscribers are present.
- Whether the state is quiescent.
- Whether state data is present and its size.
- Change stamp.
- Native query status.
- State-data hash when readable.

Recheck the exact same names later by supplying a CSV generated by a previous audit:

```powershell
.\scripts\Audit-WnfSystemScopeLiveState.ps1 `
    -ReuseNamesFromCsv 'C:\Path\To\previous-audit.csv' `
    -AuditLabel 'AfterReboot'
```

Run the complete family only after validating the sample:

```powershell
.\scripts\Audit-WnfSystemScopeLiveState.ps1 `
    -FullScan `
    -AuditLabel 'FullScan-UsersActive'
```

A complete scan of a heavily populated key may take several hours.

### 4. Collect related AppX and AppReadiness evidence

For output intended to be reviewed or shared more broadly, start with the best-effort redacted collector:

```powershell
.\scripts\Collect-AppXReadinessAudit-Redacted.ps1 `
    -Days 7
```

Default output:

```text
%ProgramData%\WindowsWnfRegistryBloatToolkit\AppX-Readiness-Audit-Redacted-<timestamp>
```

For local operational troubleshooting when unredacted identifiers are required:

```powershell
.\scripts\Collect-AppXReadinessAudit-Raw.ps1 `
    -Days 7
```

Default output:

```text
%ProgramData%\WindowsWnfRegistryBloatToolkit\AppX-Readiness-Audit-Raw-<timestamp>
```

The collectors include available data from AppReadiness, AppXDeployment/AppXDeploymentServer, AppModel Runtime/State, TWinUI, shell/Search, State Repository, Microsoft AAD/WebAuth, Cloud Experience Host, User Profile Service, Application/System logs, service/package state, per-profile package counts, AppRepository resiliency files, and event-log retention information.

> [!IMPORTANT]
> The raw collector is intentionally unredacted and should be treated as sensitive. Redaction in the redacted collector is best-effort; event messages are free-form, so review all generated files before external or public sharing.

### 5. Optional deeper structural analysis

These read-only tools are useful after the initial structural inventory:

```powershell
.\scripts\Get-WnfNotificationValues.ps1 -Count 100
```

Default CSV path is under:

```text
%ProgramData%\WindowsWnfRegistryBloatToolkit\Samples
```

To export values outside a selected repeated reference family:

```powershell
.\scripts\Find-WnfNotificationValuesOutsideReferenceFamily.ps1
```

Default CSV:

```text
%ProgramData%\WindowsWnfRegistryBloatToolkit\Analysis\Wnf-NotificationValues-OutsideReferenceFamily.csv
```

To analyze the 136-byte user-scoped family from that export:

```powershell
.\scripts\Analyze-WnfUserScopePayloads.ps1
```

Default output directory:

```text
%ProgramData%\WindowsWnfRegistryBloatToolkit\Analysis\WnfUserScope
```

Use `-ResolveSidNames` only when account-name resolution is useful and appropriate for the environment.

### 6. Run the remediation script in read-only Audit mode

Audit is the default:

```powershell
.\scripts\Invoke-WnfNotificationsRemediation.ps1
```

The script performs an immediate structural inventory and exports the exact candidate list without making registry changes.

Default output:

```text
%ProgramData%\WindowsWnfRegistryBloatToolkit\Wnf-Remediation-Audit-<timestamp>
```

### 7. Simulate the complete cleanup

```powershell
.\scripts\Invoke-WnfNotificationsRemediation.ps1 `
    -Mode Cleanup `
    -WhatIf
```

The simulation:

- Performs the same immediate structural inventory used by cleanup.
- Re-reads and revalidates every candidate.
- Performs the same live WNF checks used by cleanup.
- Records qualifying values as `WouldDelete`.
- Does not save the registry key.
- Does not delete values.

Because it checks each value individually, the simulation may take several hours.

Previously approved counts can be supplied as optional additional guards:

```powershell
.\scripts\Invoke-WnfNotificationsRemediation.ps1 `
    -Mode Cleanup `
    -ExpectedCandidateCount 256746 `
    -ExpectedUserScopedCount 4277 `
    -ExpectedTotalRootValues 261024 `
    -WhatIf
```

The cleanup run's immediate internal inventory remains authoritative. External counts are optional safeguards, not a mandatory prerequisite.

## Production cleanup

> [!WARNING]
> Do not use these commands until the read-only output has been reviewed and a tested rollback path is available.

Recommended maintenance sequence:

1. Disable new RDS logons.
2. Log off ordinary user sessions.
3. Reboot the server.
4. Sign in through the physical, hypervisor, or out-of-band console with a local administrator.
5. Verify the VM snapshot or image-level rollback.
6. Run cleanup mode.
7. Reboot immediately after successful cleanup.
8. Validate the server before restoring Gateway/RDS user access.

Production command:

```powershell
.\scripts\Invoke-WnfNotificationsRemediation.ps1 `
    -Mode Cleanup `
    -RollbackConfirmed `
    -MaintenanceWindowConfirmed
```

PowerShell presents a final high-impact confirmation before deletion.

### Cleanup safeguards

Before deleting anything, the script:

- Requires elevation.
- Requires a local account and console session by default.
- Requires explicit maintenance-window and rollback acknowledgements.
- Performs its own complete structural inventory.
- Writes the pre-cleanup summary and fixed candidate list.
- Refuses cleanup if structural safeguards fail.
- Saves the complete Notifications key with `reg save`.
- Verifies that the backup exists and is not empty.
- Records the backup SHA-256 hash.
- Separately exports `Notifications\Data` when available.

For every candidate, the script immediately rechecks:

- 16-character hexadecimal value name.
- `REG_BINARY` type.
- Decoded WNF metadata `0x011`.
- Data length of exactly 72 bytes.
- Complete payload SHA-256 hash.
- Native query success.
- Subscriber state.
- State-data size.
- Change stamp.
- Quiescent state.

The value is preserved when:

- It no longer matches the exact target.
- A native WNF query fails.
- Subscribers are present.
- State data is present.
- The change stamp is nonzero.
- `IsQuiescent` is `False`.
- Registry deletion fails.

The script does not rely on a delete failure to determine whether a state is in use.

### Explicitly preserved

Cleanup does not target:

- The `Notifications` key itself.
- Any subkey.
- `Notifications\Data`.
- `SequenceNumber`.
- The 136-byte, metadata-`0x091` user/AppContainer family.
- Any root value with a different type, length, metadata, or payload.
- Values created after the fixed candidate list was captured.

The script does not reboot automatically.

## Investigation-specific target

The current remediation script is intentionally tied to the family established during the originating investigation:

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

Do not change the hash or broaden the filter merely to make another server produce candidates. A different payload or structure requires a separate analysis.

The 136-byte metadata-`0x091` family observed in the investigation contained structured per-user/AppContainer security descriptors and is deliberately preserved.

## Originating case study

The toolkit originated from a Windows Server 2019 RDS investigation with:

- 261,024 root values under the Notifications key.
- 256,746 exact members of the repeated 72-byte family.
- 4,277 members of a distinct 136-byte user/AppContainer family.
- One `SequenceNumber`.
- Regedit becoming unresponsive and CPU usage spiking when the key was opened.
- Slow logons and periods of high CPU.
- Broken Start and taskbar Search.
- OneDrive authentication and Files On-Demand failures.
- New profiles with nearly empty `%LOCALAPPDATA%\Packages` folders.
- Repeated Cortana and AAD BrokerPlugin AppX registration loops.

A full live audit of all 256,746 target values while users were active found:

```text
Selected/read successfully:       256746
Exact family matches:             256746
Strong live evidence:                  0
Exists, no strong live evidence:  256746
Subscribers present:                   0
State data present:                    0
Nonzero change stamps:                 0
Not quiescent:                         0
Native query failures:                 0
```

The distinction between `Strong live evidence` and `Exists, no strong live evidence` is important: permanent registry-backed state names can report as existing even when no subscribers, state data, nonzero change stamp, or non-quiescent condition is observed.

In the retained seven-day AppXDeploymentServer event window, `Microsoft.Windows.Cortana` registration cycled about 141 times and `Microsoft.AAD.BrokerPlugin` about 140 times. In those repeated sequences, Event 5401 reported `0x80070003` while Windows was unable to create the AppContainer profile; Events 300/401 reported package-registration failure `0x80073CF6`; and Event 404 exposed the underlying internal `0x800705AA` insufficient-system-resources error. Events 603, 607, 854, 855, 10000, 10001, and 10002 showed repeated queuing, manifest processing, resiliency, and related registration activity. These are retained-window observations, not lifetime totals.

Cross-server comparison showed that the affected host reached 256,746 members of the repeated family despite less than 24 hours of uptime. Two other RDS hosts using the same external access path had approximately 18,000 values after 16 days of uptime and approximately 66,000 after 37 days. A lightly used file server had 93 Notifications values, and two additional non-Gateway servers had none of the repeated 72-byte family. This is an environment-level correlation, not a universal threshold and not proof that RD Gateway or any other component created the values.

## Post-cleanup validation

Before returning the server to production, verify:

- The Notifications key opens without Regedit hanging or causing an abnormal CPU spike.
- Start works.
- Taskbar Search works.
- Settings and ShellExperienceHost activate normally.
- A new test profile receives a normally populated package tree.
- Cortana/SearchUI no longer loops through AppX registration failures.
- AAD BrokerPlugin registers and activates normally.
- Microsoft/OneDrive authentication works.
- OneDrive Files On-Demand initializes and operates normally.
- AppXDeploymentServer no longer produces the same rapid registration-failure loop.
- AppReadiness completes instead of continuously retrying.
- StateRepository lock/retry events return to normal levels.
- Known Scheduled Tasks execute normally.
- Server Manager functions normally.
- RDS logon time and CPU behavior improve.

Record Notifications counts:

- Before cleanup.
- Immediately after deletion.
- After reboot.
- After controlled local-administrator logons.
- After controlled Gateway/RDS user logon and logoff cycles.
- Daily during the initial monitoring period.

Cleanup addresses accumulated state. It may not identify or permanently stop the process that created it.

## What this project does not do

- It does not define a universal safe maximum number of registry values.
- It does not assume that keeping 500 or 5,000 values is a Windows-supported baseline.
- It does not delete and recreate the complete Notifications key.
- It does not delete the `Data` subkey.
- It does not modify WindowsApps permissions.
- It does not disable AppReadiness, SystemEventsBroker, or BrokerInfrastructure.
- It does not run Microsoft's historical `wnfcleanup.exe`.
- It does not include or wrap the community `clnotifications` executable.
- It does not identify the process that originally created each WNF state.
- It does not guarantee that the originating leak will not recur.
- It does not replace normal backup, change-control, incident-management, or vendor-support decisions.

## Data handling

Treat all collected output as operationally sensitive.

The remediation output records system, account, session, registry, and backup information. Structural and live-audit output includes WNF state names and hashes. The raw AppX collector intentionally retains environment-specific information. The redacted collector reduces identifiable information on a best-effort basis but still requires manual review before publication or external sharing.

The included `.gitignore` excludes common diagnostic and backup artifacts, including hive saves, registry exports, event-log exports, generated CSVs, diagnostic archives, and toolkit output directories. Review staged files before every public commit; `.gitignore` is not a substitute for that review.

## Related work and references

### Microsoft

- [Registry bloat causes slow logons or insufficient system resources error 0x800705AA in Windows 8.1 — KB3063843](https://support.microsoft.com/en-us/topic/registry-bloat-causes-slow-logons-or-insufficient-system-resources-error-0x800705aa-in-windows-8-1-82a985fb-df27-abda-440b-f3f81a2c949d)
- [Troubleshooting packaging, deployment, and query of Windows apps](https://learn.microsoft.com/en-us/windows/win32/appxpkg/troubleshooting)
- [Issues with AppX, MSIX, or Microsoft Store applications — FSLogix](https://learn.microsoft.com/en-us/fslogix/troubleshooting-appx-issues)
- [Fix problems in Windows Search](https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/fix-problems-in-windows-search) — Windows client/Search background; not a Server 2019 WNF-remediation reference.

KB3063843 documents WNF registration leakage under the same Notifications path and an associated cleanup utility for Windows 8.1 and Windows Server 2012 R2. It is relevant historical evidence for the registry path and symptom pattern, but it does not establish that the older utility is supported on Windows Server 2019.

### Community investigations

- [Windows Server AppX Installation Failures — Joel Leach](https://www.joelleach.net/2024/12/30/windows-server-appx-installation-failures/)
- [Lazy-256/clnotifications](https://github.com/Lazy-256/clnotifications)

The community sources helped identify similar Server 2019 symptoms and prior cleanup approaches. This toolkit uses its own structural classification, live-state auditing, backup, dry-run, and per-value safety checks rather than treating an arbitrary retained-value count as a Windows-defined baseline.

## Contributing

Issues and pull requests are welcome, especially for:

- Read-only testing on additional Windows Server versions.
- Safer output and redaction.
- Improved offline-hive analysis.
- Better post-remediation monitoring.
- Additional native-query validation.
- Documentation corrections.
- Reproducible, anonymized comparison results.

Do not submit production registry exports or logs containing identifiable information.

Changes to remediation filters should include:

- A documented structural basis.
- Read-only evidence.
- Test results.
- Failure-mode analysis.
- Preservation rules.
- A dry-run path.
- Rollback considerations.

## Security and responsible use

Do not publish exploitable environment details or sensitive diagnostic output in a public issue. Use a private communication channel for security-sensitive reports.

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
