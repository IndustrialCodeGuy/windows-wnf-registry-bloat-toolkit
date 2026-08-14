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

## Confirmed recurrence findings

Controlled post-cleanup testing on Windows Server 2019 RDS hosts has narrowed the recurrence mechanism substantially.

On a reproducible affected host:

- Enabling RDP printer redirection caused new members of the exact 72-byte metadata-`0x011` target family to appear during login.
- Disabling printer redirection stopped the observed per-login target-family growth.
- Procmon attributed the WNF creation path to the `DsmSvc` service host: `svchost.exe -k netsvcs -p -s DsmSvc`.
- The captured call stack showed `DeviceSetupManager.dll` calling `ntdll!ZwCreateWnfStateName`, followed by persistence under the permanent `Notifications` registry store.
- In a controlled four-login capture with two redirected printers per login, eight redirected printer devices produced eight new exact-family WNF values.
- The state names decode as **Permanent / System** and advance by one WNF sequence number per allocation (`+0x800` in the encoded name).
- At logoff, `spoolsv.exe` successfully removed the session-specific redirected printer and `SWD\PRINTENUM` state, but the capture showed no matching deletion of the target WNF values.
- A 100 ms live-state watcher across multiple controlled logins observed no subscribers, state data, nonzero change stamps, or non-quiescent samples for the newly created target-family values during the observation windows.

A comparison host in the same environment behaves differently:

- Multi-user Procmon captures show substantial redirected-printer and `SWD\PRINTENUM` activity without one new target allocation per printer/login.
- In one analyzed scan, 36 distinct redirected-printer device records spanning 27 redirected-session suffixes were examined while only four new target states were allocated.
- A confirmed initial RDP session with seven redirected printers produced four new target states, not seven.
- Printer/SWD delete operations were captured on the comparison host without corresponding target `Notifications` deletes in the analyzed interval.
- After cleanup, the comparison host's target count rose from roughly 20 to more than 200 as ordinary users returned, but later repeated activity did not continue at the affected host's one-new-state-per-printer/login rate.

The current best-fit model is therefore **reuse versus recreation**: the comparison host appears able to reuse existing persistent registration state for many recurring redirected devices, while the affected host repeatedly requests fresh permanent/system WNF state names. The stable identity or property that controls reuse has not yet been identified, so this remains an evidence-based working model rather than a documented Microsoft implementation detail.

Several narrowing tests did **not** change the recurrence on the affected host: updating from build `17763.8511` to `17763.9020`, explicit `fDisableCpm` testing, switching the redirected printer to an installed manufacturer/native driver with `UseUniversalPrinterDriverFirst = 4`, and keeping Remote Registry alive with `DisableIdleStop = 1`. PrintService Event ID 603 was not present on either comparison server during targeted scans.

These findings establish the observed trigger and creation path on the reproducible host. They do **not** establish that printer redirection itself is universally defective or that every Server 2019 RDS host handles redirected-device/WNF registration reuse the same way.

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
| `Get-WnfPermanentNotificationsStructuralInventory.ps1` | Inventories the permanent `Notifications` store, including decoded Version/Lifetime/DataScope/PermanentData/Sequence fields, payload groups, and target-family statistics. | No |
| `Get-WnfVolatileNotificationsStructuralInventory.ps1` | Inventories `VolatileNotifications` without assuming the permanent-store target family applies there. | No |
| `Get-WnfWellKnownNotificationsStructuralInventory.ps1` | Inventories `HKLM\SYSTEM\CurrentControlSet\Control\Notifications` and decodes its WNF state-name structure. | No |
| `Get-WnfNotificationValues.ps1` | Reads and exports a selected range of root-level `Notifications` values for inspection. | No |
| `Find-WnfNotificationValuesOutsideReferenceFamily.ps1` | Auto-discovers an exact member of the confirmed 72-byte target family and identifies root values outside that family for further analysis. | No |
| `Analyze-WnfUserScopePayloads.ps1` | Analyzes the 136-byte user-scoped WNF family and its user/AppContainer security-descriptor structure. | No |
| `Audit-WnfSystemScopeLiveState.ps1` | Automatically locates an exact member of the confirmed 72-byte target family, then queries a sample or full scan for observable live-state evidence. | No |
| `Watch-WnfSystemScopeLiveState.ps1` | Repeatedly polls exact target-family values over a timed window, tracks newly observed values, and records whether live-state evidence ever appears during settling or post-settle periods. | No |
| `Get-AppXProfilePackageTimeline.ps1` | Builds a chronological inventory of per-profile AppX package-folder population and core package presence. | No |
| `Collect-AppXReadinessAudit-Raw.ps1` | Collects detailed AppX, AppReadiness, shell, authentication, StateRepository, profile, service, and event-log evidence. | No |
| `Collect-AppXReadinessAudit-Redacted.ps1` | Collects similar evidence with best-effort redaction of environment-specific identifiers. | No |
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
├── Scripts/
│   ├── Analyze-WnfUserScopePayloads.ps1
│   ├── Audit-WnfSystemScopeLiveState.ps1
│   ├── Watch-WnfSystemScopeLiveState.ps1
│   ├── Collect-AppXReadinessAudit-Raw.ps1
│   ├── Collect-AppXReadinessAudit-Redacted.ps1
│   ├── Find-WnfNotificationValuesOutsideReferenceFamily.ps1
│   ├── Get-AppXProfilePackageTimeline.ps1
│   ├── Get-WnfPermanentNotificationsStructuralInventory.ps1
│   ├── Get-WnfVolatileNotificationsStructuralInventory.ps1
│   ├── Get-WnfWellKnownNotificationsStructuralInventory.ps1
│   ├── Get-WnfNotificationValues.ps1
│   └── Invoke-WnfNotificationsRemediation.ps1
└── Docs/
    ├── investigation-overview.md
    ├── findings.md
    └── remediation.md
```

Do not publish production logs, registry exports, hive backups, user SIDs, server names, tenant identifiers, or unreviewed event data.

## Documentation

- [Investigation overview](Docs/investigation-overview.md) — signs and symptoms, how to determine whether a server may be affected, and the recommended diagnostic workflow.
- [Technical findings](Docs/findings.md) — WNF structures, live-state interpretation, AppX/AppContainer failure patterns, and preservation boundaries.
- [Remediation procedure](Docs/remediation.md) — audit, `-WhatIf`, maintenance-window cleanup, backup, validation, and recurrence monitoring.

## Quick start

Open an elevated **64-bit Windows PowerShell 5.1** window from the repository root.

If the downloaded files are blocked:

```powershell
Get-ChildItem .\Scripts\*.ps1 | Unblock-File
```

### 1. Check the user-profile timeline

```powershell
.\Scripts\Get-AppXProfilePackageTimeline.ps1
```

This can reveal a chronological transition from normally populated AppX profiles to newer profiles with very few package folders or missing core package families.

Stale profile folders are retained in the report and identified separately so they can be excluded from timeline interpretation without losing the evidence.

### 2. Inventory the Notifications key

```powershell
.\Scripts\Get-WnfPermanentNotificationsStructuralInventory.ps1
```

The inventory reports:

- Total root-level values.
- `SequenceNumber`.
- 72-byte metadata-`0x011` system-scoped values.
- 136-byte metadata-`0x091` user-scoped values.
- Other root values.
- Distinct SHA-256 payload groups.
- Matches to the toolkit's reference payload.
- Decoded Version, Lifetime, DataScope, PermanentData, and WNF Sequence values, including sequence ranges/gaps/runs.

There is no universal safe value count. Compare the structure with the server's symptoms and, when possible, with similar systems.

The related WNF stores can be inventoried independently:

```powershell
.\Scripts\Get-WnfVolatileNotificationsStructuralInventory.ps1
.\Scripts\Get-WnfWellKnownNotificationsStructuralInventory.ps1
```

The permanent-store problem family should not be assumed to exist in either related store; the scripts classify what is actually present.

### 3. Run a live WNF sample

```powershell
.\Scripts\Audit-WnfSystemScopeLiveState.ps1
```

When no `-ReferenceValueName` is supplied, the script automatically locates an exact current member of the toolkit's confirmed target family using the same fixed structural boundary documented below: `REG_BINARY`, decoded metadata `0x011`, 72-byte length, and the confirmed SHA-256 payload hash. The discovered value's complete payload is then used as the byte-for-byte reference for the live audit. An explicitly supplied `-ReferenceValueName` must match that same family.

The audit checks for:

- Native WNF query success.
- Subscribers.
- Quiescence.
- State data.
- Change stamp.

After validating a sample, a full scan can be run:

```powershell
.\Scripts\Audit-WnfSystemScopeLiveState.ps1 -FullScan
```

A complete scan of a heavily populated family may take several hours.

The absence of subscribers, state data, nonzero change stamps, and non-quiescent states is strong evidence that the states were dormant during the scan. It is not an absolute guarantee of future non-use.

### 4. Collect AppX and AppReadiness evidence

For full local diagnostic output:

```powershell
.\Scripts\Collect-AppXReadinessAudit-Raw.ps1
```

For best-effort redacted output:

```powershell
.\Scripts\Collect-AppXReadinessAudit-Redacted.ps1
```

The collectors gather available evidence from AppReadiness, AppX deployment, AppModel Runtime, TWinUI, Search, shell, authentication, StateRepository, profile, Application, and System sources.

> [!IMPORTANT]
> Redaction is best-effort. Event messages are free-form, and no automated process can guarantee that every environment-specific identifier was removed. Review generated output before sharing it outside the intended administrative team.

### 5. Run the remediation script in read-only mode

Audit is the default:

```powershell
.\Scripts\Invoke-WnfNotificationsRemediation.ps1
```

The script performs an immediate structural inventory and exports its fixed candidate list without making registry changes.

### 6. Simulate cleanup

```powershell
.\Scripts\Invoke-WnfNotificationsRemediation.ps1 `
    -Mode Cleanup `
    -WhatIf
```

The simulation performs the same per-candidate structural and live-state checks used by actual cleanup, but records qualifying values as `WouldDelete` instead of removing them.

For a large candidate family, this can take several hours.

### Remediation script parameters

`Invoke-WnfNotificationsRemediation.ps1` supports the following script-specific parameters:

| Parameter | Default | Purpose |
| --- | --- | --- |
| `-Mode` | `Audit` | Selects read-only structural audit or guarded cleanup mode. Valid values are `Audit` and `Cleanup`. |
| `-ExpectedCandidateCount` | `0` | Optional additional cleanup guard. A nonzero value requires the immediate cleanup inventory to match the supplied exact-target candidate count; `0` accepts the current count. |
| `-ExpectedUserScopedCount` | `-1` | Optional additional guard for the 136-byte metadata-`0x091` user-scoped family. `-1` skips this comparison. |
| `-ExpectedTotalRootValues` | `0` | Optional additional guard for the total root-value count. `0` skips this comparison. |
| `-OutputRoot` | `%ProgramData%\WindowsWnfRegistryBloatToolkit` | Parent directory for the timestamped run folder. |
| `-IncludeLiveCheck` | Off | In `Audit` mode, performs the same per-value native WNF live checks used by cleanup without deleting anything. |
| `-RollbackConfirmed` | Off | Required acknowledgement for an actual cleanup run. It confirms that an independent rollback path has been verified. |
| `-MaintenanceWindowConfirmed` | Off | Required acknowledgement for an actual cleanup run. It confirms that cleanup is being performed during an approved maintenance window. |
| `-AllowNonConsoleSession` | Off | Explicitly overrides the default requirement to run cleanup from a console session. The override is logged. |
| `-AllowNonLocalAccount` | Off | Explicitly overrides the default requirement to run cleanup using a local account. The override is logged. |
| `-MaximumDeleteFailures` | `5` | Maximum deletion failures tolerated before cleanup stops. |
| `-ProgressInterval` | `2500` | Number of values between progress-display updates during large inventories. |
| `-CsvBatchSize` | `500` | Number of action rows buffered before batched CSV output. |
| `-FlushInterval` | `5000` | Number of processed candidates between forced output flushes. |

Because the script supports PowerShell `ShouldProcess`, `-WhatIf` can be used with cleanup mode to run the full per-candidate simulation without deleting values:

```powershell
.\Scripts\Invoke-WnfNotificationsRemediation.ps1 `
    -Mode Cleanup `
    -WhatIf
```

The console-session and local-account checks are independent safety gates. If both conditions are intentionally being overridden, both switches are required:

```powershell
.\Scripts\Invoke-WnfNotificationsRemediation.ps1 `
    -Mode Cleanup `
    -RollbackConfirmed `
    -MaintenanceWindowConfirmed `
    -AllowNonConsoleSession `
    -AllowNonLocalAccount
```

Do not use either override unless the corresponding safety condition has been deliberately reviewed and accepted.

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
.\Scripts\Invoke-WnfNotificationsRemediation.ps1 `
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

## Post-cleanup and recurrence investigation

Cleanup removes accumulated target-family values, but it does not by itself identify why new values may be created later. The following read-only/diagnostic tools are intended for controlled recurrence testing.

### Timed live-state watcher

Use `Watch-WnfSystemScopeLiveState.ps1` to repeatedly query exact target-family values over a defined observation window:

```powershell
.\Scripts\Watch-WnfSystemScopeLiveState.ps1 `
    -IntervalMilliseconds 250 `
    -DurationMinutes 15 `
    -SettleSeconds 120
```

The watcher:

- Finds exact current members of the fixed target family.
- Adds newly observed target-family values to a persistent watch set for the remainder of the run.
- Repeatedly records native-query success, subscribers, quiescence, state-data size, and change stamp.
- Gives each newly observed value its own settling timer beginning when that value is first seen.
- Separates `LoginOrSettling` samples from later `PostSettle` samples.
- Reports whether observable live-state evidence was ever seen during the run and whether it was seen after the settling period.

For short-lived activity around a controlled login, a smaller interval can be used:

```powershell
.\Scripts\Watch-WnfSystemScopeLiveState.ps1 `
    -IntervalMilliseconds 100 `
    -DurationMinutes 20 `
    -SettleSeconds 120
```

Sub-second polling increases registry, native-query, and output-file activity. The watcher is read-only with respect to the `Notifications` registry values and WNF state names.

For the cleanest login experiment, start the watcher before the controlled RDS/RD Gateway login. It can also be run as `SYSTEM` in an on-demand Scheduled Task so that observation continues while the initiating administrator logs off and reconnects.

Absence of subscribers, state data, nonzero change stamps, and non-quiescent observations across a high-frequency polling window is strong evidence of dormancy during that window. It is not an absolute guarantee that a state can never be used later.

In controlled recurrence testing, the watcher was run at a 100 ms interval across multiple RDS login cycles while new target-family values were being created. No observable live-state evidence was recorded for those values during the captured windows.

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

Subsequent controlled post-cleanup testing identified a repeatable creation path on an affected RDS host: redirected printers were instantiated during login, `DsmSvc` / `DeviceSetupManager.dll` called `ZwCreateWnfStateName`, and new exact target-family values were persisted under `Notifications`. High-frequency live-state monitoring did not observe those newly created values becoming active during the captured login/post-login windows.

The primary heavily affected server was successfully remediated with the toolkit and broad server-level functionality improved. Most tested users recovered Start/OneDrive behavior, and clean/new package initialization worked again. A subset of users with already populated `%LOCALAPPDATA%\Packages` trees continued to have OneDrive sign-in problems. Those users had reportedly worked earlier, before broad AppX re-registration/reinstall attempts, so earlier troubleshooting may have left separate per-user package/profile damage; that causal link is plausible but unproven.

Comparison systems in the same environment remain important because the redirected-printer/device-state lifecycle is not identical on every host. Larger Procmon captures now suggest that the comparison host often reuses existing state while the affected host repeatedly recreates permanent/system state names, but the exact reuse identity remains unresolved. The current testing does not establish a universal healthy count or implementation rule.

The project documentation intentionally focuses on the repeatable diagnostic pattern rather than treating originating counts or one environment's printer behavior as universal thresholds.

## Post-cleanup validation

Before returning a server to normal production use, verify:

- The `Notifications` key opens without Registry Editor hanging or causing an abnormal CPU spike.
- Start works.
- Taskbar Search works.
- Settings and ShellExperienceHost activate normally.
- A new test profile receives an appropriately populated package tree.
- Cortana/SearchUI and AAD BrokerPlugin register and activate normally.
- Microsoft/OneDrive authentication works.
- OneDrive Files On-Demand works for a clean/new test profile.
- Previously modified profiles are evaluated separately; a residual per-user OneDrive failure does not by itself prove that the server-wide WNF condition persists.
- AppX/AppReadiness registration loops stop.
- StateRepository lock/retry activity returns to normal background levels.
- Known Scheduled Tasks execute normally.
- Server Manager remains functional.
- RDS logon time and CPU behavior improve.

Monitor the Notifications structure after cleanup, reboot, controlled user logons, and during the initial production period.

Where recurrence is observed, compare exact target-family names/counts before and after controlled RDS logins with printer redirection enabled and disabled. On the reproducible host, printer redirection is the confirmed trigger for repeated allocations. On the comparison host, the key question is whether an already-seen user/printer/device relationship causes a new allocation or reuses existing state.

Cleanup removes accumulated state. It does not change RDS printer-redirection policy or guarantee that the redirected-printer/device lifecycle that created the states will stop recurring.

## What this project does not do

- It does not define a universal safe maximum number of registry values.
- It does not assume that keeping an arbitrary number of values is a Windows-supported baseline.
- It does not delete and recreate the complete `Notifications` key.
- It does not delete the `Data` subkey.
- It does not modify WindowsApps permissions.
- It does not disable AppReadiness, SystemEventsBroker, or BrokerInfrastructure.
- It does not run Microsoft's historical `wnfcleanup.exe`.
- It does not include or wrap the community `clnotifications` executable.
- It does not guarantee complete causal attribution of WNF state creation across all systems. Procmon or ETW may still be required for call-stack attribution.
- It does not modify printer-redirection configuration or the redirected-printer/device lifecycle that has been observed to trigger recurrence on an affected host.
- It does not yet explain the host-to-host difference in `SWD\PRINTENUM` retention/reuse behavior or identify the stable identity used for reuse.
- It does not assume permanent/system target values should be deleted at every user logoff; current captures instead favor a reuse-versus-recreate distinction.
- It does not attribute residual OneDrive problems in previously modified profiles to earlier AppX repair attempts as a proven fact.
- It does not guarantee that the originating accumulation will not recur.
- It does not replace normal backup, change-control, incident-management, or vendor-support decisions.

## Data handling

Treat collected output as operationally sensitive.

The remediation output can contain system, account, session, registry, and backup information. Structural, live-audit, and timed-watcher output includes WNF state names and hashes. Procmon or other external trace output can additionally contain account names, process paths, session information, registry paths, and call stacks. Redacted AppX output should still be manually reviewed before publication or external sharing.

Do not commit production diagnostic output such as:

```text
*.hiv
*.reg
*.evtx
*.pml
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
- [Memory leak in the Remote Registry service — Microsoft Support](https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/memory-leak-remote-registry-service)

Microsoft KB3063843 documents a WNF registration leak in the same registry area and a matching slow-logon/high-CPU/`0x800705AA` symptom pattern on Windows 8.1 and Windows Server 2012 R2. It is useful historical precedent, but it does not establish that its cleanup utility is supported on Windows Server 2019.

### Community investigations

- [Windows Server AppX Installation Failures — Joel Leach](https://joelleach.net/2024/12/30/windows-server-appx-installation-failures/)
- [Lazy-256/clnotifications](https://github.com/Lazy-256/clnotifications)
- [CVE-2021-31956: Exploiting the Windows Kernel (NTFS with WNF) — NCC Group](https://www.nccgroup.com/research/cve-2021-31956-exploiting-the-windows-kernel-ntfs-with-wnf-part-1/)
- [wnfun / WNF research utilities — Alex Ionescu et al.](https://github.com/ionescu007/wnfun)

These community sources document similar Server 2019 behavior and prior cleanup approaches. This toolkit uses structural classification, live-state auditing, backup, dry-run, and per-value safety checks rather than an arbitrary retained-value threshold.

## Contributing

Issues and pull requests are welcome, especially for:

- Read-only testing on additional Windows Server versions.
- Additional anonymized comparison results.
- Safer output and redaction.
- Improved profile-timeline analysis.
- Better post-remediation monitoring.
- Additional recurrence/writer-attribution testing.
- Redirected-printer and `SWD\PRINTENUM` lifecycle comparison data.
- Additional native-query validation.
- Documentation corrections.

Do not submit production registry exports or logs containing identifiable information.

Changes to remediation filters should include a documented structural basis, read-only evidence, test results, preservation rules, a dry-run path, and rollback considerations.

## Security and responsible use

Do not publish sensitive diagnostic output or environment details in a public issue.

The tools are intended for authorized administration of systems you own or manage.

## License

Copyright (C) 2026 Dan Michel.

This project is licensed under the [GNU General Public License version 3](LICENSE) (`GPL-3.0-only`).

Commercial and private use are permitted. If you redistribute the project, including modified or derivative versions, the GPLv3 license and corresponding-source requirements apply. This summary is provided for convenience; the `LICENSE` file contains the terms that govern use and distribution.

See [NOTICE](NOTICE) for project attribution and independence information.

## Independence and trademarks

Windows WNF Registry Bloat Toolkit is an independent third-party project. It is not affiliated with, endorsed by, or distributed by Microsoft.

Windows and Windows Server are trademarks of the Microsoft group of companies. Their names are used only to identify the operating environments for which this software was developed.

## Disclaimer

The software is provided on an “AS IS” basis, without warranties or conditions of any kind. Registry cleanup and low-level Windows troubleshooting can cause service interruption or data loss when used incorrectly. Review the scripts, test in a non-production environment, maintain verified backups, and follow your organization's change-control procedures.
