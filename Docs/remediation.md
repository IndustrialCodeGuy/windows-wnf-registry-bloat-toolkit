# Remediation

## Scope

This procedure describes how to use the Windows WNF Registry Bloat Toolkit to confirm and, when appropriate, remediate the specific repeated WNF family recognized by the project's cleanup script.

The cleanup is intentionally narrow. It is not a general-purpose "delete stale WNF values" utility.

Do not proceed solely because the `Notifications` key is large.

## Before considering cleanup

Establish that the server shows a matching evidence pattern.

Recommended read-only checks:

```powershell
.\scripts\Get-AppXProfilePackageTimeline.ps1
```

```powershell
.\scripts\Get-WnfNotificationsStructuralInventory.ps1
```

```powershell
.\scripts\Audit-WnfSystemScopeLiveState.ps1
```

```powershell
.\scripts\Collect-AppXReadinessAudit-Raw.ps1
```

or, for best-effort redacted output:

```powershell
.\scripts\Collect-AppXReadinessAudit-Redacted.ps1
```

Consider cleanup only when the evidence supports a broad server-level condition rather than an isolated application or user-profile problem.

## What the remediation script targets

`Invoke-WnfNotificationsRemediation.ps1` recognizes the exact repeated 72-byte system-scoped family established during the originating investigation.

Candidates must satisfy all of the script's structural checks, including:

- Root-level value.
- 16-character hexadecimal state name.
- `REG_BINARY`.
- WNF metadata `0x011`.
- 72-byte payload.
- Exact known payload hash.

Do not edit the expected hash or relax the structural rules to target a different family.

A different structure requires a separate investigation.

## What cleanup preserves

The script does not intentionally delete:

- The `Notifications` registry key.
- Any Notifications subkey.
- `Notifications\Data`.
- `SequenceNumber`.
- The 136-byte metadata-`0x091` user/AppContainer family.
- Any value with a different type, size, metadata, or payload.
- Any value created after the candidate list is captured.
- Any candidate that changes before deletion.
- Any candidate showing live-state evidence.
- Any candidate whose native WNF queries cannot be completed successfully.

## Read-only remediation audit

Audit mode is the default:

```powershell
.\scripts\Invoke-WnfNotificationsRemediation.ps1
```

This performs the script's immediate structural inventory and exports the current candidate set without changing registry data.

Review the output before continuing.

A prior manually copied candidate count is not required. The cleanup run performs its own immediate pre-cleanup inventory.

Previously approved counts may still be supplied as optional additional safeguards when desired.

## Full cleanup simulation

Before actual cleanup, run:

```powershell
.\scripts\Invoke-WnfNotificationsRemediation.ps1 `
    -Mode Cleanup `
    -WhatIf
```

This follows the cleanup logic without saving the registry key or deleting values.

For every candidate, the script:

- Re-reads the registry value.
- Reconfirms its exact structural match.
- Queries the live WNF subsystem.
- Evaluates subscribers.
- Evaluates state data.
- Checks the change stamp.
- Checks quiescence.
- Records whether the value would be deleted or preserved.

On a heavily populated server, the simulation can take several hours.

The time is useful: it exercises the same per-value checks that will protect the real cleanup.

## Maintenance-window preparation

Before actual cleanup:

1. Schedule a maintenance window.
2. Confirm physical, hypervisor, or out-of-band console access.
3. Verify that a local administrator account is available.
4. Create and verify a VM snapshot, image-level backup, or equivalent rollback method.
5. Retain relevant AppX/AppReadiness event logs and current diagnostic output.
6. Record known pre-existing failures such as Start, Search, OneDrive, Files On-Demand, or slow logons.
7. Disable new RDS logons and ensure Gateway-mediated user sessions are disconnected.
8. Log off ordinary user sessions.
9. Reboot the server.
10. After reboot, preferably sign in through the physical, hypervisor, or
    out-of-band console with a local administrator account.

Based on the observed correlation between the repeated WNF family and Gateway-mediated RDS user activity, it is advisable to keep Gateway users disconnected during cleanup and avoid using a Gateway session for the maintenance work. A physical, hypervisor, or out-of-band console session is preferred. A direct RDP session that does not traverse the Gateway may be lower risk, but this was not specifically validated during the investigation. This is a precautionary recommendation: the investigation did not identify RD Gateway itself as the writer or establish that a direct non-Gateway RDP session would interfere with cleanup.

## Automatic registry backup

Actual cleanup mode creates a backup immediately before deletion.

The script uses `reg save` to save the complete Notifications key to a hive file, verifies that the file exists and is non-empty, and records its SHA-256 hash.

It also attempts a separate readable export of the `Notifications\Data` subkey.

The complete hive save is the required backup. Cleanup does not proceed when that required backup fails.

A `-WhatIf` simulation does not create the backup because it does not modify the registry.

The automatic backup is not a substitute for a verified VM or image-level rollback.

## Actual cleanup

Run:

```powershell
.\scripts\Invoke-WnfNotificationsRemediation.ps1 `
    -Mode Cleanup `
    -RollbackConfirmed `
    -MaintenanceWindowConfirmed
```

The script performs another immediate structural inventory and presents the current candidate information before cleanup. By default, run output is written under `%ProgramData%\WindowsWnfRegistryBloatToolkit\Wnf-Remediation-<Mode>-<timestamp>`.

PowerShell's high-impact confirmation is then used before deletion.

## Per-value safety checks

Immediately before deleting each candidate, the script verifies:

```text
Name:             16 hexadecimal characters
Type:             REG_BINARY
WNF metadata:     0x011
Data length:      72 bytes
Payload:          Exact known hash
```

It then performs the live WNF checks.

A candidate is deleted only if it still matches the exact target and the native checks show no observed live-state evidence. The value is preserved if any of these conditions is true:

- Registry re-read fails.
- Structural match has changed.
- Native WNF query fails.
- Subscribers are present.
- State data is present.
- Change stamp is nonzero.
- `IsQuiescent` is false.
- Registry deletion fails.

The script does not rely on deletion failure as a test for whether a state is in use.

## After cleanup

Reboot the server immediately after the targeted cleanup.

Do not restore normal RDS/Gateway access until the initial validation is complete.

## Validation checklist

Confirm the following before returning the server to normal use:

- Registry Editor can open the Notifications key without becoming unresponsive.
- Opening the key does not cause an abnormal CPU spike.
- Start works normally.
- Taskbar Search works normally.
- Settings and ShellExperienceHost activate normally.
- A new test profile receives a normally populated `%LOCALAPPDATA%\Packages` tree.
- Core package families such as Cortana/SearchUI, AAD BrokerPlugin, and ShellExperienceHost register successfully.
- Microsoft authentication works for a test user.
- OneDrive can sign in.
- OneDrive Files On-Demand initializes and operates normally.
- AppReadiness is no longer continuously retrying the same registration work.
- AppXDeploymentServer no longer produces the same rapid registration-failure loop.
- TWinUI activation failures return to normal background levels.
- StateRepository lock/retry events are no longer occurring as a rapid storm.
- A known Scheduled Task executes normally.
- Server Manager remains functional.
- RDS logon performance and CPU usage are acceptable.

## Monitoring for recurrence

Cleanup removes accumulated state. It does not necessarily remove the condition that originally created the registrations.

After recovery, record structural inventory results:

- Immediately after cleanup.
- After reboot.
- After controlled local logons.
- After controlled RDS/Gateway logon and logoff cycles.
- Daily during the initial monitoring period.

If the repeated family begins growing again, use Process Monitor boot logging or another registry trace to identify processes writing to:

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications
```

Useful follow-up questions include:

- Does each interactive logon create new values?
- Does a clean logoff retire any values?
- Does growth occur only through a particular access path?
- Does a particular service or process perform the `RegSetValue` operations?

## Actions not recommended

Do not:

- Delete the complete `Notifications` key.
- Delete or recreate the `Data` subkey.
- Use registry enumeration order as a measure of age or importance.
- Use an arbitrary "keep the first 500" or "keep the first 5,000" rule.
- Delete the 136-byte user/AppContainer family as part of broad cleanup.
- Modify the WindowsApps ACL solely because Effective Access cannot evaluate a conditional entry.
- Disable `BrokerInfrastructure` or `SystemEventsBroker`.
- Keep `AppReadiness` disabled as a workaround unless the server's supported configuration specifically requires it.
- Rebuild AppRepository or StateRepository databases as an initial response to lock/retry events.
- Repeatedly run broad `Add-AppxPackage` re-registration while the server is still failing at the AppContainer/resource stage.
- Run an older-version Microsoft WNF cleanup utility on Server 2019 solely because it addressed a similar historical problem.
- Modify the remediation script's target hash or structural filters just to make an unrelated system match.

## Rollback

The specific rollback method depends on the server platform and the administrator's normal recovery process.

Before cleanup, verify that the chosen rollback method is practical and tested.

The remediation output should be retained with the change record, including:

- Pre-cleanup structural inventory.
- Candidate list.
- Cleanup action log.
- Registry hive backup.
- Backup hash/manifest.
- AppX diagnostic evidence.
- Post-cleanup structural inventory.

If significant new regressions appear after cleanup, stop normal user access and use the established rollback procedure rather than attempting broad additional registry changes.

## Success criteria

A successful remediation should produce both functional and technical improvement.

Functional indicators:

- Start and Search work.
- Microsoft/OneDrive authentication works.
- Files On-Demand works.
- New profiles initialize correctly.
- RDS logons and CPU behavior improve.

Technical indicators:

- The excessive target family is removed without broad deletion of unrelated Notifications data.
- AppX/AppReadiness registration loops stop.
- AppContainer creation succeeds.
- StateRepository contention returns to normal levels.
- The repeated WNF family does not resume uncontrolled growth during controlled user activity.

If the registry count begins growing again while symptoms remain resolved, continue monitoring and identify the writer before assuming that another cleanup is required.
