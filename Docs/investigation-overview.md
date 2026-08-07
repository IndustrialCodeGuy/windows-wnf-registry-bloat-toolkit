# Investigation Overview

## Purpose

This document explains the problem that led to the Windows WNF Registry Bloat Toolkit, the symptoms that may indicate a similar condition, and the recommended first steps for determining whether a Windows Server 2019 system may be affected.

The toolkit was developed from an investigation of a Windows Server 2019 Remote Desktop Session Host where a very large number of Windows Notification Facility (WNF) registrations had accumulated under:

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications
```

The affected system also showed broad AppX/AppContainer registration failures. The important lesson from the investigation is that the visible symptom may look application-specific — for example, OneDrive sign-in or Search failing — while the underlying problem is server-wide.

This project is intended for authorized administrators and troubleshooting teams. It does not replace normal backup, change-control, rollback, or vendor-support decisions.

## Signs and symptoms

A server affected by this class of problem may show several of the following at the same time:

- Slow or inconsistent RDS logons.
- Periods of unusually high CPU usage during or after user sign-in.
- Registry Editor becoming slow or unresponsive when opening the `Notifications` key.
- Start menu failures or unreliable shell behavior.
- Taskbar Search failing to open or return results.
- OneDrive authentication or sign-in failures.
- OneDrive Files On-Demand not initializing correctly.
- Newly created user profiles with very few folders under `%LOCALAPPDATA%\Packages`.
- Deleting and recreating an affected user profile does not resolve the problem.
- Repeated AppX or AppReadiness registration failures across multiple users and multiple built-in Windows packages.
- Large volumes of AppX, AppReadiness, TWinUI, AppModel Runtime, or StateRepository events.

The strongest indication is not any one symptom. It is the combination of server-level resource symptoms, AppX/AppContainer registration failures, abnormal `Notifications` registry growth, and multiple users being affected.

## Common event errors

The originating investigation repeatedly encountered these errors:

| Error | Typical context |
| --- | --- |
| `0x800705AA` | Insufficient system resources; in the originating case this appeared as the internal AppXDeploymentServer error behind repeated registration failures |
| `0x80070003` | In the originating case, Event 5401 reported this while Windows was unable to create the AppContainer profile |
| `0x80073CF6` | AppX package registration failure; observed in Events 300/401 during the repeated package-registration loop |
| `0x800703FA` | Registry key marked for deletion during rollback/de-registration |

These errors are useful indicators, but none is unique to WNF registry bloat. They should be evaluated together with the registry and profile evidence.

## Why AppX symptoms matter

On Windows Server 2019, several important shell and authentication components rely on per-user AppX registration.

Packages worth checking include:

- `Microsoft.Windows.Cortana` / SearchUI
- `Microsoft.AAD.BrokerPlugin`
- `Microsoft.Windows.ShellExperienceHost`
- `Microsoft.Windows.CloudExperienceHost`

When the system can no longer complete per-user AppContainer creation and AppX registration, the resulting symptoms can appear unrelated:

- Cortana/SearchUI failures can present as broken taskbar Search.
- ShellExperienceHost failures can present as Start or shell problems.
- AAD BrokerPlugin failures can affect Microsoft authentication paths used by applications such as OneDrive.
- New user profiles may contain an unusually small `%LOCALAPPDATA%\Packages` tree.

This is why repeatedly rebuilding individual profiles or broadly re-registering AppX packages may fail to solve the underlying server-level condition.


## Originating-case evidence snapshot

The cleanup target and documentation are grounded in a specific Server 2019 incident rather than a generic value-count threshold.

The affected host contained 261,024 root values, including 256,746 exact members of one 72-byte metadata-`0x011` family and 4,277 members of the separate 136-byte metadata-`0x091` user/AppContainer family.

A full live audit of all 256,746 target-family values, performed while users were active, completed without native-query failures. All 256,746 state names still reported as existing, but none showed the stronger activity indicators used by this toolkit: subscribers, state data, a nonzero change stamp, or a non-quiescent state. This distinction is important because permanent registry-backed WNF states may continue to report as existing without showing current activity.

In the retained seven-day AppXDeploymentServer event window, `Microsoft.Windows.Cortana` registration repeated about 141 times and `Microsoft.AAD.BrokerPlugin` about 140 times. Event 5401 reported `0x80070003` while AppContainer-profile creation failed; Events 300/401 reported `0x80073CF6`; Event 404 exposed the underlying internal `0x800705AA` insufficient-system-resources error. Related Events 603, 607, 854, 855, 10000, 10001, and 10002 showed repeated queuing, manifest processing, resiliency, and registration work. These are retained-window counts, not lifetime totals.

Cross-server comparison also showed that value count alone is not a sufficient rule. The affected server reached 256,746 members of the repeated family with less than 24 hours of uptime. Two other RDS hosts using the same external access path had approximately 18,000 values after 16 days and approximately 66,000 after 37 days. A lightly used file server had 93 Notifications values, while two additional non-Gateway servers had none of the repeated 72-byte family. That pattern is correlation, not proof that RD Gateway or another specific component is the writer.

## First check: profile package timeline

Run:

```powershell
.\scripts\Get-AppXProfilePackageTimeline.ps1
```

The report is sorted by profile-folder creation time and records:

- Whether each profile is currently registered.
- Whether the profile is loaded.
- Whether `%LOCALAPPDATA%\Packages` exists and can be read.
- Number of package folders.
- First and last package-folder creation times.
- Presence of several core Windows package families.
- Supporting profile timestamps such as `NTUSER.DAT` and `UsrClass.dat`.

Look for a clear chronological transition where older valid profiles have normally populated package trees while newer valid profiles suddenly have very few package folders or are missing the core packages.

Old or stale folders should not automatically be treated as evidence. Use the `RegisteredProfile` field to distinguish current profiles from abandoned profile directories.

The transition should be treated as a time range, not an exact failure timestamp.

## Second check: structural inventory of the Notifications key

Run:

```powershell
.\scripts\Get-WnfNotificationsStructuralInventory.ps1
```

This performs a read-only inventory of the root values under the Windows `Notifications` registry key.

The toolkit distinguishes two structures observed during the originating investigation:

- A repeated 72-byte system-scoped WNF family using metadata `0x011`.
- A structured 136-byte user-scoped WNF family using metadata `0x091`.

The 72-byte structure was a valid Windows registration type, but excessive persistent accumulation of that family was the abnormal condition.

The 136-byte values contained structured per-user/AppContainer security descriptors and were treated as legitimate user-scoped registrations. They should not be removed simply because they are numerous.

### What should concern you

There is no universal safe count for the `Notifications` key.

Concern should increase when several of these conditions are present:

- The key contains an unusually large number of root values.
- Most of the key is made up of one repeated 72-byte family.
- Registry Editor struggles to enumerate the key.
- The same server has AppX/AppReadiness failures and affected user profiles.
- Counts remain very large after a reboot.
- Comparable servers with similar roles have dramatically lower counts or none of the repeated family.

Do not infer safety or danger from a single numeric threshold.

## Third check: compare other servers

Where practical, run the structural inventory on comparable systems:

```powershell
.\scripts\Get-WnfNotificationsStructuralInventory.ps1 `
    -ServerLabel 'Comparison-RDS-01'
```

Useful comparisons include:

- Another RDS host with similar user workload.
- An RDS host with different access patterns.
- A server that does not host interactive user sessions.
- A recently built or known-good server.

The goal is to determine whether the repeated family is normal for the environment, whether it appears to accumulate with a particular workload, and whether the affected server is an outlier.

Correlation is not proof of the process creating the values. The registry entries do not expose a creator process or per-value creation timestamp.

## Fourth check: live WNF state

After the structure is understood, run a sample live audit:

```powershell
.\scripts\Audit-WnfSystemScopeLiveState.ps1
```

The script checks the repeated system-scoped family for observable live-state evidence, including:

- Native WNF query success.
- Subscribers.
- State data.
- Change stamp.
- Quiescence.

After validating a sample, a complete scan can be run:

```powershell
.\scripts\Audit-WnfSystemScopeLiveState.ps1 -FullScan
```

A full scan of a heavily populated key can take several hours.

The absence of subscribers, state data, change stamps, and non-quiescent states is strong evidence that the values were dormant during the scan, but it is not an absolute guarantee that a permanent state name could never be referenced again.

## Fifth check: collect AppX and AppReadiness evidence

For local operational troubleshooting:

```powershell
.\scripts\Collect-AppXReadinessAudit-Raw.ps1
```

For output intended to be reviewed or shared more broadly:

```powershell
.\scripts\Collect-AppXReadinessAudit-Redacted.ps1
```

The collectors gather evidence from the AppX, AppReadiness, AppModel, TWinUI, StateRepository, shell, authentication, profile, Application, and System event sources where available.

Look for repeated registration attempts affecting multiple users and multiple built-in packages rather than one isolated package failure.

The redacted collector performs best-effort replacement of environment-specific identifiers. Review its output manually before public or external sharing.

## Indicators that the server is likely affected

The evidence is strongest when all of the following line up:

1. Multiple users or newly created profiles are affected.
2. Newer valid profiles have abnormally sparse AppX package folders.
3. AppX/AppReadiness repeatedly fail with resource, AppContainer, or package-registration errors.
4. The `Notifications` key contains a very large repeated system-scoped WNF family.
5. A live audit finds little or no observable activity in that repeated family.
6. Comparable systems provide a meaningful contrast.
7. The symptoms persist through ordinary profile repair or reboot.

At that point, use the remediation procedure rather than attempting broad registry deletion or indiscriminate AppX repair.

## What this evidence does not prove

The toolkit cannot, by itself:

- Identify the exact process that originally created every WNF state.
- Determine a creation time or last-use time for each state.
- Establish a universal "healthy" Notifications value count.
- Prove that RD Gateway, RD Connection Broker, SystemEventsBroker, or any other specific component is the writer.
- Guarantee that the accumulation will not recur after cleanup.
- Determine that every 72-byte WNF registration on every Windows version is safe to remove.

The remediation tool is intentionally narrow and should remain that way.

## Next steps

Once the server has been identified as a likely match:

- Review [Technical Findings](findings.md) for the structural and event patterns the toolkit is designed around.
- Follow [Remediation](remediation.md) for the audit, simulation, cleanup, validation, and monitoring workflow.
