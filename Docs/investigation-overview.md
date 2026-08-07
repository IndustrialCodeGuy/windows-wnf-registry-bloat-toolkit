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


## Evidence supporting the cleanup target

The remediation logic is based on a specific WNF registration structure that was extensively analyzed before cleanup was considered. The important finding was not a particular registry-value count, but the combination of a very large repeated system-scoped family, broad AppX/AppContainer failures, and an absence of observable live activity across the target family.

In the originating investigation, the Notifications key had grown into the hundreds of thousands of values, with the overwhelming majority belonging to one identical 72-byte metadata-0x011 system-scoped family. A separate 136-byte metadata-0x091 user/AppContainer family showed structured per-user security descriptors and was treated as legitimate data that must be preserved.

A complete live audit queried more than 250,000 members of the repeated system-scoped family while the server was in active use. The state names continued to report as existing, as expected for permanent registry-backed WNF states, but none showed the stronger activity indicators used by this toolkit: subscribers, state data, a nonzero change stamp, or a non-quiescent state. Native queries also completed without failures.

At the same time, AppX and AppReadiness logs showed continuous registration failures affecting multiple built-in Windows components, including Cortana/SearchUI, AAD BrokerPlugin, and ShellExperienceHost. The recurring failure pattern included 0x80070003, 0x80073CF6, and underlying 0x800705AA insufficient-system-resource errors, along with repeated queuing, resiliency, and registration activity.

Comparison with other servers reinforced that value count alone is not a cleanup rule. Systems with similar interactive workloads could contain substantial quantities of the same registration family without yet showing the same degree of failure, while servers without that workload contained little or none of it. Reboots also did not necessarily clear the accumulated registrations.

For that reason, this toolkit does not define a universal healthy count and does not infer the creating process from the correlation. Cleanup is based on the exact target-family structure, live-state checks, supporting AppX symptoms, and administrator review rather than a numeric threshold.

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
