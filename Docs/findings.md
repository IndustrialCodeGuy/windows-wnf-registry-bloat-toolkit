# Technical Findings

## Purpose

This document summarizes the technical patterns that the toolkit is designed to detect.

It intentionally avoids treating the originating environment's exact value counts as a universal baseline. The important findings are structural: what types of values were present, what live-state evidence was observed, how AppX failed, and which data must be preserved.

## Notifications registry location

The WNF registrations examined by this toolkit are stored under:

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications
```

The problem is not simply that this key exists or that it contains many values. Windows legitimately stores WNF state information here.

The diagnostic question is whether one registration family has accumulated to an abnormal degree and whether the server is simultaneously showing resource and AppX/AppContainer failures.

## WNF state-name structure

The toolkit decodes WNF state names using the known WNF XOR encoding and inspects metadata fields such as version, lifetime, scope, and permanent-data state.

Two important families were identified during the originating investigation.

### 72-byte system-scoped family

Characteristics:

```text
Value name:     16 hexadecimal characters
Registry type:  REG_BINARY
Data length:    72 bytes
WNF metadata:   0x011
Scope:          System
Lifetime:       Permanent
```

The individual state names had changing unique-ID portions while the complete 72-byte registry payload was identical across the repeated family.

This matters because the data was not random corruption. It was a real and internally consistent WNF registration structure whose abnormal property was uncontrolled accumulation and persistence.

The remediation script is intentionally tied to the exact reference payload established by the project. Do not change the expected hash or broaden the filter simply to make an unrelated server produce candidates.

### 136-byte user-scoped family

Characteristics:

```text
Value name:     16 hexadecimal characters
Registry type:  REG_BINARY
Data length:    136 bytes
WNF metadata:   0x091
Scope:          User
Lifetime:       Permanent
```

The payloads examined in the original investigation contained structured security descriptors associated with:

- `SYSTEM`
- A user/account SID
- An AppContainer SID

The observed relationships were consistent with per-user AppContainer registrations.

These values are deliberately preserved by the remediation workflow.

## Why enumeration order is not a safety rule

Registry enumeration order should not be treated as:

- Creation order.
- Age.
- Last-use order.
- Importance.
- A supported cleanup priority.

For that reason, this toolkit does not use a rule such as "keep the first 500" or "delete everything after the first 5,000."

A value must match the exact target family and pass live-state checks before the remediation script will consider it for deletion.

## Live-state auditing

`Audit-WnfSystemScopeLiveState.ps1` queries the selected WNF states for several forms of observable activity.

The important fields are:

- State-name existence.
- Subscriber presence.
- Quiescent state.
- State-data size.
- Change stamp.
- Native query success.

### How to interpret the results

A permanent registry-backed WNF state can still be reported as existing even if nothing currently subscribes to or uses it.

The strongest "no current activity" pattern is:

```text
Native query:          Success
Subscribers present:  No
State data present:    No
Change stamp:          0
IsQuiescent:           True
```

A complete family showing that pattern provides strong evidence that the family was dormant during the scan.

It does not prove that Windows could never reference a permanent state again in the future. This is why the project combines live checks with:

- Exact structural matching.
- Registry backup.
- A fixed pre-cleanup candidate list.
- Per-value revalidation immediately before deletion.
- Reboot and functional validation.
- Post-cleanup recurrence monitoring.

### Originating full-scan result

The originating server's complete live audit selected and successfully read all 256,746 members of the target family. All 256,746 were exact reference-family matches and native query failures were zero.

```text
Strong live evidence:                  0
Exists, no strong live evidence:  256746
Subscribers present:                   0
State data present:                    0
Nonzero change stamps:                 0
Not quiescent:                         0
Native query failures:                 0
```

The `Exists, no strong live evidence` result is intentional terminology. A permanent registry-backed WNF state can report that its state name exists without showing the subscriber, state-data, change-stamp, or quiescence signals used here as stronger evidence of current activity.

## Confirmed recurrence and creation path

Controlled post-cleanup testing on a reproducible Windows Server 2019 RDS host identified a repeatable trigger and creation path for the exact target family.

With RDP printer redirection enabled:

- New exact 72-byte metadata-`0x011` target-family values appeared during login.
- In the controlled tests, the number of new target-family values matched the number of redirected printers presented to the session.
- Disabling printer redirection stopped the observed per-login target-family growth.
- Procmon attributed the creation path to the `DsmSvc` service host:
  `svchost.exe -k netsvcs -p -s DsmSvc`.
- The captured stack showed `DeviceSetupManager.dll` calling `ntdll!ZwCreateWnfStateName`, followed by kernel activity that persisted the WNF state under the `Notifications` key.
- Procmon tracing around logoff showed `spoolsv.exe` removing session-specific redirected printer queues and corresponding `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\PRINTENUM` instances. A subsequent login created new redirected-printer instances and the DsmSvc WNF-creation path repeated.

The timed watcher provided a second, independent observation. At a 100 ms polling interval across multiple controlled logins, newly created target-family values showed no subscribers, no state data, no nonzero change stamps, and no non-quiescent samples during the captured observation windows.

These results establish the observed trigger, creation path, and post-creation live-state behavior on the reproducible host. They do not establish that every Windows Server 2019 RDS host handles redirected printers in the same way or that printer redirection is universally defective.

### Comparison-host difference

A comparison RDS host in the same environment currently behaves differently:

- The same printer-redirection login tests do not continue adding target-family values.
- It retains a large historical population of `SWD\PRINTENUM` entries.
- The reproducible host, during the same style of inspection, exposes primarily the currently redirected printer instances.
- Updating the reproducible host from OS build `17763.8511` to `17763.9020` did not by itself stop the per-printer recurrence.
- Testing the observed differences in `fDisableCpm` and `UseUniversalPrinterDriverFirst` did not change the reproducible behavior.

The reason for this host-to-host redirected-printer/device-state difference remains unknown.

## Production remediation result

The primary heavily affected server was successfully remediated with the toolkit's targeted cleanup. Previously impaired existing-user functionality returned without separate per-user AppX re-registration, OneDrive repair, WindowsApps-permission changes, or profile repair.

This is strong operational validation of the cleanup as a recovery action on that server. It does not by itself prove that every downstream symptom on every system has the same cause, and it does not establish that cleanup permanently corrects the redirected-printer/device-state behavior that can recreate the target family.

## AppX and AppReadiness failure pattern

A server affected by this condition may show a continuous retry loop rather than a single AppX error.

Relevant sources include:

- `Microsoft-Windows-AppReadiness/Admin`
- `Microsoft-Windows-AppReadiness/Operational`
- `Microsoft-Windows-AppXDeployment/Operational`
- `Microsoft-Windows-AppXDeploymentServer/Operational`
- `Microsoft-Windows-AppModel-Runtime/Admin`
- `Microsoft-Windows-TWinUI/Operational`
- `Microsoft-Windows-StateRepository/Operational`
- Application and System logs

The originating investigation showed repeated failures affecting many user profiles and many built-in package families.

### Observed AppXDeploymentServer sequence

In the retained seven-day event window from the originating case, `Microsoft.Windows.Cortana` version `1.11.6.17763` registration cycled about 141 times and `Microsoft.AAD.BrokerPlugin` version `1000.17763.1.0` about 140 times.

The repeated sequences included:

- Event 5401: `0x80070003` while Windows was unable to create the AppContainer profile.
- Events 300 and 401: package-registration failure `0x80073CF6`.
- Event 404: underlying internal error `0x800705AA` (insufficient system resources).
- Events 603, 607, 854, 855, 10000, 10001, and 10002: repeated queuing, manifest processing, resiliency, and related registration activity.
- `0x800703FA` also appeared during rollback/de-registration activity where registry keys had been marked for deletion.

These are retained-window observations, not lifetime totals. The exact event ordering can vary. The important distinction is between one damaged application and a broad server-wide registration loop affecting multiple users and core packages.

## Packages that expose the impact

The following package families are useful indicators because failures map to visible Windows functionality:

### Microsoft.Windows.Cortana / SearchUI

On Windows Server 2019, repeated registration or activation failure can align with broken taskbar Search.

### Microsoft.AAD.BrokerPlugin

Repeated AppX/AppContainer failure involving AAD BrokerPlugin can affect Microsoft authentication paths used by applications such as OneDrive.

This is evidence of a technical connection between the broader AppX failure and authentication symptoms; it does not prove that every individual sign-in failure used the same transaction.

### Microsoft.Windows.ShellExperienceHost

Failure can align with Start and other shell problems.

### Microsoft.Windows.CloudExperienceHost

Useful as another core package-family check when evaluating profile initialization.

## Profile package-tree pattern

A useful server-wide indicator is a chronological inventory of:

```text
C:\Users\<profile>\AppData\Local\Packages
```

Use:

```powershell
.\Scripts\Get-AppXProfilePackageTimeline.ps1
```

An affected timeline may show:

- Older current profiles with a normally populated `Packages` tree.
- A transition period.
- Newer current profiles with very few package folders.
- Missing Cortana, AAD BrokerPlugin, ShellExperienceHost, and other core folders.
- Rebuilding a profile does not restore normal package population.

The report also shows whether a profile folder still corresponds to `Win32_UserProfile`. This is important because abandoned profile directories can otherwise distort the apparent timeline.

Profile-folder timestamps are supporting evidence, not authoritative account-creation dates.

## StateRepository contention

Heavy AppX registration retry activity can be accompanied by repeated State Repository database-lock or retry events.

Treat this as evidence of contention and load unless there is separate proof of database corruption.

The initial remediation should not delete or rebuild StateRepository or AppRepository databases merely because lock events are present.

## Event-log retention

Some AppX-related event logs are small circular logs and can roll over quickly during a registration storm.

Therefore:

- Retained event counts are often minimum observed counts.
- A short time span in the log does not mean the condition is new.
- Rapid log rollover is itself evidence of sustained event volume.

Collect relevant logs before the maintenance window when possible.

## AppReadiness configuration

AppReadiness participates in per-user AppX/MSIX registration during sign-in.

If it is disabled, restore or validate the configuration appropriate to the server before concluding that WNF cleanup is required.

However, if AppReadiness is running and the same broad registration loop continues, a disabled service alone does not explain the condition.

The toolkit does not disable AppReadiness.

## WindowsApps ACL observations

Do not change the `C:\Program Files\WindowsApps` ACL merely because Effective Access appears unable to evaluate a conditional `BUILTIN\Users` entry.

Conditional package access entries can be legitimate, and cross-domain users still receive local `BUILTIN\Users` group membership.

The originating investigation did not support an ACL change as the remediation.

## Cross-server comparison

A comparison is more useful than a universal count threshold.

Run the same structural inventory on other systems and compare:

- Total root values.
- Size of the repeated 72-byte family.
- Payload hash groups.
- Presence of the 136-byte user-scoped family.
- Server role and interactive-session workload.
- Whether the system shows matching AppX symptoms.

In the originating environment, the affected host reached 256,746 members of the repeated family despite less than 24 hours of uptime. Two other RDS hosts using the same external access path had approximately 18,000 values after 16 days of uptime and approximately 66,000 after 37 days. A lightly used file server had 93 Notifications values, and two additional non-Gateway servers had none of the repeated 72-byte family.

Those comparisons established that the primary server was an extreme outlier, but they did not identify the cause. Subsequent controlled testing on a reproducible RDS host tied new target-family creation to redirected-printer setup and the `DsmSvc` / `DeviceSetupManager.dll` WNF-creation path described above.

The comparison hosts still demonstrate why a universal threshold is inappropriate. One host currently does not reproduce the per-login accumulation despite similar printer-redirection testing, and the reason for that difference remains unresolved.

## Historical Microsoft precedent

Microsoft has previously documented WNF registration leakage under the same Notifications registry key as a cause of:

- Slow logons.
- High CPU.
- `0x800705AA` insufficient-system-resource errors.

That historical fix applied to older Windows/Windows Server versions and involved System Events Broker/Broker Infrastructure components.

This is useful precedent for the failure mechanism, but it does not establish that the older cleanup utility or exact writer applies to Windows Server 2019.

## Community precedent

Other Windows Server 2019 administrators have reported similar combinations of:

- AppX installation/registration failures.
- `0x800705AA`.
- Very large Notifications keys.
- Broken Start or other per-user Windows features.

Community cleanup tools helped establish that the pattern has been seen elsewhere, but they do not define a Microsoft-supported safe retained count.

This toolkit therefore uses exact structural matching and per-value safety checks rather than an arbitrary keep/delete boundary.

## What should be preserved

The remediation workflow is designed to preserve:

- The `Notifications` key itself.
- Every subkey.
- The `Data` subkey.
- `SequenceNumber`.
- The 136-byte metadata-`0x091` user/AppContainer family.
- Any root value that does not match the exact target family.
- Any target-family candidate that changes between inventory and deletion.
- Any candidate with live-state evidence.
- Any candidate whose native WNF query fails.

## What the toolkit intentionally does not infer

The toolkit does not assume:

- Every large Notifications key is affected.
- Every 72-byte state is stale.
- Zero subscribers is sufficient by itself for deletion.
- A reboot automatically clears the condition.
- StateRepository lock events prove database corruption.
- The redirected-printer recurrence path observed on one host applies identically to every Windows Server 2019 RDS host.
- One healthy server establishes a universal threshold.

Use the combination of profile, AppX, structural, live-state, recurrence, and comparison evidence.
