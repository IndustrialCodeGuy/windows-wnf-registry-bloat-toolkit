# Technical Findings

## Purpose

This document summarizes the technical patterns that the toolkit is designed to detect.

It intentionally avoids treating the originating environment's exact value counts as a universal baseline. The important findings are structural: what types of values were present, what live-state evidence was observed, how AppX failed, and which data must be preserved.

## WNF registry stores examined

The original bloat condition is under the permanent WNF state-name store:

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Notifications
```

Two related stores are now inventoried separately for comparison:

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\VolatileNotifications
HKLM\SYSTEM\CurrentControlSet\Control\Notifications
```

The toolkit refers to these as the permanent, volatile/persistent, and well-known stores respectively. The scripts decode the lifetime and scope from each 16-character WNF state name instead of assuming that every value in a registry location has the same structure.

The problem is not simply that one of these keys exists or contains many values. Windows legitimately stores WNF state-name metadata in these locations. The diagnostic question is whether a particular registration family has accumulated abnormally and whether that structural finding aligns with server symptoms and runtime evidence.

An initial inventory of `VolatileNotifications` on one investigated Server 2019 host contained only two root values; both were 16-character `REG_BINARY` WNF-style names with decoded metadata `0x021`, with 64-byte and 72-byte payloads. That small sample is comparison evidence only, not a universal baseline. The `Control\Notifications` store contained a larger population and is now inventoried separately rather than being conflated with the problem key.

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

The individual state names had changing sequence portions while the complete 72-byte registry payload was identical across the repeated family.

Further decoding confirmed that the observed names are consecutive WNF state-name allocations. For example, `41C64E6DA162B865` decodes to Version 1, Permanent lifetime, System scope, `PermanentData = False`, and sequence `0x5BD7`; the next observed name `41C64E6DA162C065` decodes to sequence `0x5BD8`. Because the sequence field begins at bit 11, a one-step sequence increment appears as `+0x800` in the encoded 64-bit state name. Long captured runs followed this exact progression.

This matters because the data was not random corruption or arbitrary registry naming. It was a real and internally consistent series of permanent, system-scoped WNF state-name allocations whose abnormal property was repeated accumulation.

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

With RDP printer redirection enabled on the reproducible host:

- New exact 72-byte metadata-`0x011` target-family values appeared during login.
- Disabling printer redirection stopped the observed per-login target-family growth.
- Procmon attributed the creation path to the `DsmSvc` service host: `svchost.exe -k netsvcs -p -s DsmSvc`.
- The captured stack showed `DeviceSetupManager.dll` calling `ntdll!ZwCreateWnfStateName`, followed by kernel activity that persisted the WNF state under the permanent `Notifications` store.
- In a controlled four-login capture with two redirected printers per login, eight redirected printer devices were processed and eight new exact-family values were written: effectively one new target allocation per redirected printer in that capture.
- The new state names advanced by exactly one decoded WNF sequence number each time (`+0x800` in the encoded name).

Procmon also exposed the device lifecycle immediately around the write. A redirected queue was represented under `HKLM\SYSTEM\CurrentControlSet\Enum\SWD\PRINTENUM`; `DsmSvc` processed that software-device instance; and a 72-byte permanent/system WNF value was then created. The `FriendlyName` data in the trace allowed individual target writes to be associated with specific redirected printers.

### Logoff and teardown observations

The same controlled bad-host trace captured complete printer teardown activity. `spoolsv.exe` removed the redirected printer registry trees and the corresponding `SWD\PRINTENUM` device state with successful `RegDeleteKey`/`RegDeleteValue` operations. No corresponding deletion of the target-family values under the WNF `Notifications` store was observed.

This is important because it weakens the earlier working theory that the main defect is simply a missing per-logoff WNF delete. The target state names decode as **Permanent / System** registrations, and later comparison-host captures likewise showed printer/SWD deletion activity without target `Notifications` deletion. Current evidence therefore favors a creation/reuse difference over a straightforward failed-logoff-cleanup model.

The timed watcher provided a second, independent observation. At a 100 ms polling interval across multiple controlled logins, newly created target-family values showed no subscribers, no state data, no nonzero change stamps, and no non-quiescent samples during the captured observation windows.

### Comparison-host difference and probable reuse behavior

A comparison RDS host in the same environment behaves materially differently.

Earlier short captures showed many redirected-printer operations with no new target allocations. A larger multi-user capture then caught both existing-device enumeration and a small number of new target allocations:

- The system-side device-processing `svchost.exe` examined 36 distinct redirected-printer `SWD\PRINTENUM` devices spanning 27 redirected-session suffixes during the analyzed scan.
- Only four new exact target-family values were allocated during that activity.
- A confirmed initial establishment of RDP session 117 presented seven redirected printers but produced four new target-family allocations rather than seven.
- `RegDeleteKey` and `RegDeleteValue` were included in the capture. Hundreds of printer/SWD deletion operations occurred, but no target `Notifications` deletions were observed in the analyzed interval.
- As ordinary users returned after cleanup, the comparison host's target-family count rose from roughly 20 to more than 200, yet later captures showed substantial repeated redirected-printer activity without one new target value per printer/login.

These observations support, but do not yet prove, a **reuse-versus-recreate** model: a healthy/bounded path may recognize an existing logical device registration and reuse persistent WNF state, while the affected path repeatedly allocates a fresh permanent/system state name when the redirected printer is instantiated. The exact stable identity or registry/device property used for reuse has not yet been identified.

The comparison host also retains a large historical population of `SWD\PRINTENUM` entries, while the reproducible host exposes primarily the currently redirected printer instances during the same style of inspection. That difference remains a candidate part of the reuse mechanism rather than a proven cause.

### Negative and narrowing tests

Several plausible side paths have been tested without changing the target-family recurrence:

- Updating the reproducible host from OS build `17763.8511` to `17763.9020` did not by itself stop the per-printer recurrence.
- Explicit testing of `fDisableCpm` did not change the recurrence pattern.
- Installing a matching manufacturer printer driver and setting `UseUniversalPrinterDriverFirst = 4` so the redirected printer used the native/manufacturer driver instead of relying on Easy Print did not stop accumulation. Driver selection alone therefore does not explain the host difference.
- Setting `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RemoteRegistry\DisableIdleStop = 1` and keeping Remote Registry running did not change accumulation. Microsoft's separate Remote Registry/WNF paged-pool leak should not be conflated with this registry-value recurrence based on current evidence.
- Targeted scans for PrintService Event ID 603 returned no matching events on either comparison server. Event 603 is therefore not part of the observed evidence chain in this environment.

These results establish a strong redirected-printer → software-device setup → `DsmSvc` → permanent WNF allocation path on the reproducible host, while the comparison host appears to allocate only when some additional initialization condition is met. They do not establish that every Windows Server 2019 RDS host behaves identically or that printer redirection is universally defective.

## Production remediation result

The primary heavily affected server was successfully remediated with the toolkit's targeted cleanup, and broad server-level behavior improved: Start/search and OneDrive behavior recovered for many users, and users whose `%LOCALAPPDATA%\Packages` state had not already been populated/altered during earlier troubleshooting were able to initialize successfully after cleanup.

A residual OneDrive sign-in problem remained for a subset of users who already had populated `%LOCALAPPDATA%\Packages` trees. Those users had reportedly been working earlier in the investigation, before broad AppX re-registration/reinstall attempts were performed. This creates a reasonable suspicion that some remaining per-user package/profile state was changed by the earlier repair attempts, but **causation has not been established**. The residual issue should therefore be documented separately from the server-wide WNF/AppX failure rather than presented as proof that targeted WNF cleanup failed.

This remains strong operational validation of the cleanup as a recovery action for the server-level condition. It does not prove that every downstream user-specific symptom has the same cause, reverse prior profile/package modifications, or permanently correct the redirected-printer/device-state behavior that can recreate the target family.

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

The comparison hosts still demonstrate why a universal threshold is inappropriate. The current evidence suggests the important difference may be whether existing redirected-device/WNF registration state is reused or recreated, but the stable identity and exact decision path remain unresolved.

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
- Permanent/system WNF state names are expected to be deleted at every user logoff.
- The current reuse-versus-recreate model is proven; it remains the best fit to the captures, not a documented Microsoft implementation contract.
- The residual OneDrive issue in previously modified user profiles is proven to have been caused by earlier AppX repair attempts.
- One healthy server establishes a universal threshold.

Use the combination of profile, AppX, structural, live-state, recurrence, and comparison evidence.
