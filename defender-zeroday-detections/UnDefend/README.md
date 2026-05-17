# UnDefend

Unpatched. No CVE. No fix in May Patch Tuesday. Doesn't escalate privileges. What it does is worse in some ways: it silently blinds Defender so the engine can't load new signatures, while letting the management console keep reporting the endpoint as healthy.

A standard unprivileged user can run it. The whole thing is just file locking and a service status watch.

UnDefend is the second half of the Nightmare-Eclipse playbook. The pattern Huntress observed: BlueHammer or RedSun gets you SYSTEM, then UnDefend gets dropped on the same box to keep Defender from learning about whatever you do next. Layered degradation.

## How the attack works

There are two modes.

### Passive mode (no flags)

The default behavior, doesn't require anything special to invoke.

1. Read the Defender signature paths from the registry: `HKLM\SOFTWARE\Microsoft\Windows Defender\ProductAppDataPath` and `HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates\SignatureLocation`.
2. Use `NtCreateFile` + `LockFileEx` to grab exclusive locks on `mpavbase.vdm`, `mpavbase.lkg`, and `mpasbase.vdm` in the Definition Updates directory.
3. Use `ReadDirectoryChangesW` to monitor the Definition Updates directory. Every time Defender tries to write a new signature file, lock it before Defender finishes.
4. Same thing for `C:\Windows\System32\MRT\` so Malicious Software Removal Tool updates also fail.

The result: Defender keeps running with whatever signatures it had loaded at the time UnDefend started. New signatures never load. Windows Update history starts showing error code `0x80070643`. The existing in-memory protection still works, but the corpus is frozen in time.

### Aggressive mode (requires `-aggressive` flag)

This one is interesting because it depends on Microsoft helping the attacker.

1. Call `OpenService("WinDefend")` and `NotifyServiceStatusChangeW(SERVICE_NOTIFY_STOPPED)` to get a callback when the Defender service stops.
2. Wait. The Defender service stops on its own during major platform updates (when Microsoft pushes a new `MsMpEng.exe`).
3. When the service stops, grab an exclusive lock on `MsMpEng.exe`.
4. The new platform binary can't write over the locked file, so Defender fails to restart.

Defender is now fully disabled until the lock is released.

### What Huntress observed in the wild

The threat actor spawned UnDefend as a child of `cmd.exe` under `explorer.exe` with the `-aggressive` flag. They also misspelled it as `-agressive` (one `g`). They tried `-h` for help, which UnDefend doesn't support. Huntress's take was that the operator didn't really understand the tool, which is interesting because it suggests the toolkit is being passed around faster than the tradecraft.

## Key IoCs

| What | Value |
|---|---|
| Windows Update error code | `0x80070643` |
| Files locked (passive) | `mpavbase.vdm`, `mpavbase.lkg`, `mpasbase.vdm` in `\ProgramData\Microsoft\Windows Defender\Definition Updates\` |
| Directory locked (passive) | `C:\Windows\System32\MRT\` |
| Service watched (aggressive) | `WinDefend` |
| Binary path locked (aggressive) | `MsMpEng.exe` |
| Command flag | `-aggressive` (also seen misspelled as `-agressive`) |
| Process tree | `explorer.exe → cmd.exe → undef.exe` |
| Observed binary names | `undef.exe`, `UnDefend.exe` |

## Rules in this folder

| Rule ID | File | Severity | Frequency | What it catches |
|---|---|---|---|---|
| UD-T2-3 | `UD-T2-3-signature-database-access.kql` | High | 3h | Non-Microsoft process touching `mpavbase.vdm` / `mpavbase.lkg` / `mpasbase.vdm`. Direct catch of the passive-mode file locking. |
| UD-T2-4 | `UD-T2-4-update-error-80070643.kql` | Medium | 6h | Spike in Defender signature update failures with Windows error `0x80070643`. Test in your environment first. |
| UD-T5-1 | `UD-T5-1-fleet-signature-staleness.kql` | Info | Daily | Sentinel-only. Fleet-wide query for hosts with Defender signature age > 24h. |
| UD-T5-2 | `UD-T5-2-rtp-non-compliant.kql` | High | 3h | Sentinel-only. Hosts where Defender real-time protection is reporting non-compliant via TVM tables. |
| UD-T5-4 | `UD-T5-4-rtp-suppressed-fleet.kql` | High | Daily | Sentinel-only. Fleet-wide `AvIsSigUpdateOverdue` spike across multiple endpoints at once. |

Pair with `Shared/T3-7-suspicious-binary-names.kql` which catches `undef.exe` and `UnDefend.exe` in user-writable paths.

## What to actually do

The operationally important thing about UnDefend: while it's unpatched, **the Defender management console can lie to you.** The dashboard's "endpoint healthy" indicator is derived from metrics that UnDefend's passive mode can falsify. You need out-of-band verification.

Three ways to verify out of band:

1. Deploy UD-T5-1 daily across the fleet. It queries the actual `AntivirusSignatureLastUpdated` timestamps via the TVM tables, not the aggregated dashboard view.
2. Push a PowerShell collector via Intune Proactive Remediation that runs `Get-MpComputerStatus` and writes the signature timestamp back to a central store.
3. If you have Defender for Endpoint Live Response, run the same query across the fleet on-demand during incident triage.

Any host with `AntivirusSignatureLastUpdated` older than 72 hours: treat it as suspected UnDefend, even if the dashboard says it's healthy.

About UD-T2-4: the `0x80070643` error can fire from sources that aren't malicious. Legitimate update failures, corrupted definition files, disk errors. Baseline it for a week in your environment and threshold against normal noise before turning on auto-response. The right threshold for most environments is "more than 3 failures in 24 hours from a single device."

UD-T5-2 and UD-T5-4 are Sentinel-only because they query the `DeviceTvmInfoGathering` and `DeviceTvmSecureConfigurationAssessment` tables, which don't produce `ReportId` reliably. The XDR portal won't save them as Custom Detection Rules. That's not a bug, that's the platform.

### One historical note on the rule set

The v1 of this pack had a rule that referenced an ActionType called `AntivirusDefinitionsUpdateFailed`. I'd pulled that from a community repo without verifying. When I went looking for it in Microsoft's MDE schema documentation, I couldn't find it. It may exist as an internal field that isn't documented, or the community repo may have hallucinated it. Either way, I removed it from v3 and replaced it with the error-code-based detection (UD-T2-4) and the TVM-table-based fleet check (UD-T5-4). Both of those are verified to exist and work.

## Sources

- Ampcus Cyber, *RedSun and UnDefend zero-day analysis*
- Vectra, *When the Defender Becomes the Door: BlueHammer, RedSun, and UnDefend in the Wild*
- Huntress Labs, *Nightmare-Eclipse Tooling Seen in Real-World Intrusion* (the misspelled flag observation)
- Heise, *Unpatched Windows zero-days RedSun, UnDefend, and BlueHammer are being attacked*
