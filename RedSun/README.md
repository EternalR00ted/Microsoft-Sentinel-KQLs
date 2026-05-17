# RedSun

Unpatched. No CVE. The May Patch Tuesday came and went without a fix, and Microsoft hasn't committed to an out-of-band release. Local privilege escalation that takes a standard user account to SYSTEM with what CloudSEK measured as ~100% reliability on fully-patched Windows 11 25H2.

This is the highest-priority folder in the repo. Detection is currently the primary mitigation.

## How the attack works

The attacker abuses Defender's cloud file rollback logic. When Defender detects a malicious file that's been tagged as a cloud-synced placeholder, instead of quarantining or deleting it, Defender restores the file to its original detection path. That restore happens as SYSTEM and without validating that the original path still points to where Defender thinks it does.

The exploit weaponizes that gap:

1. Create a working directory at `%TEMP%\RS-{GUID}\`.
2. Drop a decoy file in that directory. The decoy contains the EICAR test string, stored reversed in the binary and flipped at runtime so the PoC itself doesn't get flagged before it runs. The decoy is named `TieringEngineService.exe`.
3. Open the file with `FILE_EXECUTE` access. That's enough to trigger Defender's real-time scan.
4. Watch `\Device\` for the moment a `HarddiskVolumeShadowCopy*` object gets created. That's the signal that Defender is about to scan.
5. Acquire a batch oplock on the shadow copy of the target.
6. The oplock breaks deterministically the moment Defender accesses the file.
7. POSIX-delete the original file using `SetFileInformationByHandle` + `FILE_DISPOSITION_FLAG_POSIX_SEMANTICS`.
8. Register a Cloud Files sync root via `CfRegisterSyncRoot()` with the provider name `SERIOUSLYMSFT`. Yes, that's actually the name in the PoC.
9. Create a placeholder via `CfCreatePlaceholders()` with the `MARK_IN_SYNC` flag.
10. Rename the working directory away. Recreate it as a junction using `FSCTL_SET_REPARSE_POINT`, with the junction target set to `\??\C:\Windows\System32`.
11. Defender resumes its write. The kernel resolves the junction. The attacker's payload lands at `C:\Windows\System32\TieringEngineService.exe`, written by MsMpEng running as SYSTEM.
12. The exploit activates the Storage Tiers Management DCOM `{50d185b9-fff3-4656-92c7-e4018da4361d}`. That CLSID resolves to the legitimate `TieringEngineService.exe`, which is now the attacker's binary. It runs as SYSTEM.
13. The SYSTEM payload reads the user's session ID via `\\.\pipe\REDSUN` and spawns `conhost.exe` in that session. Interactive SYSTEM shell.

The provider name `SERIOUSLYMSFT` is a message to Microsoft from the researcher. So is `IHATEMICROSOFT` over in BlueHammer.

## Key IoCs

| What | Value |
|---|---|
| Cloud Files provider name | `SERIOUSLYMSFT` |
| Working directory pattern | `%TEMP%\RS-{GUID}\` |
| Default payload name | `TieringEngineService.exe` (the decoy and the final target share this name) |
| Junction target | `\??\C:\Windows\System32` |
| Storage Tiers DCOM CLSID | `{50d185b9-fff3-4656-92c7-e4018da4361d}` |
| Named pipe | `\\.\pipe\REDSUN` |
| Pipe access signature | `DesiredAccess == 1704351`, `AcceptRemote == 1`, called by a non-SYSTEM, non-Microsoft binary |
| Defender signatures | `Exploit:Win64/Halaminer.D!ml` (PoC source), `Program:Win32/Wacapew.C!ml` (in-the-wild variant per Huntress) |
| In-the-wild binary | `RedSun.exe` in `Downloads\<2-letter-subfolder>\` (April 16, 2026) |

## Rules in this folder

| Rule ID | File | Severity | Frequency | What it catches |
|---|---|---|---|---|
| RS-T2-1 | `RS-T2-1-defender-arbitrary-write-system32.kql` | Critical | 1h | `MsMpEng.exe` writing `.exe` / `.dll` / `.sys` to `C:\Windows\System32\`. This is the exploitation primitive itself. |
| RS-T3-1 | `RS-T3-1-redsun-named-pipe.kql` | Critical | 1h | The `REDSUN` named pipe accessed with the specific `DesiredAccess` + `AcceptRemote` flags by a non-SYSTEM, non-Microsoft binary. |
| RS-T3-2 | `RS-T3-2-seriouslymsft-cloud-provider.kql` | Critical | 3h | Cloud Files sync root registered with provider name `SERIOUSLYMSFT`. Hardcoded in the PoC. |
| RS-T3-4 | `RS-T3-4-redsun-working-directory.kql` | High | 3h | Working directory matching `%TEMP%\RS-{GUID}\` created by a user process. |
| RS-T3-5 | `RS-T3-5-tieringengineservice-anomaly.kql` | High | 6h | `TieringEngineService.exe` created in or executed from anywhere other than `C:\Windows\System32\`. |
| RS-T3-6 | `RS-T3-6-storage-tiers-dcom-activation.kql` | High | 6h | DCOM activation of Storage Tiers Management (CLSID `{50d185b9-fff3-4656-92c7-e4018da4361d}`) by a non-standard parent process. |
| RS-T4-4 | `RS-T4-4-cloud-files-api-unexpected-process.kql` | High | 6h | `cldapi.dll` loaded by a process that isn't a known cloud sync client (OneDrive, Dropbox, Box, etc.). |

Pair this folder with these Shared rules:

- `Shared/T0-1` catches the unmodified PoC via Microsoft's `Halaminer` and `Wacapew.C` signatures.
- `Shared/T2-2` catches the junction creation primitive.
- `Shared/T2-5` catches the VSS shadow copy enumeration step.
- `Shared/T3-7` catches `RedSun.exe`, `z.exe`, and other observed binary names.
- `Shared/T3-8` catches the in-the-wild staging pattern (2-letter subfolders under Downloads).

## What to actually do

If you can only deploy three rules from this whole pack, deploy these:

1. `RS-T2-1` (System32 write by MsMpEng)
2. `Shared/T0-1` (Defender's own signature)
3. `RS-T3-1` (REDSUN pipe)

Together they have effectively zero false-positive rate against legitimate workflows and they cover >95% of unmodified PoC variants. Set auto-isolate on RS-T2-1.

Two tuning notes:

- `RS-T2-1` will occasionally fire on legitimate Defender quarantine restore operations into System32, like signed driver files restored after an AV scan completes. Filter on `SHA256` not matching known Microsoft-signed drivers before isolating, or set the auto-action to "collect investigation package" first and isolate manually.
- `RS-T4-4` is going to FP on whatever legitimate cloud sync software you have that wasn't on your initial exclusion list. Baseline `cldapi.dll` loaders across your fleet for a week before turning it on.

While you wait for a patch, Qualys recommended a compensating control: disable the Cloud Files Mini Filter driver on systems that don't need OneDrive Files On-Demand. That eliminates the RedSun attack surface entirely. Validate first that no legitimate workflow depends on the driver. See `HARDENING.md`.

## Sources

- CloudSEK, *RedSun: Windows 0day when Defender becomes the attacker*
- Cyderes / Howler Cell, *RedSun Zero-Day: When Defender Becomes the Delivery Mechanism*
- Fortra / Core Security, *Analysis of RedSun: Local Privilege Escalation via Defender Remediation Abuse*
- Ampcus Cyber, *RedSun and UnDefend zero-day analysis*
- Huntress Labs, *Nightmare-Eclipse Tooling Seen in Real-World Intrusion*
- Will Dormann, independent confirmation that the exploit works on fully-patched systems
