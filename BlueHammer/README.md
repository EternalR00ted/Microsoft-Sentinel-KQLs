# BlueHammer

CVE-2026-33825. Patched in April Patch Tuesday. CVSS 7.8. Local privilege escalation that takes a standard user account to NT AUTHORITY\SYSTEM.

The rules in this folder are mainly for two things: historical hunting on systems that might have been compromised before the patch propagated, and catching modified variants that abuse the same primitives on unpatched hosts. If your fleet is fully on `Defender Antimalware Platform 4.18.26030.3011` or later, BlueHammer itself is closed, but the techniques aren't going anywhere.

## How the attack works

The exploit is a chain of nine steps. Here it is end to end:

1. Poll the Windows Update Agent COM API to find a pending Defender definition update.
2. Download `mpam-fe.exe` from `go.microsoft.com/fwlink/?LinkID=121721&arch=x64`.
3. Extract the CAB out of `MpSigStub.exe`'s `.rsrc` section in memory.
4. Write the extracted `.vdm` files to an attacker-controlled temp directory.
5. Call `Proc42_ServerMpUpdateEngineSignature` via ALPC-RPC against the `IMpService` pipe (UUID `c503f532-443a-4c69-8300-ccd1fbdb3839`).
6. Use `ReadDirectoryChangesW` to monitor `Definition Updates\` for the new subdirectory Defender will create.
7. Set a batch oplock on `mpasbase.vdm` inside that new directory.
8. When the oplock breaks, rename `mpasbase.vdm` out, rename the parent directory, and recreate it as a mount-point junction targeting `\BaseNamedObjects\Restricted`.
9. Defender resumes the write. The kernel resolves the junction. The SAM hive on the VSS snapshot is now accessible to the exploit.

Once it has read access to the SAM hive, the rest is the easy part:

10. Parse SAM with `offreg.dll` for the boot key and per-user NTLM hashes.
11. Call `SamiChangePasswordUser` to overwrite the local admin password. The PoC hardcodes `$PWNed666!!!WDFAIL`.
12. Call `LogonUserEx` with the new password.
13. Call `CreateService` + `StartService` to spawn a LocalSystem shell.
14. Restore the original NTLM hash so the password change isn't obvious in forensics.

The clever part isn't any single step. It's that every step uses a legitimate Windows API doing something it was designed to do. The vulnerability is in how they compose.

## Key IoCs

| What | Value |
|---|---|
| Cloud Files provider name | `IHATEMICROSOFT` |
| Hardcoded PoC password | `$PWNed666!!!WDFAIL` |
| DLL loads to watch | `offreg.dll`, `CldApi.dll` |
| Network endpoint | `go.microsoft.com/fwlink/?LinkID=121721` |
| RPC pipe | `IMpService77BDAF73-B396-481F-9042-AD358843EC24` |
| RPC UUID | `c503f532-443a-4c69-8300-ccd1fbdb3839` |
| Junction target | `\BaseNamedObjects\Restricted` |
| Defender signature | `Exploit:Win32/DfndrPEBluHmrBZ`, `Exploit:Win32/DfndrPEBluHmr.BB` |
| In-the-wild binary | `FunnyApp.exe` (Pictures folder, April 10, 2026) |
| Patched platform version | `4.18.26030.3011` |

## Rules in this folder

| Rule ID | File | Severity | Frequency | What it catches |
|---|---|---|---|---|
| BH-T2-6 | `BH-T2-6-sam-hive-access-via-defender-chain.kql` | Critical | 3h | SAM hive accessed by MsMpEng or via a VSS snapshot mount. Direct catch of the read primitive. |
| BH-T2-7 | `BH-T2-7-transient-service-from-user-path.kql` | High | 1h | A transient Windows service created from a user-writable path. This is the final SYSTEM escalation step. |
| BH-T3-3 | `BH-T3-3-ihatemicrosoft-cloud-provider.kql` | Critical | 3h | Cloud Files sync root registered with the provider name `IHATEMICROSOFT`. PoC-specific. |
| BH-T3-9 | `BH-T3-9-defender-definition-download-non-update.kql` | High | 3h | `mpam-fe.exe` downloaded by a process that isn't `MpCmdRun.exe` or `WindowsUpdate`. |
| BH-T4-3 | `BH-T4-3-password-change-logon-chain.kql` | High | 1h | Local-account password change immediately followed by an interactive logon by the same account from the same device. This is the credential weaponization signature. |
| BH-T4-5 | `BH-T4-5-offreg-dll-non-system-loader.kql` | High | 6h | `offreg.dll` (offline registry parsing) loaded by a non-system process. |
| BH-T5-3 | `BH-T5-3-unpatched-defender-platform-version.kql` | Medium | Daily | Sentinel-only. Integer-based version comparison to find hosts still on Defender Antimalware Platform `< 4.18.26030.3011`. |

The Shared folder has more rules that fire on BlueHammer too. The big ones to deploy alongside this folder:

- `Shared/T0-1` catches the unmodified PoC via Microsoft's signature.
- `Shared/T2-2` catches the junction creation primitive.
- `Shared/T2-5` catches the VSS shadow copy enumeration step.
- `Shared/T3-7` catches `FunnyApp.exe` and other known PoC binary names.

## What to actually do

If you're already patched, run BH-T2-6, BH-T2-7, BH-T4-3, and BH-T4-5 as historical hunts first. Sweep them across the maximum retention window you have. If they come back clean after a full week of runs, scale them down to event-driven Custom Detection Rules with 6h+ frequency.

BH-T5-3 is the one to deploy daily during the patch rollout window. It tells you which hosts haven't received the platform update yet. The Defender for Endpoint compliance dashboard tells you the same thing, but don't trust the dashboard alone, because UnDefend can falsify it. Verify out of band.

BH-T3-9 has noticeable false positives in environments where bundled security tools or imaging utilities ship their own Defender update mechanism. Baseline before you turn on auto-response.

## Sources

- Microsoft Security Response Center, CVE-2026-33825
- Cyderes / Howler Cell, *BlueHammer Inside the Windows Zero-Day*
- cyb3r-w0lf, *BlueHammer: Fixing the Bugs in a Windows Zero-Day LPE PoC* (deep code analysis)
- Picus Security, *BlueHammer & RedSun: Windows Defender CVE-2026-33825 Zero-Day Vulnerability Explained*
- Huntress Labs, *Nightmare-Eclipse Tooling Seen in Real-World Intrusion*
