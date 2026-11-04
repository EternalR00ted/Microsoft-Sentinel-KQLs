# Getting the PsExec and WMI ASR Rule to Block

One Advanced Hunting query for moving "Block process creations originating from PSExec and WMI commands" from Audit to Block. It reads 30 days of audit hits and gives every program the rule caught a verdict, plus the exact path to exclude.

Behavior in this README was checked against Microsoft's docs in November 2026.

## Why this rule sits in Audit

PsExec and WMI can both run code on another machine. Malware uses them for command and control and to spread. This rule stops any process that WMI or PsExec tries to start.

The rule can't tell an attacker from your own tools. Microsoft's ASR reference says that if you use Configuration Manager (MECM), you shouldn't turn this rule on with any other deployment method, because the MECM client relies heavily on WMI. MECM can't deploy this rule itself either. Microsoft's Intune security baselines for Windows and for Defender for Endpoint both ship it in Audit.

Audit doesn't block anything. It only logs what Block would have stopped. This query turns those logs into a to-do list.

It's worth the work. In January 2021, Daniel Wesemann at the SANS Internet Storm Center ran an Emotet document against ASR. The macro started cmd through WMI, so Word was never the parent and the Office child process rule didn't fire. The only ASR rule that fired was this one.

## Files

| File | What it does |
|---|---|
| `What to exclude before Block.kql` | One row per program the rule caught in the last 30 days, with a verdict and the path to exclude. |

## Running it

Paste it into Advanced hunting in the Defender portal. It needs Defender for Endpoint Plan 2. It only reads data, so it's safe to run any time.

Status: Testing. It hasn't had its first run in a real tenant yet.

## Reading the verdicts

The query checks each program against these in order and stops at the first match.

| Verdict | What it matched | What to do |
|---|---|---|
| Wait: MECM client file, stays in Audit until MECM is gone | Runs from the MECM client folders (`C:\Windows\CCM`, `ccmcache` or `ccmsetup`) | Nothing yet. These stop mattering once the client is gone. |
| Investigate: runs from a user-writable or temp folder | A user profile, AppData or a temp folder | Find out what it is. Never exclude these paths. Anyone can write to them. |
| Investigate: runs from a network share | A UNC path | Find out what it is and who owns the share. |
| Investigate: started from another machine | `RemoteCallers` has a machine name in it | Find out which machine and why. A host that isn't your scanner or an admin box is an incident. Once you know, the rows below still apply. |
| Don't exclude: built-in Windows binary | System32, SysWOW64, WinSxS, Microsoft.NET or the Windows folder itself | These are your real blockers. See the next section. |
| Don't exclude: shell or script engine | The file name is on the `ShellsAndScriptEngines` list at the top of the query, wherever the file lives | Same as above. Excluding a shell lets anything run through it. |
| Investigate: unsigned or bad signature | FileProfile says it's unsigned or the signature is invalid | Find out what it is before you do anything else. |
| Investigate: one device, one or two days | One device, 2 days or less | Find out who ran it. It could be a one-time admin job. |
| Exclude: add ExclusionPath to this rule's exclusions | Runs from Program Files with a valid signature | Add `ExclusionPath` to this rule's exclusions. |
| Check: confirm the signer and folder permissions first | Anything else. Usually ProgramData, another drive, or a file Defender couldn't profile. | Check the signer and make sure regular users can't write to the folder. A path exclusion on a folder users can write to lets anyone drop a file there and run it. |

### Why built-in tools can't be excluded

Impacket's wmiexec runs its commands through cmd.exe as a child of WmiPrvSE.exe, with cmd's `/Q /c` switches. Excluding cmd.exe or powershell.exe switches the rule off for exactly that. Tenable's Nessus agent trips this rule too, and the parent there is WmiPrvSE.exe as well.

For these rows, use `WmiCallers`, `RunAs` and `SampleCommandLine` to find the tool behind them. Then change how the tool works, or keep the devices that need it in Audit.

## Columns

| Column | What it is |
|---|---|
| `ExclusionPath` | Full path of the program the rule caught. This is what goes in the exclusion list. |
| `DevicesHit` | Devices it was caught on. |
| `NonMecmDevices` | Devices without the MECM client it was caught on. These are the devices Block would affect today. |
| `DaysSeen` | Days it was caught on. |
| `AuditHits`, `BlockHits` | Audit and Block events. They're throttled, so treat them as a floor. |
| `LaunchedBy` | The parent. It should be wmiprvse.exe or psexesvc.exe. |
| `WmiCallers` | The initiating process Defender recorded on `ProcessCreatedUsingWmiQuery` events for a file with this name, across every device. A lead for finding the tool. |
| `RemoteCallers` | Machines that started a file with this name over WMI. |
| `RunAs` | Accounts the process ran as. |
| `Signer`, `SigState`, `GlobalPrevalence` | From `FileProfile()`. |
| `Company` | Company name from the file's version info. |
| `SampleCommandLine`, `SampleDevices`, `FirstSeen`, `LastSeen` | For triage. |

## Moving to Block

1. Run the query. Work every row where `NonMecmDevices` is above 0.
2. In your Intune ASR policy, add each Exclude row's `ExclusionPath` under this rule's "ASR only per rule exclusions". That box only shows up once the rule has a mode set. If the vendor installs into a folder with a version number in its name, put a `*` in place of that folder so the exclusion survives updates.
3. Sort out the Don't exclude rows. Each one is a tool that has to change, or devices that stay in Audit.
4. Put devices without the MECM client in a pilot group with this rule on Block. MECM devices stay in Audit. Grow the group in rings, the way Microsoft recommends.
5. Take the Block group out of every other policy and baseline that sets this rule. If two Intune policies give this rule different modes on one device, Intune treats it as a conflict and holds that setting back. Microsoft's Windows and Defender for Endpoint security baselines both set it to Audit, so check those too.
6. Run the query again a week later. `BlockHits` shows anything you missed.

## Things to know

- **Throttling.** Advanced hunting keeps one ASR event per unique process per hour. Hit counts are a floor. Make decisions on `DevicesHit` and `DaysSeen`.
- **Which exclusions work.** Defender Antivirus exclusions don't apply to this rule. Per-rule ASR exclusions do. Global ASR exclusions work too, but they cover every ASR rule, so stick to per-rule.
- **Excluded files go quiet.** Once a file is excluded, ASR lets it run and records nothing about it. ASR exclusions only cover ASR, so the process still shows up in DeviceProcessEvents.
- **Wildcards.** Exclusions can use wildcards and system environment variables. Don't use user environment variables. A wildcard can't replace the drive letter.
- **RemoteCallers.** It reads `ClientMachine` and `IsRemoteMachine` from `AdditionalFields`. Microsoft doesn't document those fields. Fabian Bader's XDR Internals lists them for this event, and its examples use made-up values. If the column is empty on every row, your tenant doesn't fill them in.
- **WmiCallers matches on file name.** On cmd.exe it shows everything that started cmd.exe over WMI on any device. Treat it as a lead.
- **FileProfile.** It enriches up to 1,000 rows. Anything past that shows `SigState` as Unknown and lands on Check.
- **Finding MECM devices.** A device counts as MECM if CcmExec.exe or CcmEval.exe ran on it, or CcmExec.exe started something, in the same 30 days.

## The other WMI rule

"Block persistence through WMI event subscription" is a separate rule. Microsoft puts it in its standard protection set, the rules most orgs can put on Block without testing in Audit first. If you run MECM, Microsoft says to test it in Audit first. Its Block events show up as `AsrPersistenceThroughWmiBlocked`.

## Credits

This builds on other people's work. Thanks to:

| Who | What I used | Link |
|---|---|---|
| Daniel Wesemann | His January 2021 SANS ISC test of an Emotet document against ASR. The macro started cmd through WMI, and this was the only ASR rule that fired. He also warned that putting it on Block can break device management. | [Emotet vs. Windows Attack Surface Reduction](https://isc.sans.edu/diary/Emotet+vs.+Windows+Attack+Surface+Reduction/27036) |
| Kijo Girardi | His Impacket wmiexec hunt. It looks for cmd.exe or powershell.exe under WmiPrvSE.exe, with cmd's `/Q /c` switches. It's why those never get excluded here. | [Impacket wmiexec hunting query](https://kqlsearch.com/query/Endpoint-ImpacketWmi-LMP&clmer2t4j000b5iqwo2ym52fe) |
| Fabian Bader | XDR Internals. Its DeviceEvents examples show the `ClientMachine` and `IsRemoteMachine` fields on `ProcessCreatedUsingWmiQuery`. `RemoteCallers` reads them. | [XDR Internals: DeviceEvents](https://xdrinternals.com/docs/microsoftxdr/devices/deviceevents/) |
| Ugur Koc | KQL Search. It's where I found Kijo's query. | [kqlsearch.com](https://www.kqlsearch.com/) |

## References

| Source | Used for |
|---|---|
| [ASR rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) | What the rule blocks, the MECM warning, MECM can't deploy it, the action type names |
| [ASR rules overview](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview) | Which exclusions this rule honors, wildcards, excluded files recording nothing, standard protection rules |
| [ASR FAQ](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-faq) | The MECM note on the WMI persistence rule, rolling out in rings |
| [Monitor ASR rule activity](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-monitor) | Hunting events are throttled to unique processes per hour |
| [Configure ASR rules and exclusions](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure) | Per-rule exclusions in Intune show up once the rule has a mode |
| [Use Intune policy to manage ASR rules](https://learn.microsoft.com/en-us/intune/device-configuration/endpoint-security/attack-surface-reduction) | Conflicting settings get held back |
| [Windows MDM security baseline settings](https://learn.microsoft.com/en-us/intune/device-security/security-baselines/ref-windows-mdm-settings) | This rule ships in Audit in the 24H2, 25H2 and 26H2 baselines |
| [Defender for Endpoint security baseline settings](https://learn.microsoft.com/en-us/intune/device-security/security-baselines/ref-defender-settings) | Both WMI rules ship in Audit in version 24H1 |
| [FileProfile()](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-fileprofile-function) | Signer, signature state, prevalence and the 1,000 row limit |
| [Tech Community: AsrPsexecWmiChildProcess and Nessus](https://techcommunity.microsoft.com/discussions/microsoftdefenderatp/asrpsexecwmichildprocess-and-nessus/3264504) | Tenable's Nessus agent tripping this rule with WmiPrvSE.exe as the parent |
