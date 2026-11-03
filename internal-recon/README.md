# Internal Recon

Once someone gets into a network, the next thing they do is look around. They want to know who the domain admins are and where the domain controllers sit. Most of that gets done with tools that ship with Windows, like `net`, `nltest` and `whoami`. The rest gets done with free tools like AdFind and SharpHound.

This folder is alerts for that step. 13 rules, all Defender XDR custom detections. 11 of them can run in near real time. The other 2 count things over time, so they run every hour.

## Why I built this

Recon happens before anything gets encrypted or stolen, and it's loud if you know where to look. That makes it one of the best places to catch an intrusion early.

The tools are well known. MITRE's [Domain Groups page](https://attack.mitre.org/techniques/T1069/002/) uses `net group /domain` as its example. Its [Domain Trust Discovery page](https://attack.mitre.org/techniques/T1482/) lists QakBot, TrickBot, Bazar, Akira and FIN8 all running `nltest` to map trusts. Its [AdFind page](https://attack.mitre.org/software/S0552/) lists Play, Akira, BlackByte, INC Ransom and Wizard Spider.

The catch is that matching on plain text isn't enough. [ArgFuscator](https://github.com/wietze/ArgFuscator.net) documents which Windows tools accept obfuscated arguments. `nltest`, `wmic`, `ipconfig`, `netstat`, `route` and AdFind all take lookalike characters, so `nltest /ｄomain_trusts` with a fullwidth d runs fine and walks past a rule looking for `/domain_trusts`. `net.exe` takes quotes inside words and short switches, so `net gr"ou"p "Domain Admins" /dom` works too. These rules are built to catch both.

## Layout

```
internal-recon/
├── active-directory/   AD lookups with built-in tools and PowerView
├── tools/              Third-party recon tools and what they leave behind
├── endpoint/           Recon from odd places, and obfuscated recon
└── bursts/             A lot of recon in a short time
```

Every `.kql` file starts with a short header with what it catches, how often it runs, the severity, MITRE mapping, what it needs and a triage card. Paste the triage card into the rule's Recommended actions field so whoever picks up the alert knows what to check.

## Rules

Live means I've had the rule running in a real tenant for at least two weeks. Testing means it hasn't gotten there yet.

| Rule | File | Runs | Severity | Status |
|---|---|---|---|---|
| Net group command used | `active-directory/net-group-command-used.kql` | Continuous (NRT) | Medium | Testing |
| Domain users or password policy listed with net | `active-directory/domain-users-or-password-policy-listed-with-net.kql` | Continuous (NRT) | Medium | Testing |
| Domain trusts or domain controllers listed | `active-directory/domain-trusts-or-domain-controllers-listed.kql` | Continuous (NRT) | Medium | Testing |
| SPNs listed with setspn | `active-directory/spns-listed-with-setspn.kql` | Continuous (NRT) | Medium | Testing |
| PowerView recon functions run | `active-directory/powerview-recon-functions-run.kql` | Continuous (NRT) | High | Testing |
| AD recon tool run | `tools/ad-recon-tool-run.kql` | Continuous (NRT) | High | Testing |
| BloodHound output written to disk | `tools/bloodhound-output-written-to-disk.kql` | Continuous (NRT) | High | Testing |
| Network scanner run | `tools/network-scanner-run.kql` | Continuous (NRT) | Medium | Testing |
| Recon commands from a server process | `endpoint/recon-commands-from-a-server-process.kql` | Continuous (NRT) | High | Testing |
| Antivirus products looked up | `endpoint/antivirus-products-looked-up.kql` | Continuous (NRT) | Medium | Testing |
| Recon tool run with lookalike characters | `endpoint/recon-tool-run-with-lookalike-characters.kql` | Continuous (NRT) | High | Testing |
| Recon command burst | `bursts/recon-command-burst.kql` | Every hour | Medium | Testing |
| Many hosts contacted on admin ports | `bursts/many-hosts-contacted-on-admin-ports.kql` | Every hour | Medium | Testing |

If you only deploy two things from here, I'd go with "Recon commands from a server process" and "Recon tool run with lookalike characters". Both should be close to silent, and both are worth a look every time they fire.

If you run my `defender-zeroday-detections` pack, its `T1-1` rule (whoami, cmdkey and net group within 30 minutes) is a narrow version of "Recon command burst". You can run both.

## How I kept these from spamming

Nobody wants a recon rule that fires every time the helpdesk opens a command prompt, so I built these with a few things in mind:

- Commands from the same account and launcher should land in one alert. Defender groups results when the entities, custom details and dynamic details match, so the custom details stick to things that stay the same across a session, like the account and the launching process. The Summary, TargetGroup and Member columns are in the results for hunting, but they aren't custom details. Add them if you want an alert per command.
- The commands IT runs all day are left out: `nltest /dsgetdc`, `/sc_query` and `/sc_verify`, `net user` for one named user, `net use`, `net time`, `setspn` for one exact SPN, and `net localgroup`.
- `net.exe` hands each command to a `net1.exe` child. The net rules drop that copy so one command makes one event. The same idea applies to a shell wrapping AdFind or SharpHound, so a batch file doesn't double the alert.
- New custom detections scan the last 30 days as soon as you save them. The NRT rules have `ingestion_time() > ago(1d)` in them so your first day isn't a month's worth of alerts. The two hourly rules only look at the last 2 hours.
- The burst rules have their thresholds at the top. The defaults are 4 different tools in one sitting and 30 hosts in an hour.
- Defender's own processes (MsSense.exe and SenseIR.exe) are ignored as launchers in the burst rule.
- Each rule caps out at 150 alerts per run. If one of these gets anywhere near that, something's wrong.
- None of them take automated response actions. Every alert goes to a person.

## Why some checks aren't here

LDAP and SAMR recon seen from the domain controller. If you run Defender for Identity, it already has [alerts for this](https://learn.microsoft.com/en-us/defender-for-identity/alerts-xdr), like "Suspicious LDAP query", "Possible Kerberoasting LDAP reconnaissance" and "Anomalous Samr activity (Preview)". Mine would be duplicates. It's also the only place you'll see recon that never starts a process these rules can match. Cobalt Strike's net commands, for example, are [built on the Windows network enumeration APIs](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_network-host-enumeration.htm), so the process rules here won't see them.

The PowerShell AD module (`Get-ADUser`, `Get-ADGroupMember`). Admins use it all day. PowerView's function names are a different story, so those get their own rule.

`net localgroup`. Installers and scripts run it constantly.

## Before you deploy

- Creating custom detections takes Security settings (manage) or Security Administrator.
- "Many hosts contacted on admin ports" needs aggregated reporting turned on (Settings > Endpoints > Advanced features). Microsoft says it can take up to 7 days for the data to show up after you turn it on.
- "Many hosts contacted on admin ports" only counts RFC 1918 addresses. If your internal ranges are different, change the RemoteIPType line.
- The Defender for Identity v2.x sensor contacts devices on 135 and 3389 to resolve their names, so "Many hosts contacted on admin ports" leaves its process out. Without that, every domain controller would fire every hour.
- "BloodHound output written to disk" depends on Defender logging the file writes. Run SharpHound once in a lab and check the files show up in DeviceFileEvents.
- Defender for Identity is optional, but it covers the LDAP side these can't see.

## Deploying one

1. Run the query in Advanced hunting over the last 30 days first. Comment out the `ingestion_time()` line for this run, or you'll only see the last day. Count rows per day to get a rough idea of how noisy it'll be in your tenant.
2. Create the detection rule and use `<Company> - MDE - <rule name>` as the alert title. Copy only the query and leave the header out. Continuous (NRT) rules won't take a query with comments in it, and that includes the line you commented out in step 1. If the portal still won't offer Continuous (NRT), delete the `ingestion_time()` line and try again. Microsoft's own NRT example uses it, but it isn't on the NRT operator list.
3. Set the frequency from the table above.
4. Map entities. Defender data maps on its own.
5. Add the custom details listed in the header.
6. Paste the triage card into Recommended actions.
7. Give it a week, then check the volume. My rule of thumb: if one rule fires more than 5 times a week, it needs tuning.

The thresholds and lists in the queries are just my defaults. Tune them for your environment.

## How these were checked

All 13 are Testing. None of them have run in a live tenant yet.

The matching logic was tested offline with 219 checks. They cover normal use, obfuscated versions built from ArgFuscator's models, and lookalikes that shouldn't fire, like `net localgroup`, `net user /comment:"group lead"`, `nltest /dsgetdc` and French group names with accents. The tests run the same regex strings through Python's engine, and the patterns only use features that behave the same in Python and KQL. Every query also got a second pass for syntax, column names and the NRT rules. The queries themselves still need their first real run in Advanced hunting.

## Credit

A lot of the matching logic started from Sigma rules, so shoutout to their authors. Sigma rules are under the [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License).

| Sigma rule | Authors | Used in |
|---|---|---|
| Potential Recon Activity Via Nltest.EXE | Craig Young, oscd.community, Georg Lauenstein | Domain trusts or domain controllers listed |
| Domain Trust Discovery Via Dsquery | E.M. Anhaus, Tony Lambert, oscd.community, omkar72 | Domain trusts or domain controllers listed |
| Potential SPN Enumeration Via Setspn.EXE | Markus Neis, keepwatch | SPNs listed with setspn |
| PUA - AdFind Suspicious Execution | Janantha Marasinghe, FPT.EagleEye Team, omkar72, oscd.community | AD recon tool run |
| PUA - Suspicious ActiveDirectory Enumeration Via AdFind.EXE | frack113 | AD recon tool run |
| Renamed AdFind Execution | Florian Roth (Nextron Systems) | AD recon tool run |
| Suspicious Active Directory Database Snapshot Via ADExplorer | Nasreddine Bencherchali (Nextron Systems) | AD recon tool run |
| HackTool - Bloodhound/Sharphound Execution | Florian Roth (Nextron Systems) | AD recon tool run |
| PUA - PingCastle Execution | Nasreddine Bencherchali (Nextron Systems), frack113 | AD recon tool run |
| BloodHound Collection Files | C.J. May | BloodHound output written to disk |
| PUA - Advanced IP Scanner Execution | Nasreddine Bencherchali (Nextron Systems), `@ROxPinTeddy` | Network scanner run |
| PUA - Advanced Port Scanner Execution | Nasreddine Bencherchali (Nextron Systems) | Network scanner run |
| PUA - SoftPerfect Netscan Execution | `@d4ns4n_` (Wuerth-Phoenix) | Network scanner run |
| PUA - Nmap/Zenmap Execution | frack113 | Network scanner run |
| Webshell Detection With Command Line Keywords | Florian Roth (Nextron Systems), Jonhnathan Ribeiro, Anton Kutepov, oscd.community, Chad Hudson, Matt Anderson | Recon commands from a server process |
| Suspicious Process By Web Server Process | Thomas Patzke, Florian Roth (Nextron Systems), Zach Stanford `@svch0st`, Tim Shelton, Nasreddine Bencherchali (Nextron Systems) | Recon commands from a server process |
| Potential Product Class Reconnaissance Via Wmic.EXE | Michael Haag, Florian Roth (Nextron Systems), juju4, oscd.community, Swachchhanda Shrawan Poudel (Nextron Systems) | Antivirus products looked up |

Also:

- [Wietze Beukema's ArgFuscator](https://github.com/wietze/ArgFuscator.net). The obfuscation handling, and the whole lookalike rule, come from its models.
- [JPCERT/CC's analysis of the net command](https://jpcertcc.github.io/ToolAnalysisResultSheet/details/net-user.htm). It shows net.exe starting net1.exe with the same arguments.
- [SpecterOps SharpHound](https://github.com/SpecterOps/SharpHound) and [SharpHoundCommon](https://github.com/SpecterOps/SharpHoundCommon). The output file names and command line options come straight from the source.
- [PowerSploit's PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1). The function list and old aliases come from the script itself.
- [Microsoft's PowerShellCommand hunting query](https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries/blob/master/Execution/PowershellCommand%20footprint.txt), for how that event works.
- [Elastic's "Newly Seen Commonly Abused Network Scanner" rule](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/discovery_newly_seen_abused_scanners).

This is still a work in progress and I'll keep adding rules as I build them. If you spot a mistake or something fires way more than it should in your tenant, please feel free to open an issue.

## Sources

- [MITRE ATT&CK, T1069.002 Permission Groups Discovery: Domain Groups](https://attack.mitre.org/techniques/T1069/002/)
- [MITRE ATT&CK, T1482 Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)
- [MITRE ATT&CK, S0552 AdFind](https://attack.mitre.org/software/S0552/)
- [MITRE ATT&CK, T1027.010 Command Obfuscation](https://attack.mitre.org/techniques/T1027/010/)
- [Microsoft Learn, Create custom detection rules](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules)
- [Microsoft Learn, Aggregated reporting in Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/aggregated-reporting)
- [Microsoft Learn, Defender for Identity alerts in Microsoft Defender format](https://learn.microsoft.com/en-us/defender-for-identity/alerts-xdr)
- [Microsoft Learn, DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)
- [Microsoft Learn, Network Name Resolution in Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/nnr-policy)
- [Cobalt Strike user guide, Network and Host Enumeration](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_network-host-enumeration.htm)
- [Lansweeper, How Lansweeper scans antivirus information](https://docs.lansweeper.com/classic/docs/how-lansweeper-scans-antivirus-information)
