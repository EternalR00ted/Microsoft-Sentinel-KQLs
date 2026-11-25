# Known Bad VS Code Extensions

A VS Code extension runs with the same rights as the editor. A bad one can read your source code and every token on the machine. This folder has Defender XDR custom detections that tell you when an extension on a device is on a public list of extensions that were pulled for cause.

Two of the rules run once a day and only alert. Two run in near real time and are built so you can attach device isolation to them.

There are 6 files: a hunt you run first, the main rule, a rule for VS Code forks like Cursor, two NRT rules, and a script that refreshes the list inside the NRT rules.

The numbers in this README were checked on November 25, 2026.

## Why I built this

Extensions have had a bad year.

- On May 18, 2026, a poisoned Nx Console 18.95.0 went out through Microsoft's Marketplace and Open VSX. The extension has over 2.2 million installs. ([Nx postmortem](https://nx.dev/blog/nx-console-v18-95-0-postmortem))
- Between July 26 and August 1, 77 fake extensions landed on Open VSX under the names of real Marketplace extensions. ([The Hacker News](https://thehackernews.com/2026/08/open-vsx-removes-77-malicious-evil-twin.html))
- On October 29, tampered builds of the Claude Code extension, 2.1.312 and 2.1.313, were served through Cursor's marketplace for about 11 hours. ([Cursor](https://cursor.com/blog/security-incident-update), [StepSecurity](https://www.stepsecurity.io/blog/claude-code-extension-trojanized))

VS Code cleans up some of this by itself. When Microsoft confirms an extension is malicious, it goes on a block list and [VS Code uninstalls it](https://code.visualstudio.com/docs/configure/extensions/extension-runtime-security). That list has about 280 IDs. VSXSentry's malicious feed has 2,709. Everything that isn't on the block list stays installed wherever it already is.

Defender doesn't help much either. Its [advanced hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables) has tables for browser extensions and nothing for VS Code extensions.

I already lock extensions down with an allowlist through Intune. That's my [intune-vscode-extension-policy](https://github.com/EternalR00ted/intune-vscode-extension-policy) repo. The allowlist is the block. These rules are the alarm for the devices and editors the allowlist doesn't reach.

## Files

| File | What it does |
|---|---|
| `Check your telemetry first (hunt).kql` | Counts where extension IDs show up in your Defender data, one row per signal. It also lists the editors it saw. Run it first. |
| `Known bad VS Code extension on a device.kql` | The main rule. Daily, alert only. It matches VSXSentry's list in every editor. One row per device and extension, with a tier. |
| `Extension blocked by Open VSX on a VS Code fork.kql` | The fork rule. Daily, alert only. It matches Open VSX's block list in Cursor, Windsurf, VSCodium and other forks. |
| `Known malware VS Code extension, file activity (NRT).kql` | Near real time, on `DeviceFileEvents`. It matches malware Microsoft itself removed, and the poisoned releases. Built for device isolation. |
| `Known malware VS Code extension, process activity (NRT).kql` | The same thing on `DeviceProcessEvents`. |
| `Refresh the NRT list.py` | Rebuilds the ID list inside the two NRT rules from VSXSentry's feed. |

Status: Testing. The rebuild ran in Advanced hunting in a real tenant on November 25, 2026. The two NRT rules are new and haven't run anywhere yet. Nothing in this folder has run as a saved detection rule or with isolation attached. [How this was checked](#how-this-was-checked) has the details.

## Which rule does what

| | Main rule | Fork rule | NRT rules |
|---|---|---|---|
| Frequency | Every 24 hours, 30-day lookback | Every 24 hours, 30-day lookback | Continuous (NRT) |
| Where the list lives | Downloaded on every run | Downloaded on every run | Written into the query |
| What it matches | Malware, impersonation and removed for cause | Open VSX's block list, in forks only | Malware Microsoft removed, plus the poisoned releases |
| Result | One row per device and extension | One row per device and extension | One row per event |
| Device isolation | No | No | Yes, if you want it |

## What it checks against

| List | Entries | Used by | What it is |
|---|---|---|---|
| [VSXSentry malicious feed](https://vsxsentry.github.io/) | 2,709 | Main rule, every editor | Microsoft's [removed packages list](https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md) plus community reports, kept by mthcht. It's rebuilt every 6 hours. |
| [Open VSX extension control list](https://github.com/EclipseFdn/publish-extensions/blob/master/extension-control/extensions.json) | 966, or 937 without repeats | Fork rule, forks only | The IDs Open VSX blocks. 747 of them aren't in VSXSentry. |
| Entries inside the main rule | 18 | Main rule, set per entry | 5 IDs VSXSentry doesn't carry and 13 poisoned releases. The NRT rules carry the 13 releases too. |
| The list inside the NRT rules | 781 | NRT rules, every editor | The part of VSXSentry that Microsoft removed as malware at least 21 days ago. |

Every match in the main rule gets a tier.

| Tier | Categories | Entries | Severity |
|---|---|---|---|
| Malware | malware, impersonation-malware, spam-malware, potentially-malicious, poisoned-release | 962 from VSXSentry and 15 in the query | High |
| Impersonation | impersonation, typo-squatting | 1,228 from VSXSentry and 3 in the query | Medium |
| Removed for cause | untrustworthy, spam, copyright-violation | 503 from VSXSentry | Low |

A category the rule has never seen lands in Removed for cause, so a new one upstream still alerts.

The fork rule has no tiers. Every match is Medium. The NRT rules have no tiers either. Every match is High.

### What's left out on purpose

- **Housekeeping removals.** Owner request, publisher request, deprecated and expired domain. That's 14 entries. One of them is Microsoft's own Embedded Tools extension.
- **VSXSentry's risky feed.** It's 72 legitimate extensions that can be misused, like GitHub Copilot, Remote-SSH and PowerShell. It's worth a hunt. As an alert it would fire on half your developers. For the same reason, don't swap in `ioc_all_extension_ids.txt`. It includes the risky set.

### Real extensions with one bad release

Some of the worst cases are real extensions that shipped a poisoned version. A list of IDs can't hold those, because the ID would flag every clean version too.

That isn't a theory. VSXSentry lists `checkmarx.ast-results` and `checkmarx.cx-dev-assist` by ID, in its malware category. Those are the real Checkmarx One plugins. They had bad releases on [March 23 and April 22, 2026](https://checkmarx.com/blog/ongoing-security-updates/). Only those releases were bad.

So the main rule keeps a short list called `RealProducts`. For the 8 extensions on it, an ID alone never matches. Only an exact `id@version` does. There are 13 of those.

| Entry | Applies to | Source |
|---|---|---|
| `nrwl.angular-console@18.95.0` | Every editor | [Nx postmortem](https://nx.dev/blog/nx-console-v18-95-0-postmortem) |
| `checkmarx.ast-results@2.63.0` and `@2.66.0` | Every editor | [Checkmarx](https://checkmarx.com/blog/ongoing-security-updates/) |
| `checkmarx.cx-dev-assist@1.17.0` and `@1.19.0` | Every editor | [Checkmarx](https://checkmarx.com/blog/ongoing-security-updates/) |
| `checkmarx.ast-results@2.53.0` | Forks | [Checkmarx](https://checkmarx.com/blog/ongoing-security-updates/), [Wiz](https://www.wiz.io/blog/teampcp-attack-kics-github-action) |
| `checkmarx.cx-dev-assist@1.7.0` | Forks | [Checkmarx](https://checkmarx.com/blog/ongoing-security-updates/), [Wiz](https://www.wiz.io/blog/teampcp-attack-kics-github-action) |
| `oorzc.ssh-tools@0.5.1` | Forks | [The Hacker News](https://thehackernews.com/2026/02/open-vsx-supply-chain-attack-used.html) |
| `oorzc.i18n-tools-plus@1.6.8` | Forks | [The Hacker News](https://thehackernews.com/2026/02/open-vsx-supply-chain-attack-used.html) |
| `oorzc.mind-map@1.0.61` | Forks | [The Hacker News](https://thehackernews.com/2026/02/open-vsx-supply-chain-attack-used.html) |
| `oorzc.scss-to-css-compile@1.3.4` | Forks | [The Hacker News](https://thehackernews.com/2026/02/open-vsx-supply-chain-attack-used.html) |
| `anthropic.claude-code@2.1.312` and `@2.1.313` | Cursor | [Cursor](https://cursor.com/blog/security-incident-update) |

The March Checkmarx releases and the oorzc releases only went to Open VSX, so they only match in forks. The April Checkmarx releases went to both marketplaces. The Claude Code builds were only served through Cursor's marketplace, so those two only match inside Cursor.

OSV tracks poisoned releases with their versions under its `VSCode` ecosystem. Nx Console is [MAL-2026-5161](https://osv.dev/vulnerability/MAL-2026-5161). That's where I'd pull new entries from. When you add one, add the extension to `RealProducts` too.

The other 5 entries are IDs. 3 are hidden by a formatting slip in Microsoft's list, where two rows each have two IDs stuck together. 2 are the [Solidity Pro stealer](https://securityarsenal.com/blog/malicious-solidity-pro-vs-code-extensions-steal-crypto-wallets-and-credentials-detection-and-removal-guide), which Open VSX blocks and VSXSentry didn't list when I checked.

### Why the Open VSX list has its own rule

Two reasons.

**It only makes sense in forks.** When Open VSX removes a malicious extension, the ID goes on this list. The 77 fakes from this summer copied the names of real Marketplace extensions, and the list has names like `tsandall.opa` and `azurite.azurite` on it. On Microsoft's Marketplace those are the real OPA and Azurite extensions. Matching that list inside VS Code would alert on real installs. So the fork rule only looks at Cursor, Windsurf, VSCodium, Kiro, Antigravity, Trae and Positron. The list of forks is `ForkEditors` at the top of both daily rules.

**A failed download fails the whole query.** KQL has no way to catch a download that didn't work. With both lists in one rule, a bad minute at GitHub would have taken the VSXSentry matches down with it. The Open VSX list is served from `raw.githubusercontent.com`, and GitHub [rate limits downloads from there that aren't signed in](https://github.blog/changelog/2025-05-08-updated-rate-limits-for-unauthenticated-requests/). Now each rule downloads one file and fails alone.

190 IDs are on both lists. A fork install of one of those raises an alert from each rule.

## The NRT rules

[Continuous (NRT)](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules#continuous-nrt-frequency) checks events as they arrive. Microsoft only allows it for a query that reads one table, has no joins, unions or `externaldata`, has no comments, and sticks to a [short list of operators and functions](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-transformations-structure#supported-kql-features). The daily rules break all four. That's why the NRT rules look so different:

- There are two of them, one per table.
- The list is written into the query, because an NRT rule can't download one.
- The files have no header and no comments. This README is their header.
- The regexes are normal strings with doubled backslashes. That's the form Microsoft's page shows for NRT.
- They only use `where`, `extend`, `project`, `has`, `in`, `startswith`, `matches regex`, `extract`, `iif`, `isnotempty`, `strcat` and `tolower`. All of those are on the list.

### What's on the list inside them

781 IDs. An ID gets in when all three of these are true.

1. **Microsoft removed it from the Marketplace as malware.** That's 812 of VSXSentry's entries. The 148 malware entries that only come from community reports stay out. That's where the two real Checkmarx plugins are.
2. **It has been on Microsoft's list for at least 21 days.** 31 entries are waiting. In February 2025 Microsoft pulled Material Theme as malware, uninstalled it from millions of editors, and [restored it two weeks later with an apology](https://scworld.com/news/microsoft-restores-vs-code-theme-flagged-as-malicious-we-messed-up). It had nearly 4 million installs. A rule that isolates devices shouldn't act on a call that fresh.
3. **It isn't in `RealProducts`.**

The NRT rules also carry the 13 poisoned releases, with the same editor limits as the main rule.

Everything that's left off still alerts through the daily rules.

### What counts as a match

- **File activity.** A file created, changed or renamed in the VSIX cache, the extension's folder, or its storage or log folder. Deletions are skipped, so uninstalling the extension doesn't set the rule off.
- **Process activity.** A process started from the extension's folder or its storage folder, or a child of one.

There's no install-command signal in the NRT rules. A command that names a bad ID isn't proof it's on the device. The main rule still reports those.

### Keeping the list fresh

The list is a snapshot from November 25, 2026. Refresh it with:

```
python3 "Refresh the NRT list.py"
```

It downloads VSXSentry's feed, applies the three rules above, and rewrites the ID lines in both NRT files. It only uses Python's standard library. Then read the `git diff`, commit it, and paste the new queries into the two rules in the portal.

The script stops without writing anything if:

- an ID has any character outside letters, digits, dots, dashes and underscores. An ID with a quote in it could change what the query does.
- more than 100 IDs would be added or removed in one go. `--max-change` raises that when a big batch is real.
- the feed is missing a column or a date.

`--check` shows what would change and writes nothing. `--soak-days` changes the 21 days. `--feed` reads a copy you already have.

## If you attach device isolation

Put it on the two NRT rules. Leave it off the daily rules, for three reasons.

- **The daily rules download their list.** Whoever controls that file would control which of your devices get isolated. One bad commit upstream that adds a popular extension would start cutting off the developers who have it. The NRT list only changes when you commit a change to it.
- **The daily rules alert on spam and impersonation too.** Those are worth a look. They aren't worth cutting a developer off.
- **The daily rules look back 30 days.** The same event matches on every run. Defender folds the repeats into one alert. Microsoft's page doesn't say whether the action runs again each time, so I wouldn't count on a released device staying released.

Things to sort out before you turn it on:

- **Test isolate and release on one device first.** A custom detection applies [full isolation](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules#actions-on-devices). Microsoft [warns](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts#isolate-devices-from-the-network) that with a web proxy (PAC, WPAD or a static proxy) a device might not recover from isolation, and that a device behind a full VPN tunnel can't reach Defender once it's isolated. If either one describes your network, find out on a test device.
- **Scope the rule to workstations.** `.vscode-server` runs on whatever a developer connects to over SSH, so a match can come from a server. Use the Scope step to keep the rule on device groups you're willing to cut off.
- **Remove the extension before you release the device.** An isolated device keeps its connection to Defender, so you can still use live response on it. If the extension is still active when you release, the next event isolates the device again.
- **Run it alert-only for a while first.** A week of alerts with no action shows you what it would have isolated.

Triage card for the NRT rules (paste into Recommended actions):

- This fired on file or process activity from an extension Microsoft removed as malware, or from a known poisoned release. If isolation is on, the device is already cut off.
- Check ExtensionId, Version, EditorFolder and Evidence.
- Find out what the editor started after the first event. Plan on rotating the tokens, SSH keys and cloud keys that developer had.
- Remove the extension with live response before you release the device.

## How it spots an extension

VS Code doesn't install an extension straight into its final folder. It extracts into a folder with a random name, then renames that folder to `publisher.name-version`. That's in [VS Code's source](https://github.com/microsoft/vscode/blob/main/src/vs/platform/extensionManagement/node/extensionManagementService.ts). So the file events from the install itself don't carry the extension ID.

The rules look in 4 other places.

| Signal | What it matches | When you'd see it |
|---|---|---|
| VSIX cache | `CachedExtensionVSIXs\publisher.name-version` | A marketplace install or update. VS Code names the downloaded file after the extension. |
| Extension folder | `extensions\publisher.name-version\` | Later file activity in the installed folder, or a process started from it. |
| Storage or log folder | `User\globalStorage\publisher.name\`, `User\workspaceStorage\<id>\publisher.name\`, `logs\<time>\window1\exthost\publisher.name\` | The extension is running and writing state or logs. |
| Install command | `--install-extension publisher.name` | A command line install. Daily rules only. |

The matching doesn't care which editor it is. `.vscode`, `.vscode-insiders`, `.vscode-server`, `.cursor`, `.windsurf` and portable installs all match, with Windows, macOS and Linux paths.

## How I kept this from spamming

- The daily rules return one row per device and extension. The alert sits on the first event that matched. Defender groups results when the entities, custom details and dynamic details match, so the next run lands in the same alert.
- The NRT rules return one row per event, because NRT gives them no way to roll events up. The same grouping is what should keep that to one alert. They don't return file names or hashes as their own columns. The idea is to keep the entities down to the device and the user, so every event for one extension lands in one alert. That needs a real run to confirm.
- Use `ExtensionId` and `Tier` as custom details in the main rule, and `ExtensionId` alone in the fork rule and the NRT rules. Leave `Version`, `Versions`, `Signal` and `Signals` out. They change from event to event, and a changed custom detail makes a new alert.
- Housekeeping removals and the risky feed never alert.
- The Open VSX list never runs against VS Code.
- `AlertTiers` at the top of the main rule picks which tiers a copy alerts on. Save one copy per tier if you want a severity for each.
- Each rule caps out at 150 alerts per run. If one gets anywhere near that, check the feeds before you check your devices.
- The daily rules take no automated response actions. Every alert goes to a person.

## Before you deploy

- Creating custom detections takes Security settings (manage) or Security Administrator. You also need permissions for every device in the rule's scope.
- It needs Defender for Endpoint Plan 2 on the machines your developers use.
- Each daily rule downloads 1 file off the internet every time it runs. If that file is down or changes shape, the run fails or matches nothing. A bad commit upstream could also flood your queue or blind the rule. Copy both files into a repo or storage account you control and point the `externaldata` line in each rule there before you rely on this.
- A failed run shows up as Last run status on the Custom detection rules page. Check it after the first few runs.
- The daily rules can't run as Continuous (NRT). The NRT rules can run at any frequency.
- Don't add blank lines to the queries. The Defender query editor treats a blank line as the end of a query and runs only the part your cursor is in. A comment header above a blank line counts as its own query, and it isn't a valid one.
- Don't add comments to the NRT rules. NRT rejects a query that has any.
- The daily rules look back 30 days on purpose. Extensions usually get reported days or weeks after people install them, and the long lookback is what catches those. The first run can raise a month of matches at once.

## Deploying it

1. Run `Check your telemetry first (hunt).kql`. You want rows for more than one signal, and `SampleExtensions` should include extensions you know your developers use. If it comes back empty, Defender isn't recording enough and the rules can't fire for you.
2. Run the main rule's query in Advanced hunting. Anything that comes back is a real match, so triage it before you save the rule.
3. Create the detection rule and use `<Company> - MDE - Known bad VS Code extension on a device` as the alert title. You can paste the whole file. The header is all comments.
4. Set the frequency to Every 24 hours. It's the only frequency with a 30-day lookback.
5. Map entities. Defender data maps the device and the account on its own.
6. Add the custom details listed in the header.
7. Paste the triage card into Recommended actions.
8. For a severity per tier, save it 3 times and set `AlertTiers` to one tier in each copy.
9. If `Editors` in the telemetry check shows a fork, repeat steps 2 to 7 with `Extension blocked by Open VSX on a VS Code fork.kql`. Use `<Company> - MDE - Extension blocked by Open VSX on a VS Code fork` as the alert title and Medium as the severity.
10. For each NRT rule, paste the whole file and run it in Advanced hunting first. Create the rule with `<Company> - MDE - Known malware VS Code extension on a device` as the alert title, High severity and `ExtensionId` as the custom detail. Set the frequency to Continuous (NRT). If the wizard won't offer Continuous (NRT) for it, please open an issue. That part hasn't been tested. The same query can run at Every hour in the meantime.
11. Add Isolate device under Automated actions only after you've read [If you attach device isolation](#if-you-attach-device-isolation).

## Known blind spots

- **Quiet sideloads.** An extension installed from a `.vsix` skips the VSIX cache. If it also keeps no state and starts no processes, these rules have nothing to read.
- **Anything older than 30 days.** Advanced hunting goes back 30 days. An extension installed before that only shows up if it's still doing something.
- **New malware.** A list only knows what's been reported. The Nx Console build was live for under an hour, and the Claude Code builds for about 11 hours. That takes behavior rules, like the editor starting a shell or calling somewhere it shouldn't.
- **The NRT list is a snapshot.** It's as old as your last refresh, and a new Microsoft removal waits 21 days before it gets in. Until then it only alerts, through the main rule.
- **IDs have no version.** If a feed lists the ID of a real extension that shipped one bad release, every version matches. `RealProducts` covers the 8 I know about. Check `Versions` before you escalate anything else.
- **Real extensions sideloaded into a fork.** If a developer sideloads the real OPA extension into Cursor, the fork rule matches. That one is a false positive.
- **Forks I haven't listed.** The fork rule and the fork-only entries match on the folder or process name. Add yours to `ForkEditors` in both daily rules and to the same list inside both NRT rules.
- **Defender caps file events.** It doesn't record every file write. That's why the telemetry check comes first.

## How this was checked

Testing. The rebuild ran in Advanced hunting in a real tenant on November 25, 2026. Nothing has run as a saved rule yet, and the NRT rules haven't run at all.

The first try that day ended in a generic Advanced hunting error. I rebuilt the queries and the rerun worked. I changed three things at once, so I can't say which one fixed it:

- **No blank lines.** The first version had a blank line under the header comments. The Defender editor [treats a blank line as the end of a query](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-query-language#work-with-multiple-queries-in-the-editor) and runs only the part your cursor is in.
- **One download per rule.** The first version read both lists in one query.
- **Dedupe first, then `lookup`.** The first version joined every matching event to the list, with the big table on the left of a `join`. [Microsoft's guidance](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-best-practices) is to keep the smaller table on the left. [`lookup`](https://learn.microsoft.com/en-us/kusto/query/lookup-operator) is built for a big left side and a small list.

What was checked offline:

- **Syntax.** All 5 queries parse under [Microsoft's published KQL grammar](https://github.com/microsoft/Kusto-Query-Language/tree/master/grammar). I checked with a script that reads the grammar files and runs the queries through them. The same script accepts 13 known-good queries and rejects 16 broken ones.
- **NRT limits.** A check reads both NRT files and fails if it finds a second table, a comment, a join, a union, `externaldata`, or any operator or function that isn't on Microsoft's supported list.
- **Function calls.** I read every function and operator the daily queries use against the signatures in [Microsoft's Kusto.Language source](https://github.com/microsoft/Kusto-Query-Language/tree/master/src/Kusto.Language).
- **The lists.** I read both downloaded files byte for byte. The CSV is valid UTF-8 with no BOM and 10 fields on every one of its 2,710 lines. The JSON is strict JSON, and `malicious` is a flat list of strings.
- **Matching.** 408 checks cover Windows, macOS and Linux paths for each signal, the temp folders VS Code extracts and downloads into, browser extension folders that shouldn't match, and the list logic for all four rules. They read the regex strings and lists straight out of the `.kql` files, so the NRT rules' escaped regexes are compared with the main rule's character for character.
- **The NRT list.** A check recounts it from the feed and compares it with what's in the two files.
- **The refresh script.** It was run against a copy of the feed, and against copies I'd tampered with: 150 new IDs at once, an ID with a quote in it, a missing date, a missing column, and Microsoft's list naming a real product. It stopped or skipped every time. The download itself wasn't run. The machine I tested on can't reach the feed.

The list logic was tested as a Python copy of the queries' steps. That checks the design. It can't check the KQL.

55 bugs were planted in copies of the queries and the script, like a comment in an NRT rule or a real product in the isolation list. The tests caught all 55.

Column names were checked against Microsoft Learn's schema pages for `DeviceFileEvents` and `DeviceProcessEvents`. The feeds' columns and counts were read from the live files on November 25, 2026.

What's still open:

- Whether the rule wizard offers Continuous (NRT) for the two NRT queries. Each is about 29 KB, and I haven't found a published limit on query size.
- How the Isolate device action behaves on repeat matches.
- Which of the 4 signals Defender records in practice.

If a query errors for you, select View full query details under the error and open the Errors tab. That's where the real message is. Please open an issue with it.

## Credit

This builds on other people's work. Thanks to:

| Who | What I used | Link |
|---|---|---|
| mthcht | VSXSentry and the awesome-lists data behind it. It's the main feed. | [vsxsentry.github.io](https://vsxsentry.github.io/), [awesome-lists](https://github.com/mthcht/awesome-lists) |
| Microsoft | The removed packages list VSXSentry builds on, and VS Code's source for where an extension ID ends up on disk. Also the KQL grammar I checked the queries against. | [RemovedPackages.md](https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md), [vscode](https://github.com/microsoft/vscode), [Kusto-Query-Language](https://github.com/microsoft/Kusto-Query-Language) |
| Eclipse Foundation | Open VSX's extension control list. | [extensions.json](https://github.com/EclipseFdn/publish-extensions/blob/master/extension-control/extensions.json) |
| OpenSSF and OSV | Version-level records for poisoned releases. | [MAL-2026-5161](https://osv.dev/vulnerability/MAL-2026-5161) |

This is still a work in progress. If you spot a mistake or something fires way more than it should in your tenant, please feel free to open an issue.

## Sources

- [VSXSentry](https://vsxsentry.github.io/) and [its repo](https://github.com/vsxsentry/vsxsentry.github.io) (feed files, columns, category counts, the 6-hour sync)
- [Microsoft, History of Extensions Removed from VS Marketplace](https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md) (removal reasons, the two glued rows)
- [Open VSX extension control list](https://github.com/EclipseFdn/publish-extensions/blob/master/extension-control/extensions.json)
- [GitHub changelog, Updated rate limits for unauthenticated requests](https://github.blog/changelog/2025-05-08-updated-rate-limits-for-unauthenticated-requests/) (downloads from raw.githubusercontent.com)
- [VS Code docs, Extension runtime security](https://code.visualstudio.com/docs/configure/extensions/extension-runtime-security) (the block list and automatic uninstall)
- VS Code source: [extensionManagementService.ts](https://github.com/microsoft/vscode/blob/main/src/vs/platform/extensionManagement/node/extensionManagementService.ts) (extract to a random folder, then rename), [extensionDownloader.ts](https://github.com/microsoft/vscode/blob/main/src/vs/platform/extensionManagement/node/extensionDownloader.ts) (VSIX cache file names), [extHostStoragePaths.ts](https://github.com/microsoft/vscode/blob/main/src/vs/workbench/api/common/extHostStoragePaths.ts) (storage folders), [extHostExtensionService.ts](https://github.com/microsoft/vscode/blob/main/src/vs/workbench/api/common/extHostExtensionService.ts) (log folders)
- [Nx, Postmortem: Nx Console v18.95.0 supply-chain compromise](https://nx.dev/blog/nx-console-v18-95-0-postmortem)
- [Checkmarx, Update: Ongoing Checkmarx Supply Chain Security Incident](https://checkmarx.com/blog/ongoing-security-updates/) (which versions, which marketplace, both dates)
- [Wiz, KICS GitHub Action Compromised](https://www.wiz.io/blog/teampcp-attack-kics-github-action) (the March Checkmarx releases on Open VSX)
- [The Hacker News, Open VSX Removes 77 Malicious Evil Twin Extensions](https://thehackernews.com/2026/08/open-vsx-removes-77-malicious-evil-twin.html)
- [The Hacker News, Open VSX supply chain attack](https://thehackernews.com/2026/02/open-vsx-supply-chain-attack-used.html) (the 4 oorzc releases)
- [Cursor, An update on our recent security incident](https://cursor.com/blog/security-incident-update)
- [StepSecurity, Trojanized Claude Code Extension Delivered Persistent SSH Backdoor to Developer Machines](https://www.stepsecurity.io/blog/claude-code-extension-trojanized)
- [Security Arsenal, Malicious 'Solidity Pro' VS Code Extensions](https://securityarsenal.com/blog/malicious-solidity-pro-vs-code-extensions-steal-crypto-wallets-and-credentials-detection-and-removal-guide)
- [SC Media, Microsoft restores VS Code theme flagged as malicious](https://scworld.com/news/microsoft-restores-vs-code-theme-flagged-as-malicious-we-messed-up) (Material Theme, the reason for the 21 days)
- [OSV, MAL-2026-5161](https://osv.dev/vulnerability/MAL-2026-5161)
- [MITRE ATT&CK, T1176.002 Software Extensions: IDE Extensions](https://attack.mitre.org/techniques/T1176/002/)
- [Microsoft Learn, Create custom detection rules](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules) (lookbacks, what NRT allows, the Isolate device action, 150 alerts per run, how alerts get grouped)
- [Microsoft Learn, Supported KQL features in Azure Monitor transformations](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-transformations-structure#supported-kql-features) (the operator and function list NRT points to)
- [Microsoft Learn, Take response actions on a device](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts#isolate-devices-from-the-network) (isolation with proxies and VPNs, what an isolated device can still reach)
- [Microsoft Learn, Manage existing custom detection rules](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-manage) (Last run status)
- [Microsoft Learn, Learn the advanced hunting query language](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-query-language#work-with-multiple-queries-in-the-editor) (a blank line separates queries in the editor)
- [Microsoft Learn, Advanced hunting query best practices](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-best-practices) (smaller table on the left of a join)
- [Microsoft Learn, Handle advanced hunting errors](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-errors) and [Work with advanced hunting query results](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-query-results) (error types, the Errors tab)
- [Microsoft Learn, externaldata operator](https://learn.microsoft.com/en-us/kusto/query/externaldata-operator) and [lookup operator](https://learn.microsoft.com/en-us/kusto/query/lookup-operator)
- [microsoft/Kusto-Query-Language](https://github.com/microsoft/Kusto-Query-Language) (the KQL grammar and the function signatures)
- [Microsoft Learn, DeviceFileEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) and [DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
