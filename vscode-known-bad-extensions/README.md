# Known Bad VS Code Extensions

A VS Code extension runs with the same rights as the editor. A bad one can read your source code and every token on the machine. This folder is one Defender XDR custom detection that tells you when an extension on a device is on a public list of extensions that were pulled for cause.

There are 2 files: the rule, and a hunt you run first to see what your tenant records.

The numbers in this README were checked on November 24, 2026.

## Why I built this

Extensions have had a bad year.

- On May 18, 2026, a poisoned Nx Console 18.95.0 went out through Microsoft's Marketplace and Open VSX. The extension has over 2.2 million installs. ([Nx postmortem](https://nx.dev/blog/nx-console-v18-95-0-postmortem))
- Between July 26 and August 1, 77 fake extensions landed on Open VSX under the names of real Marketplace extensions. ([The Hacker News](https://thehackernews.com/2026/08/open-vsx-removes-77-malicious-evil-twin.html))
- On October 29, tampered builds of the Claude Code extension, 2.1.312 and 2.1.313, were served through Cursor's marketplace for about 11 hours. ([Cursor](https://cursor.com/blog/security-incident-update), [StepSecurity](https://www.stepsecurity.io/blog/claude-code-extension-trojanized))

VS Code cleans up some of this by itself. When Microsoft confirms an extension is malicious, it goes on a block list and [VS Code uninstalls it](https://code.visualstudio.com/docs/configure/extensions/extension-runtime-security). That list has about 280 IDs. VSXSentry's malicious feed has 2,705. Everything that isn't on the block list stays installed wherever it already is.

Defender doesn't help much either. Its [advanced hunting schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-tables) has tables for browser extensions and nothing for VS Code extensions.

I already lock extensions down with an allowlist through Intune. That's my [intune-vscode-extension-policy](https://github.com/EternalR00ted/intune-vscode-extension-policy) repo. The allowlist is the block. This rule is the alarm for the devices and editors the allowlist doesn't reach.

## Files

| File | What it does |
|---|---|
| `Check your telemetry first (hunt).kql` | Counts where extension IDs show up in your Defender data, one row per signal. Run it first. |
| `Known bad VS Code extension on a device.kql` | The rule. One row per device and extension, with a tier. |

Status: Testing. Neither file has had its first run in a real tenant yet.

## What it checks against

| List | Entries | Applies to | What it is |
|---|---|---|---|
| [VSXSentry malicious feed](https://vsxsentry.github.io/) | 2,705 | Every editor | Microsoft's [removed packages list](https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md) plus community reports, kept by mthcht. It's rebuilt every 6 hours. |
| [Open VSX extension control list](https://github.com/EclipseFdn/publish-extensions/blob/master/extension-control/extensions.json) | About 500 | Forks only | The IDs Open VSX blocks. |
| Entries inside the query | 10 | Set per entry | IDs and poisoned releases the two lists don't carry. |

Every match gets a tier.

| Tier | Categories | Entries | Severity |
|---|---|---|---|
| Malware | malware, impersonation-malware, spam-malware, potentially-malicious, poisoned-release | 964 from VSXSentry and 7 in the query | High |
| Impersonation | impersonation, typo-squatting, open-vsx-blocklist | 1,227 from VSXSentry, about 500 from Open VSX and 3 in the query | Medium |
| Removed for cause | untrustworthy, spam, copyright-violation | 500 from VSXSentry | Low |

A category the rule has never seen lands in Removed for cause, so a new one upstream still alerts.

### What's left out on purpose

- **Housekeeping removals.** Owner request, publisher request, deprecated and expired domain. That's 14 entries. One of them is Microsoft's own Embedded Tools extension.
- **VSXSentry's risky feed.** It's 72 legitimate extensions that can be misused, like GitHub Copilot, Remote-SSH and PowerShell. It's worth a hunt. As an alert it would fire on half your developers. For the same reason, don't swap in `ioc_all_extension_ids.txt`. It includes the risky set.

### Why the Open VSX list only applies to forks

When Open VSX removes a malicious extension, the ID goes on this list. The 77 fakes from this summer copied the names of real Marketplace extensions, and the list has names like `tsandall.opa` and `azurite.azurite` on it. On Microsoft's Marketplace those are the real OPA and Azurite extensions. Matching that list inside VS Code would alert on real installs.

So the rule only uses it when the path or process belongs to a fork: Cursor, Windsurf, VSCodium, Kiro, Antigravity, Trae or Positron. The list of forks is `ForkEditors` at the top of the query.

### Poisoned releases

Some of the worst cases are real extensions that shipped one bad version. An ID-only list can't hold those, because it would flag every clean version too. The query takes `id@version` entries for them. It ships with 5.

| Entry | Applies to | Source |
|---|---|---|
| `nrwl.angular-console@18.95.0` | Every editor | [Nx postmortem](https://nx.dev/blog/nx-console-v18-95-0-postmortem) |
| `oorzc.ssh-tools@0.5.1` | Forks | [The Hacker News](https://thehackernews.com/2026/02/open-vsx-supply-chain-attack-used.html) |
| `oorzc.i18n-tools-plus@1.6.8` | Forks | [The Hacker News](https://thehackernews.com/2026/02/open-vsx-supply-chain-attack-used.html) |
| `anthropic.claude-code@2.1.312` | Cursor | [Cursor](https://cursor.com/blog/security-incident-update) |
| `anthropic.claude-code@2.1.313` | Cursor | [Cursor](https://cursor.com/blog/security-incident-update) |

The Claude Code builds were only served through Cursor's marketplace, so those two only match inside Cursor. The oorzc releases were published to Open VSX, so they only match in forks.

OSV tracks poisoned releases with their versions under its `VSCode` ecosystem. Nx Console is [MAL-2026-5161](https://osv.dev/vulnerability/MAL-2026-5161). That's where I'd pull new entries from.

The other 5 entries are IDs. 3 are hidden by a formatting slip in Microsoft's list, where two rows each have two IDs stuck together. 2 are the [Solidity Pro stealer](https://securityarsenal.com/blog/malicious-solidity-pro-vs-code-extensions-steal-crypto-wallets-and-credentials-detection-and-removal-guide), which Open VSX blocks and VSXSentry didn't list when I checked.

## How it spots an extension

VS Code doesn't install an extension straight into its final folder. It extracts into a folder with a random name, then renames that folder to `publisher.name-version`. That's in [VS Code's source](https://github.com/microsoft/vscode/blob/main/src/vs/platform/extensionManagement/node/extensionManagementService.ts). So the file events from the install itself don't carry the extension ID.

The rule looks in 4 other places.

| Signal | What it matches | When you'd see it |
|---|---|---|
| VSIX cache | `CachedExtensionVSIXs\publisher.name-version` | A marketplace install or update. VS Code names the downloaded file after the extension. |
| Extension folder | `extensions\publisher.name-version\` | Later file activity in the installed folder, or a process started from it. |
| Storage or log folder | `User\globalStorage\publisher.name\`, `User\workspaceStorage\<id>\publisher.name\`, `logs\<time>\window1\exthost\publisher.name\` | The extension is running and writing state or logs. |
| Install command | `--install-extension publisher.name` | A command line install. |

The matching doesn't care which editor it is. `.vscode`, `.vscode-insiders`, `.vscode-server`, `.cursor`, `.windsurf` and portable installs all match, with Windows, macOS and Linux paths.

## How I kept this from spamming

- One row per device and extension. The alert sits on the first event that matched. Defender groups results when the entities, custom details and dynamic details match, so the next run lands in the same alert.
- Use `ExtensionId` and `Tier` as custom details. Leave `Versions` and `Signals` out. They grow as more evidence comes in, and a changed custom detail makes a new alert.
- Housekeeping removals and the risky feed never alert.
- The Open VSX list is ignored inside VS Code.
- `AlertTiers` at the top picks which tiers a copy alerts on. Save one copy per tier if you want a severity for each.
- Each rule caps out at 150 alerts per run. If this one gets anywhere near that, check the feeds before you check your devices.
- It takes no automated response actions. Every alert goes to a person.

## Before you deploy

- Creating custom detections takes Security settings (manage) or Security Administrator.
- It needs Defender for Endpoint Plan 2 on the machines your developers use.
- The rule reads 2 files off the internet every time it runs. If either one is down or changes shape, the run fails or matches nothing. A bad commit upstream could also flood your queue or blind the rule. Copy both files into a repo or storage account you control and point the two `externaldata` lines there before you rely on this.
- `externaldata` rules can't run as Continuous (NRT).
- It looks back 30 days on purpose. Extensions usually get reported days or weeks after people install them, and the long lookback is what catches those. The first run can raise a month of matches at once.

## Deploying it

1. Run `Check your telemetry first (hunt).kql`. You want rows for more than one signal, and `SampleExtensions` should include extensions you know your developers use. If it comes back empty, Defender isn't recording enough and the rule can't fire for you.
2. Run the rule's query in Advanced hunting. Anything that comes back is a real match, so triage it before you save the rule.
3. Create the detection rule and use `<Company> - MDE - Known bad VS Code extension on a device` as the alert title. Copy only the query and leave the header out.
4. Set the frequency to Every 24 hours. It's the only frequency with a 30-day lookback.
5. Map entities. Defender data maps the device and the account on its own.
6. Add the custom details listed in the header.
7. Paste the triage card into Recommended actions.
8. For a severity per tier, save it 3 times and set `AlertTiers` to one tier in each copy.

## Known blind spots

- **Quiet sideloads.** An extension installed from a `.vsix` skips the VSIX cache. If it also keeps no state and starts no processes, this rule has nothing to read.
- **Anything older than 30 days.** Advanced hunting goes back 30 days. An extension installed before that only shows up if it's still doing something.
- **New malware.** A list only knows what's been reported. The Nx Console build was live for under an hour, and the Claude Code builds for about 11 hours. That takes behavior rules, like the editor starting a shell or calling somewhere it shouldn't.
- **IDs have no version.** If a feed lists the ID of a real extension that shipped one bad release, every version matches. Check `Versions` before you escalate.
- **Real extensions sideloaded into a fork.** If a developer sideloads the real OPA extension into Cursor, the Open VSX entry matches. That one is a false positive.
- **Forks I haven't listed.** Fork-only entries match on the folder or process name. Add yours to `ForkEditors`.
- **Defender caps file events.** It doesn't record every file write. That's why the telemetry check comes first.

## How this was checked

Testing. It hasn't run in a live tenant yet.

The matching logic was tested offline with 165 checks. They cover Windows, macOS and Linux paths for each signal. They cover the temp folders VS Code extracts and downloads into, and browser extension folders that shouldn't match. They also cover the list logic: tiers, housekeeping removals, fork-only entries and version pins.

The tests read the regex strings and lists straight out of the two `.kql` files and run them through Python's engine. The patterns only use features that behave the same in Python and KQL.

The list logic was tested as a Python copy of the query's steps. That checks the design. It can't check the KQL.

18 bugs were planted in copies of the queries, like dropping the VSIX cache from the regex or widening a Cursor-only entry to every editor. The tests caught all 18.

Column names were checked against Microsoft Learn's schema pages for `DeviceFileEvents` and `DeviceProcessEvents`. The feeds' columns and counts were read from the live files on November 24, 2026.

What's still open: nobody has run the queries in Advanced hunting, and I don't know yet which of the 4 signals Defender records in practice. Your first run of the telemetry check is the real test.

## Credit

This builds on other people's work. Thanks to:

| Who | What I used | Link |
|---|---|---|
| mthcht | VSXSentry and the awesome-lists data behind it. It's the main feed. | [vsxsentry.github.io](https://vsxsentry.github.io/), [awesome-lists](https://github.com/mthcht/awesome-lists) |
| Microsoft | The removed packages list VSXSentry builds on, and VS Code's source for where an extension ID ends up on disk. | [RemovedPackages.md](https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md), [vscode](https://github.com/microsoft/vscode) |
| Eclipse Foundation | Open VSX's extension control list. | [extensions.json](https://github.com/EclipseFdn/publish-extensions/blob/master/extension-control/extensions.json) |
| OpenSSF and OSV | Version-level records for poisoned releases. | [MAL-2026-5161](https://osv.dev/vulnerability/MAL-2026-5161) |

This is still a work in progress. If you spot a mistake or something fires way more than it should in your tenant, please feel free to open an issue.

## Sources

- [VSXSentry](https://vsxsentry.github.io/) and [its repo](https://github.com/vsxsentry/vsxsentry.github.io) (feed files, columns, category counts, the 6-hour sync)
- [Microsoft, History of Extensions Removed from VS Marketplace](https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md) (removal reasons, the two glued rows)
- [Open VSX extension control list](https://github.com/EclipseFdn/publish-extensions/blob/master/extension-control/extensions.json)
- [VS Code docs, Extension runtime security](https://code.visualstudio.com/docs/configure/extensions/extension-runtime-security) (the block list and automatic uninstall)
- VS Code source: [extensionManagementService.ts](https://github.com/microsoft/vscode/blob/main/src/vs/platform/extensionManagement/node/extensionManagementService.ts) (extract to a random folder, then rename), [extensionDownloader.ts](https://github.com/microsoft/vscode/blob/main/src/vs/platform/extensionManagement/node/extensionDownloader.ts) (VSIX cache file names), [extHostStoragePaths.ts](https://github.com/microsoft/vscode/blob/main/src/vs/workbench/api/common/extHostStoragePaths.ts) (storage folders), [extHostExtensionService.ts](https://github.com/microsoft/vscode/blob/main/src/vs/workbench/api/common/extHostExtensionService.ts) (log folders)
- [Nx, Postmortem: Nx Console v18.95.0 supply-chain compromise](https://nx.dev/blog/nx-console-v18-95-0-postmortem)
- [The Hacker News, Open VSX Removes 77 Malicious Evil Twin Extensions](https://thehackernews.com/2026/08/open-vsx-removes-77-malicious-evil-twin.html)
- [The Hacker News, Open VSX supply chain attack](https://thehackernews.com/2026/02/open-vsx-supply-chain-attack-used.html) (the oorzc releases)
- [Cursor, An update on our recent security incident](https://cursor.com/blog/security-incident-update)
- [StepSecurity, Trojanized Claude Code Extension Delivered Persistent SSH Backdoor to Developer Machines](https://www.stepsecurity.io/blog/claude-code-extension-trojanized)
- [Security Arsenal, Malicious 'Solidity Pro' VS Code Extensions](https://securityarsenal.com/blog/malicious-solidity-pro-vs-code-extensions-steal-crypto-wallets-and-credentials-detection-and-removal-guide)
- [OSV, MAL-2026-5161](https://osv.dev/vulnerability/MAL-2026-5161)
- [MITRE ATT&CK, T1176.002 Software Extensions: IDE Extensions](https://attack.mitre.org/techniques/T1176/002/)
- [Microsoft Learn, Create custom detection rules](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules) (30-day lookback at Every 24 hours, 150 alerts per run, how alerts get grouped, NRT limits)
- [Microsoft Learn, externaldata operator](https://learn.microsoft.com/en-us/kusto/query/externaldata-operator)
- [Microsoft Learn, DeviceFileEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) and [DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
