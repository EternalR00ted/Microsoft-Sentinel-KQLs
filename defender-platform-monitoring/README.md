# Defender Platform Monitoring

Defender is supposed to catch the bad guys. The problem is the bad guys know that too. Ransomware groups kill EDR before they encrypt now, and in April someone dropped three Defender zero-days on GitHub.

So I started building alerts for Defender itself. That's what this folder is. 17 rules so far, all Defender XDR custom detections, and one of them reads a Sentinel table.

If you're here for BlueHammer, RedSun or UnDefend specifically, check out my `defender-zeroday-detections` pack. It goes after those exploits directly. This folder is about the platform side.

## Why I built this

A big part of it was the April zero-days. Nightmare-Eclipse dropped BlueHammer, RedSun and UnDefend. BlueHammer (CVE-2026-33825) is on CISA's KEV list now and [has been used in ransomware attacks](https://www.securityweek.com/bluehammer-vulnerability-exploited-in-ransomware-attacks/). UnDefend is the one that matters most for this folder. A standard user can run it to block Defender's signature updates, and from [what's been written about it](https://labs.cloudsecurityalliance.org/research/csa-research-note-defender-triple-zero-day-bluehammer-redsun/), the console keeps showing the device as healthy the whole time. I think that's the worst one for a SOC, because nothing looks wrong.

The other part is EDR killers. [ESET counted 54 of them](https://bellatorcyber.com/blog/edr-killers-byovd-signed-vulnerable-drivers-2026) in March 2026, abusing 35 signed vulnerable drivers between them. Some operators skip the driver completely and just reboot the box into Safe Mode, where Defender doesn't run. [Huntress wrote up](https://www.huntress.com/blog/how-attackers-disable-av-edr) an Akira affiliate doing exactly that.

Then there are the gaps. ASR has rules that block vulnerable drivers and Safe Mode reboots, but [Microsoft's own ASR reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference) says neither one raises an EDR alert. So the block happens and nothing shows up in your queue. Same goes for Defender settings. If someone changes one in the portal, nothing alerts on it by default.

## Layout

```
defender-platform-monitoring/
├── health/    Defender not working
├── tamper/    Someone going after Defender
└── audit/     Admin changes that can turn it off
```

Every `.kql` file starts with a short header with what it catches, the severity, MITRE mapping, prerequisites and a triage card. Paste the triage card into the rule's Recommended actions field so whoever picks up the alert knows what to check.

## Rules

Live means I've had the rule running in a real tenant for at least two weeks. Testing means it hasn't gotten there yet.

| Rule | File | Runs | Severity | Status |
|---|---|---|---|---|
| Defender sensor unhealthy | `health/sensor-unhealthy.kql` | Every 24 hours | Medium | Testing |
| Defender signatures not updating | `health/signatures-not-updating.kql` | Every 24 hours | Medium | Testing |
| Defender protection off | `health/protection-off.kql` | Every 24 hours | High | Testing |
| Defender antivirus not active | `health/antivirus-not-active.kql` | Every 24 hours | High | Testing |
| Server stopped reporting to Defender | `health/server-stopped-reporting.kql` | Every 3 hours | High | Testing |
| Defender platform or engine out of date | `health/platform-or-engine-out-of-date.kql` | Every 24 hours | Low | Testing |
| Vulnerable driver dropped | `tamper/vulnerable-driver-dropped.kql` | Continuous (NRT) | High | Testing |
| Safe Mode reboot attempt | `tamper/safe-mode-reboot-attempt.kql` | Continuous (NRT) | High | Testing |
| Safe Mode boot set with bcdedit | `tamper/safe-mode-boot-set-with-bcdedit.kql` | Continuous (NRT) | High | Testing |
| Driver loaded from user or temp folder | `tamper/driver-loaded-from-user-or-temp-folder.kql` | Continuous (NRT) | Medium | Testing |
| Defender Live Response used | `audit/live-response-used.kql` | Continuous (NRT) | Medium | Testing |
| Defender offboarding package downloaded | `audit/offboarding-package-downloaded.kql` | Continuous (NRT) | High | Testing |
| Defender advanced feature changed | `audit/advanced-feature-changed.kql` | Continuous (NRT) | Medium | Testing |
| App granted Defender API permissions | `audit/app-granted-defender-api-permissions.kql` | Continuous (NRT) | High | Testing |
| Defender troubleshooting mode turned on | `audit/troubleshooting-mode-turned-on.kql` | Continuous (NRT) | Medium | Testing |
| Intune policy deleted or reassigned | `audit/intune-policy-deleted-or-reassigned.kql` | Every hour | Low | Testing |
| Custom detection rule deleted | `audit/custom-detection-rule-deleted.kql` | Continuous (NRT) | Medium | Testing |

If you only deploy two things from here, I'd go with "Vulnerable driver dropped" and "Safe Mode boot set with bcdedit". They should be close to silent in most environments, and if either one fires you want to know about it.

## How I kept these from spamming

Nobody wants another rule that fires 200 times a day, so I built these with a few things in mind:

- One alert per device per problem. Defender groups results together when the entities, custom details and dynamic details match. So the titles are fixed text, and the custom details only use things that don't change between runs, like a setting name or a version number.
- New custom detections scan the last 30 days as soon as you save them. The event rules have `ingestion_time() > ago(1d)` in them so your first day isn't a month's worth of alerts.
- The health rules only look at devices that sent process telemetry in the last 24 hours, so a laptop that's been off for a week won't page anyone.
- The health rules will also fire on every device that's already broken. Clean up your backlog first or day one is going to flood your queue.
- "Server stopped reporting to Defender" should be scoped to a server device group. Laptops go offline constantly. Servers really shouldn't.
- Each rule caps out at 150 alerts per run. If one of these gets anywhere near that, something's wrong.
- None of them take automated response actions. Every alert goes to a person.

## Why some checks aren't here

You won't find a rule for tamper protection blocks. Microsoft already [raises alerts when it detects tampering](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/tamper-resiliency?view=o365-worldwide), so mine would just be a duplicate.

Posture stuff like ASR rule states and onboarding gaps stays as manual queries. Nobody needs to act on those within hours.

I also looked at Sentinel summary rules for the trend side and skipped them. They only process the last 24 hours and can't raise alerts on their own. Most of these checks need TVM tables too, and those never make it into Sentinel.

## Before you deploy

- Creating custom detections takes Security settings (manage) or Security Administrator. "Intune policy deleted or reassigned" reads a Sentinel table, so it also needs Microsoft Sentinel Contributor and a workspace connected to the Defender portal.
- The CloudAppEvents audit rules need the Defender for Cloud Apps Microsoft 365 connector with Microsoft 365 activities turned on.
- "App granted Defender API permissions" reads Entra ID audit events from `CloudAppEvents`, so it needs that same connector. "Intune policy deleted or reassigned" needs Intune diagnostic settings sending audit logs to your workspace.
- "Vulnerable driver dropped" and "Safe Mode reboot attempt" only fire if their ASR rules are in Audit or Block. The bcdedit one doesn't depend on ASR at all.
- "Defender antivirus not active" skips any device with the exception tag named in the query. Tag the devices that are passive on purpose.

## Deploying one

1. Run the query in Advanced hunting over the last 30 days first and count rows per day. That gives you a rough idea of how noisy it'll be in your tenant.
2. Create the detection rule and use the rule name as the alert title. Copy only the query and leave the header out. Continuous (NRT) rules won't take a query with comments in it.
3. Set the frequency from the table above.
4. Map entities. Defender data maps on its own. For the Intune rule, map the account to the Actor column yourself.
5. Paste the triage card into Recommended actions.
6. Give it a week, then check the volume. My rule of thumb: if one rule fires more than 5 times a week, it needs tuning.

The thresholds in the queries are just my defaults. Tune them for your environment.

## Credit

A few of these started from other people's queries, so shoutout to them:

- [Bert-Jan Pals](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules). The offboarding package and custom detection deletion rules started from his queries, and his [post on auditing Defender XDR](https://kqlquery.com/posts/audit-defender-xdr/) is worth a read.
- [Jeffrey Appel](https://jeffreyappel.nl/how-to-check-for-a-healthy-defender-for-endpoint-environment/). The health checks use the scid list from his write-up, and the advanced features rule started from [this post](https://jeffreyappel.nl/auditing-microsoft-defender-and-intune-configuration-changes/).

If you've never read [Microsoft's custom detection docs](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules), the part on how alerts get grouped is what most of the anti-spam stuff here is based on.

This is still a work in progress and I'll keep adding rules as I build them. If you spot a mistake or something fires way more than it should in your tenant, please feel free to open an issue.
