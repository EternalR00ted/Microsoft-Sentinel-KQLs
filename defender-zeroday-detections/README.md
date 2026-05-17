# Defender Zero-Day Detection Pack — BlueHammer / RedSun / UnDefend

So Nightmare-Eclipse dropped three Defender zero-days on GitHub in April 2026, and Microsoft has only patched one of them. Detection-and-containment is the play for the other two until that changes.

This repo is my production detection coverage for all three: BlueHammer (CVE-2026-33825, patched), RedSun (unpatched), and UnDefend (unpatched). 30 rules total, written for Defender XDR Advanced Hunting and Microsoft Sentinel. I split them by exploit so you can grab what's relevant and ignore the rest.

## Quick context on each

**BlueHammer** is the read-side privilege escalation. It abuses Defender's signature update flow to mount a VSS snapshot, reads the SAM hive, dumps NTLM hashes, and escalates to SYSTEM. Microsoft patched this in April Patch Tuesday as CVE-2026-33825 (platform version 4.18.26030.3011 or later). If you're not on that version, fix it before reading the rest of this README.

**RedSun** is the write-side. It tricks Defender into restoring a "cloud-tagged" file to a path the attacker has swapped with a junction to System32. Defender obediently writes the attacker's binary into System32 as SYSTEM. No patch. CloudSEK reported ~100% reliability on fully-patched Windows 11 25H2.

**UnDefend** doesn't escalate anything. It just blinds Defender by locking the signature update files so new definitions can't load. The Defender management console reports the endpoint as healthy while the engine slowly goes blind. A standard unprivileged user can run it. No patch.

Huntress confirmed all three being used in real intrusions starting April 10, against a FortiGate SSL VPN with no MFA. The attacker dropped binaries named `FunnyApp.exe`, `RedSun.exe`, and `z.exe` into Pictures and Downloads, ran `whoami /priv` / `cmdkey /list` / `net group` to enumerate, and tried to chain RedSun + UnDefend. None of the privilege escalations actually succeeded in that specific incident, but the operator behavior is documented and worth detecting on.

## Status

| Exploit | CVE | Patched? |
|---|---|---|
| BlueHammer | CVE-2026-33825 | Yes. April 14, 2026 (`≥ 4.18.26030.3011`) |
| RedSun | None assigned | No, and no out-of-band patch in May Patch Tuesday |
| UnDefend | None assigned | No |

CISA added CVE-2026-33825 to the KEV catalog on April 22, with an FCEB deadline of May 6. If you work for the US federal government and this isn't deployed, you're already late.

## Repo layout

```
defender-zeroday-detections/
├── README.md          ← this file
├── HARDENING.md       ← prevention controls (ASR, Tamper Protection, AppLocker, etc.)
├── LICENSE            ← MIT
│
├── BlueHammer/        ← 7 rules + README (patched, useful for historical hunts)
├── RedSun/            ← 7 rules + README (unpatched, deploy first)
├── UnDefend/          ← 5 rules + README (unpatched)
└── Shared/            ← 11 rules + README (cross-exploit + kill-chain correlation)
```

Each `.kql` file is self-contained. Open it and you get a header comment with the rule name, severity, MITRE mapping, frequency, response actions, and how to deploy it. The KQL itself sits below. Copy the query straight into the XDR portal or Sentinel and it works.

## How to deploy

### Defender XDR Custom Detection Rules

1. Open the `.kql` file.
2. Copy everything below the `// ===` header block.
3. M365 Defender portal → Hunting → Advanced hunting. Paste, run the query, make sure it returns what you expect.
4. Save as → Detection rule. Use the rule name from the header.
5. Set frequency, severity, MITRE ATT&CK, and auto-response actions per the header.

Every rule projects `Timestamp`, `DeviceId`, and `ReportId`. Don't remove those. The portal refuses to save the rule without them.

### Sentinel Analytics Rules

A handful of rules are Sentinel-only because they query TVM tables or `SecurityEvent` and don't produce `ReportId` reliably. They're flagged `Deploy As: Sentinel Analytics Rule` in the header. Mostly fleet-wide Defender health checks (`UD-T5-*`, `BH-T5-3`) and the FortiGate VPN logon correlation (`T4-2`).

1. Sentinel workspace → Analytics → Create → Scheduled query rule.
2. Paste the KQL.
3. Map entities: `DeviceName` → Host, `DeviceId` → HostCustomEntity.
4. Set frequency, lookup period, and threshold per the header.

## What order to deploy in

Start with the highest signal, lowest false-positive rules and work down. If a rule generates too many alerts in your environment, stop and tune before continuing.

**Phase 1, deploy first:**

1. `Shared/T0-1-defender-native-signature.kql`. Microsoft already catches the unmodified PoCs. Zero false positives. Easiest win in the pack.
2. `Shared/T1-1-hands-on-keyboard-enumeration.kql`. The `whoami /priv` + `cmdkey /list` + `net group` triad Huntress observed before every exploitation attempt. If this fires, an operator is on the box.
3. `RedSun/RS-T2-1-defender-arbitrary-write-system32.kql`. MsMpEng writing executables into System32. Highest-confidence RedSun catch.
4. `Shared/T4-1-beigeburrow-tunneling-agent.kql`. The only component that successfully connected outbound in the Huntress intrusion.

**Phase 2, vulnerability primitives:**

5. `UnDefend/UD-T2-3-signature-database-access.kql`
6. `Shared/T2-2-ntfs-junction-user-temp.kql`
7. `Shared/T2-5-vss-enumeration-non-backup.kql`
8. `BlueHammer/BH-T2-6-sam-hive-access-via-defender-chain.kql`
9. `BlueHammer/BH-T2-7-transient-service-from-user-path.kql`
10. `UnDefend/UD-T2-4-update-error-80070643.kql`

**Phase 3, PoC-specific IoCs.** Tier 3 rules catch the unmodified samples but a recompile bypasses them. Worth deploying anyway because they're cheap and the original PoC strings are still common in lazy reuse.

**Phase 4, post-exploitation and fleet health checks.** Tier 4 and Tier 5 rules.

**Phase 5, kill-chain correlation.** `COMBO-1` and `COMBO-2` in `Shared/`. These fire when multiple independent signals line up. Auto-isolate on these.

Each folder README has the full deployment table for its rules.

## Tables you'll need

The pack uses these Defender XDR Advanced Hunting tables. If your RBAC scope blocks any of them, the corresponding rules will fail to save:

- `DeviceProcessEvents`
- `DeviceFileEvents`
- `DeviceEvents`
- `DeviceImageLoadEvents`
- `DeviceRegistryEvents`
- `DeviceLogonEvents`
- `DeviceNetworkEvents`
- `DeviceTvmInfoGathering` (Sentinel)
- `DeviceTvmSoftwareInventory` (Sentinel)
- `SecurityEvent` (Sentinel, for VPN logon correlation)

## A note on what's mine and what isn't

A lot of the detection logic for RedSun and UnDefend started from public community work and I built on it. Specifically:

- `3ch0p01nt/RedSun_Undefend` (MIT licensed) is where most of the RedSun and UnDefend primitive detection patterns come from. Several `RS-T3-*`, `UD-T2-*`, and `UD-T5-*` rules build on what they published. Their repo is excellent and you should read it.
- `jkerai1/KQL-Queries` is where the REDSUN pipe `DesiredAccess` + `AcceptRemote` pattern comes from.
- `microsoft/Microsoft-365-Defender-Hunting-Queries` (MIT) is where the TVM table parsing pattern in `BH-T5-3` comes from.

What I added on top: production hardening so the rules actually save in the XDR portal (mandatory `Timestamp` / `DeviceId` / `ReportId` projections), MITRE mapping, severity recommendations, false-positive analysis, the Sentinel-vs-XDR deployment split, integer-based version comparison in `BH-T5-3` instead of brittle string comparison, the Tier 0 native-signature layer, the Tier 1 hands-on-keyboard correlation, the Tier 4 post-exploitation rules including BeigeBurrow, and both COMBO kill-chain rules.

Vulnerability research credit:

- BlueHammer (CVE-2026-33825). Microsoft credits Zen Dodd and Yuanpei Xu (HUST, working with Diffract). The public PoC was dropped by Chaotic Eclipse / Nightmare-Eclipse on April 3, 2026.
- RedSun and UnDefend. Discovered and publicly released by Chaotic Eclipse / Nightmare-Eclipse on April 12 and April 16, 2026. No CVEs assigned.

Active exploitation reporting:

- Huntress Labs, *Nightmare-Eclipse Tooling Seen in Real-World Intrusion* (April 21, 2026). Their writeup is the primary source for the in-the-wild TTPs I built detections against in this pack.

## Sources I used

- CloudSEK, *RedSun: Windows 0day when Defender becomes the attacker*
- Cyderes / Howler Cell, *RedSun Zero-Day: When Defender Becomes the Delivery Mechanism*
- Fortra / Core Security, *Analysis of RedSun: Local Privilege Escalation via Defender Remediation Abuse*
- Huntress Labs, *Nightmare-Eclipse Tooling Seen in Real-World Intrusion*
- Microsoft Security Response Center, CVE-2026-33825
- CISA Known Exploited Vulnerabilities Catalog

If you spot a mistake in any of the queries, the technical reference, or the attribution, please open an issue or leave a comment. I'm still learning and feedback makes the next iteration better.

## License

MIT. See `LICENSE`.
