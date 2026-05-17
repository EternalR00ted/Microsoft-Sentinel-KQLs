# Shared

These are the rules that don't belong to a single exploit. Some catch behavior that's common across all three (NTFS junction creation, VSS shadow copy enumeration). Some catch operator behavior that happens regardless of which exploit gets used (the enumeration triad, the BeigeBurrow tunneling agent). Some are full kill-chain correlations that fire when independent signals line up.

If you can only deploy one rule from this entire pack, deploy `T0-1`. If you can deploy two, add `T1-1`. If three, add `T4-1`.

## Rules in this folder

### Tier 0 — Defender's own signatures

| Rule ID | File | Severity | What it catches |
|---|---|---|---|
| T0-1 | `T0-1-defender-native-signature.kql` | Critical | Defender detected an unmodified Nightmare-Eclipse PoC by name: `DfndrPEBluHmr*` (BlueHammer), `Halaminer.D!ml` (RedSun PoC source), or `Wacapew.C!ml` (RedSun in-the-wild variant per Huntress). |

Zero false positives. Microsoft maintains the signatures. Deploy with auto-isolate on every endpoint. This is the easiest, highest-confidence rule in the pack and there's no reason not to turn it on first.

### Tier 1 — Hands-on-keyboard

| Rule ID | File | Severity | What it catches |
|---|---|---|---|
| T1-1 | `T1-1-hands-on-keyboard-enumeration.kql` | High | The exact `whoami /priv` + `cmdkey /list` + `net group` triad Huntress observed before every Nightmare-Eclipse exploitation attempt, correlated within a 30-minute window. |
| T1-2 | `T1-2-anomalous-whoami-parent.kql` | Medium | `whoami.exe` spawned from a process other than the usual shells. Huntress saw an anomalous case where `M365Copilot.exe` was the parent, which nobody has fully explained. |

T1-1 is the single highest-signal "intrusion in progress" detection in this pack. Legitimate users rarely run all three commands within 30 minutes. SCCM, MSP tools, and AD admins are the main false-positive sources. Add their parent processes to an exclusion list after baselining.

### Tier 2 — Vulnerability primitives

| Rule ID | File | Severity | What it catches |
|---|---|---|---|
| T2-2 | `T2-2-ntfs-junction-user-temp.kql` | High | `mklink /j` or `mklink /d` invocations creating junctions inside user-writable temp paths. The core TOCTOU primitive both BlueHammer and RedSun rely on. |
| T2-5 | `T2-5-vss-enumeration-non-backup.kql` | High | Processes enumerating `\Device\HarddiskVolumeShadowCopy*` objects from a non-backup, non-system context. Cyderes recommended this as a high-confidence reconnaissance signal. |

T2-2 is durable. It catches the technique, not the PoC. A modified variant that renames everything and ships a new SHA-256 still has to create a junction to do its job, and this rule still fires. Tune exclusions for legitimate junction creators in your environment (installers, build tools, some imaging utilities).

### Tier 3 — Staging IoCs

| Rule ID | File | Severity | What it catches |
|---|---|---|---|
| T3-7 | `T3-7-suspicious-binary-names.kql` | Critical | Known Nightmare-Eclipse binary names (`FunnyApp.exe`, `RedSun.exe`, `UnDefend.exe`, `undef.exe`, `z.exe`) in user-writable paths. |
| T3-8 | `T3-8-two-letter-downloads-subfolder.kql` | Medium | Executables created in 2-character subfolders directly under `Downloads\`, like `Downloads\ks\RedSun.exe`. Specific staging pattern Huntress observed in the live intrusion. |

These catch unmodified PoCs and the specific in-the-wild TTP. Easy for an attacker to bypass by renaming, but the cost to them is real because they have to know to do it. Keep them on.

### Tier 4 — Post-exploitation

| Rule ID | File | Severity | What it catches |
|---|---|---|---|
| T4-1 | `T4-1-beigeburrow-tunneling-agent.kql` | Critical | The `agent.exe -server staybud.dpdns.org:443 -hide` BeigeBurrow tunneling tool. The only component Huntress observed successfully connecting outbound during the live intrusion. |
| T4-2 | `T4-2-fortigate-known-bad-source-ip.kql` | Critical | Sentinel-only. FortiGate SSL VPN logons from the specific source IPs Huntress observed: `78.29.48.29` (Russia), `212.232.23.69` (Singapore), `179.43.140.214` (Switzerland). |

T4-1 is high-value because BeigeBurrow is actual operator tradecraft, not PoC code. It's a Go binary that uses HashiCorp's Yamux library to multiplex over TCP/443. The port-protocol pair looks normal to a firewall. The persistence pattern is what gives it away.

About T4-2: those IPs are weeks old at this point. Verify against your current threat intel feed before deploying. The infrastructure has very likely rotated.

### Kill-chain correlation

| Rule ID | File | Severity | What it catches |
|---|---|---|---|
| COMBO-1 | `COMBO-1-full-kill-chain.kql` | Critical | Enumeration triad (T1-1 hit) → suspicious binary drop (T3-7 / T3-8 pattern) → Defender alert (T0-1 hit), all on the same device within 4 hours. |
| COMBO-2 | `COMBO-2-redsun-undefend-chained.kql` | Critical | RedSun arbitrary-write primitive (RS-T2-1) AND UnDefend signature database access (UD-T2-3) on the same device. The documented chained attack. |

COMBO-1 is the highest-confidence "we are being actively intruded right now" alert in the pack. It correlates evidence of operator behavior, evidence of payload staging, and evidence of Defender flagging the payload. When it fires, you have three independent signals pointing at the same box. False positive rate is effectively zero.

COMBO-2 captures the explicit chain the researcher documented: use RedSun for SYSTEM, then use UnDefend to blind Defender to whatever happens next.

Both COMBO rules should auto-isolate. Don't wait for a human to validate. Isolate first, validate second.

## What to actually do

Phase 1, deploy these three:

1. T0-1 (Defender signatures)
2. T1-1 (hands-on-keyboard triad)
3. T4-1 (BeigeBurrow)

That's ~70% of the realistic detection surface for this attack family and the false-positive rate is effectively zero against legitimate workflows.

Phase 2, add T2-2 and T2-5. These catch the underlying technique rather than specific IoCs, so they keep working against modified PoC variants. Deploy with longer frequencies (3-6h) and lower severity to start, then escalate after baselining.

Phase 3, add the Tier 3 rules. Treat them as tripwires for unmodified samples. High signal when they fire, but don't lean on them as primary coverage.

Phase 4, add COMBO-1 and COMBO-2 with auto-isolate.
