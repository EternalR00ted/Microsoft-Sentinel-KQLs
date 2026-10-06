# Find Devices Still Running the Microsoft Monitoring Agent (MMA)

Three read-only KQL queries for finding every device that still has the Microsoft Monitoring Agent, also called the legacy Log Analytics agent. Each one runs in a different place and answers a different question.

Dates and behavior in this README were checked against Microsoft's docs in October 2026.

## Why this matters now

MMA retired on August 31, 2024. Microsoft doesn't support it anymore.

Microsoft is also shutting down the cloud ingestion services MMA uploads to. After March 2, 2026, uploads from MMA can stop at any time with no notice.

That breaks the common way of finding it. The usual approach is to query the Heartbeat table in Log Analytics. A box whose uploads have stopped won't show up there, even with MMA still installed. So start with what Defender sees on the endpoint. Then use Heartbeat to see what's still getting through.

## The queries

Each query is its own `.kql` file in this repo.

| File | Run it in | What it tells you |
|---|---|---|
| `Devices with MMA installed.kql` | Defender portal, Advanced hunting | Which devices have MMA, and whether their Defender sensor depends on it |
| `Devices still reporting through MMA.kql` | Sentinel or Log Analytics | Which devices still send heartbeats through MMA, and whether AMA is on the box too |
| `Azure VMs and Arc servers with the MMA extension.kql` | Azure Resource Graph Explorer | Which Azure and Arc machines still have the MMA extension |

Start with `Devices with MMA installed.kql`. It covers every device onboarded to Defender, whether MMA is still uploading or not.

## Devices with MMA installed

File: `Devices with MMA installed.kql`

Run it in the Defender portal under Advanced hunting. Don't run it in Sentinel. The TVM tables aren't ingested into Sentinel, so the query runs there but comes back empty.

Look at `DefenderDependsOnMMA` first.

Before April 2022, onboarding Windows Server 2016 and 2012 R2 to Defender for Endpoint required MMA. On those servers the Defender sensor runs through MMA. You can spot them by sensor version. MMA-based sensors start with 10.3720. The unified agent starts with 10.8.

If `DefenderDependsOnMMA` is `true`, uninstalling MMA offboards that server. It stops sending sensor data to Defender. Move it to the unified agent first. Microsoft's migration script, `install.ps1` from microsoft/mdefordownlevelserver, handles the move. You run it with `-RemoveMMA` and your onboarding script. The migration doc under References has the exact syntax.

The query matches on `monitoring_agent`. That's the name Defender Vulnerability Management gives MMA. I got it from Alex Verboon's MMA end-of-life hunt.

If you run SCOM, check `MMAVersion` before you remove anything. See [Before you uninstall anything](#before-you-uninstall-anything).

## Devices still reporting through MMA

File: `Devices still reporting through MMA.kql`

Run it in Sentinel or Log Analytics. If your Sentinel workspace is onboarded to the Defender portal, it also runs in Advanced hunting.

The legacy agents report under the Heartbeat categories `Direct Agent`, `SCOM Agent` and `SCOM Management Server`. On Linux, `Direct Agent` is the old OMS agent, so Linux boxes show up too. AMA reports as `Azure Monitor Agent`.

The query groups by short hostname. That lines up the MMA and AMA rows for the same box, even if one agent reports an FQDN. `ReportedNames` keeps the raw names so you can spot two machines sharing a short name.

`MMA only` rows sort to the top. They're the priority. When MMA uploads stop, those boxes stop sending agent data to Sentinel.

It looks back 30 days by default. An empty result doesn't mean you're clean. It can mean MMA uploads already stopped. Set `Lookback` at the top of the file to your workspace retention to see when each box last got through. Any device from `Devices with MMA installed.kql` with no AMA heartbeat isn't sending agent data to Sentinel.

Microsoft also has a GUI view. The AMA Migration Helper workbook is in the Azure portal under Monitor > Workbooks, in the Azure Monitor essentials section. It can only see on-prem servers without Arc through workspace data, so it has the same blind spot.

## Azure VMs and Arc servers with the MMA extension

File: `Azure VMs and Arc servers with the MMA extension.kql`

Run it in Azure Resource Graph Explorer. Skip it if you don't have Azure VMs or Arc-enabled servers. Resource Graph only returns resources you can read, so set the scope to every subscription you care about.

The query matches on extension type. Extension names aren't reliable, and the same agent can show up as `MMAExtension`. The types are `MicrosoftMonitoringAgent` on Windows and `OmsAgentForLinux` on Linux.

This only sees MMA installed as an Azure extension. An on-prem server where someone ran the MSI won't show up. `Devices with MMA installed.kql` catches those if they're onboarded to Defender.

## Before you uninstall anything

Check `DefenderDependsOnMMA` in the results from `Devices with MMA installed.kql`. Pulling MMA off those servers takes them out of Defender.

If you run SCOM, slow down. The retirement doesn't apply to MMA connected only to an on-prem SCOM, and Microsoft says to keep the agent on machines SCOM manages. SCOM uses the same agent as MMA. Microsoft's System Center team says 10.20.x is the Log Analytics build. Other versions on your list may be SCOM agents.

Find whatever deploys MMA and stop it first. That might be an Intune Win32 app, a GPO startup script, a ConfigMgr package or an Azure Policy assignment. Skip this and the agent comes back.

## Credits

These queries build on other people's work. Thanks to:

| Who | What I used | Link |
|---|---|---|
| Alex Verboon | The `monitoring_agent` name for MMA, from his MMA end-of-life hunt. The 10.3720 vs 10.8 sensor version split, from his unified agent deployment status query. | [MDE MMA Update](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/MDE-MMA-Update.md), [MDE Unified Agent](https://github.com/alexverboon/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/MDE-Unified%20Agent.md) |
| Jeffrey Appel | His Defender for Endpoint health check post. It explains the 10.3720 vs 10.8 split and points readers to Alex's query. | [How to check for a healthy Defender for Endpoint environment?](https://jeffreyappel.nl/how-to-check-for-a-healthy-defender-for-endpoint-environment/) |
| Ugur Koc | KQL Search. It's how I found Alex's MMA query. | [kqlsearch.com](https://www.kqlsearch.com/) |
| Azure Landing Zones team at Microsoft | The Heartbeat query in their AMA migration guidance. It tags each machine's migration status from the agent categories it reports. `Devices still reporting through MMA.kql` uses the same idea. | [ALZ AMA Migration Guidance](https://github.com/Azure/Enterprise-Scale/wiki/ALZ-AMA-Migration-Guidance) |

## References

| Source | Used for |
|---|---|
| [Migrate from Log Analytics agent to Azure Monitor Agent](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-migration) | Retirement date, the March 2, 2026 ingestion shutdown, support status, the SCOM exception, stopping automated deployment |
| [Heartbeat table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/heartbeat) | Heartbeat columns and the legacy `Category` values |
| [Analyze logs with KQL: list active machines](https://learn.microsoft.com/en-us/training/modules/analyze-logs-with-kql/3-list-active-machines-not-sending-logs) | `Direct Agent` on Linux is the OMS agent |
| [DeviceTvmSoftwareInventory table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicetvmsoftwareinventory-table) | TVM data isn't ingested into Sentinel |
| [Onboard servers to Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/onboard-server) | Server 2016 and 2012 R2 onboarding required MMA before April 2022 |
| [Onboard previous versions of Windows](https://learn.microsoft.com/en-us/defender-endpoint/onboard-downlevel) | Uninstalling MMA offboards an endpoint that was onboarded through it |
| [Migrating servers from MMA to the unified solution](https://learn.microsoft.com/en-us/defender-endpoint/application-deployment-via-mecm) | `install.ps1` with `-RemoveMMA` |
| [microsoft/mdefordownlevelserver](https://github.com/microsoft/mdefordownlevelserver) | The migration script |
| [Overview of the Azure Connected Machine agent](https://learn.microsoft.com/en-us/azure/azure-arc/servers/agent-overview) | `MicrosoftMonitoringAgent` and `OmsAgentForLinux` extension types |
| [Microsoft Q&A: which monitoring agents do I need](https://learn.microsoft.com/en-us/answers/questions/1164261/which-monitoring-agents-to-i-really-need) | The MMA extension can be named `MMAExtension` |
| [AMA Migration Helper workbook](https://learn.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-migration-helper-workbook) | Where the workbook lives |
| [Agent recommendations for SCOM users](https://techcommunity.microsoft.com/blog/systemcenterblog/agent-recommendations-for-scom-users/3941707) | 10.20.x is the Log Analytics build, and SCOM agent support follows SCOM's lifecycle |
