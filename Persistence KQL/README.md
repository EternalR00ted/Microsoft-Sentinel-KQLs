# Persistence detections for Defender XDR

KQL for the persistence mechanisms on the FOR508 slide: autostart locations, service creation and replacement, service failure recovery, scheduled tasks, DLL hijacking, WMI event consumers, local Group Policy, Office add-ins and BIOS/boot.

The folder has 37 files.

- **27 detection rules.** Each one queries a single table and only uses operators and functions on Microsoft's Continuous (NRT) list. None of them has comments, because one comment line blocks NRT.
- **10 hunts.** Their names end in "(hunt)". Run them by hand in Advanced Hunting. They use joins, `summarize` or `let`, so they can't be rules.

## Before you turn anything on

1. **Run `0 Check your telemetry first (hunt).kql`.** It counts the last 7 days of events for every registry area, event type and folder these rules depend on. Microsoft doesn't publish which registry writes MDE records. If an area shows zero events, the rule for it can't fire in your tenant.
2. **Baseline every rule over 30 days in Advanced Hunting.** A new rule checks the past 30 days the moment you save it, and one run can raise up to 150 alerts. Tune anything that returns more than a few rows before you save it.
3. **Add exclusions as extra `| where` lines.** Match the writer's full folder path plus the key or folder it wrote to. Don't exclude on a file name alone. An attacker only has to rename a tool to get past that. The built-in exclusions follow the same rule: a Windows process like TiWorker.exe, svchost.exe or services.exe is only trusted when it runs from its real folder and as SYSTEM (S-1-5-18). A user-level attacker can copy a tool to a writable folder like `C:\Windows\Tasks` and give it the same name, but they can't make it run as SYSTEM.
4. **Run the VM test at the bottom of this file.** It shows which of these events your tenant actually records.

## Turning a query into a rule

- **Name and alert title:** use your format, for example `<Company> - MDE - Run key points to a script or temp folder`. The file names are written to work as alert titles.
- **Frequency:** Continuous (NRT). If the portal won't offer NRT for a rule, use Every hour (4-hour lookback).
- **Description:** use dynamic fields so the analyst sees why it fired. Every rule outputs a `Reason` column, so `{{Reason}} on {{DeviceName}}` works for all 27. The portal allows 3 columns per field. Keep the title static so your naming format holds.
- **Impacted assets:** Device is `DeviceId`. For users, map `InitiatingProcessAccountSid` on registry, file and DeviceEvents rules. On process rules, map `AccountSid`.
- **Custom details:** add the Reason column, the key or file path, and the writer's command line. The limit is 20 pairs and 4 KB per alert.
- **Actions:** none to start. Once a rule has run clean for a month, add Collect investigation package.
- **Duplicates:** Defender merges repeat hits that have the same entities and the same custom and dynamic details into one alert.

## Telemetry limits you should know about

- **Registry coverage isn't published.** The telemetry check and the VM test are the only way to see what your tenant records.
- **Deletes use different columns.** For `RegistryValueDeleted` and `RegistryKeyDeleted`, MDE puts the key and value name in `PreviousRegistryKey` and `PreviousRegistryValueName`. Microsoft's own ASIM parser maps them that way. The rules that watch deletes read both sets of columns. The telemetry check has a `Deletes` column, so you can see whether your tenant records deletes for each area at all. In 2022 a researcher deleted a task's SD value as SYSTEM and MDE didn't record it. If the telemetry check shows zero TaskCache deletes, the hidden-task branches can't fire.
- **MDE caps events on the device.** In 2022 FalconForce found many event types have a local cap of 1 event per 24 hours for each unique set of field values. The same persistence write repeated on the same device within a day may not show up twice.
- **Image loads are sampled.** FalconForce calls `DeviceImageLoadEvents` "very unreliable". That's why the DLL hijacking rules watch file writes. The image-load hunt is a bonus. An empty result there doesn't mean nothing loaded.
- **Aggregated reporting.** If you turn it on (Settings > Endpoints > Advanced features), some file and process events arrive as hourly summaries with ActionTypes like `FileCreatedAggregatedReport`. The file rules match on `startswith "FileCreated"`, so they catch both kinds. Microsoft says it can take up to 7 days to start.
- **Custom data collection.** It went GA in May 2026. It needs a Sentinel workspace and dynamic device tags, and it caps at 75,000 events per rule per device per 24 hours. Microsoft's doc lists 5 tables: process, image load, file, network and script. Registry isn't on that list, even though Azure Monitor already documents a `DeviceCustomRegistryEvents` table. It's the fix for the image-load gap on high-value machines.
- **Firmware.** An SPI flash write never shows up in OS telemetry. The 7c rules catch the tools and drivers used to do it, plus the protections attackers turn off first. Your real controls are Secure Boot, memory integrity (HVCI), the vulnerable driver blocklist and the UEFI scanner alerts MDE already raises. `Firmware and boot alerts by device (hunt).kql` pulls those alerts up per device.

## ATT&CK v20 notes

The IDs below come from the ATT&CK v20 STIX bundle (Enterprise, modified October 13, 2026). Changes that matter when you fill in the MITRE fields:

- Defense Evasion is no longer one tactic. It's split into Stealth (TA0005) and Defense Impairment (TA0112).
- T1574.001 is now just "DLL". Its description covers search order hijacking, side-loading and phantom DLLs. It sits under Stealth and Execution.
- T1574.002 DLL Side-Loading is revoked. Use T1574.001.
- T1562.001 Disable or Modify Tools is revoked. Use T1685, under Defense Impairment.
- T1574.011 Services Registry Permissions Weakness sits under Stealth and Execution. ATT&CK's text for it names the `FailureCommand` value.
- T1053.005 Scheduled Task describes hiding a task by deleting its SD value or changing its Index value (Tarrask).

If the portal's MITRE picker still shows older names, pick the closest match.

## Files

Severity is a suggestion. "Rule" files are NRT-ready. "Hunt" files are manual.

### 0 Telemetry check

| File | Type | Notes |
|---|---|---|
| 0 Check your telemetry first (hunt) | Hunt | Run this first. Zero rows for an area means the matching rule can't fire. |

### 1 AutoStart Locations

| File | Type | Table | ATT&CK | Severity | What to expect |
|---|---|---|---|---|---|
| Run key points to a script or temp folder | Rule | DeviceRegistryEvents | T1547.001 | Medium | Fires on Run, RunOnce, RunOnceEx and policy Run values that start a script host or proxy binary, point at temp, Public, Downloads or the ProgramData root, or contain a URL. Edge and OneDrive cleanup commands are already excluded. Expect a few vendor agents that start through PowerShell. |
| Winlogon Userinit or Shell changed | Rule | DeviceRegistryEvents | T1547.004 | High | Any non-default Userinit, Shell, Taskman, AppSetup or VmApplet value. Kiosk or shell-replacement builds will fire. Exclude those by device group. |
| File dropped in a Startup folder | Rule | DeviceFileEvents | T1547.001 | Medium | Any program or script in a Startup folder. Shortcuts only fire when a script host, Office, a browser, or a program running from AppData, temp, Public or Downloads wrote them. Per-user apps that install into AppData and add a Startup shortcut will fire. |
| Debugger or exit monitor attached to a program | Rule | DeviceRegistryEvents | T1546.012, T1546.008 | High | IFEO Debugger, GlobalFlag and VerifierDlls, plus SilentProcessExit MonitorProcess. GlobalFlag also fires when a developer uses gflags or page heap. |
| Rarely used autostart point changed | Rule | DeviceRegistryEvents | T1546.010, T1546.009, T1547.002, T1547.005, T1556.002, T1546.007, T1547.010, T1547.012, T1547.003, T1547.001, T1547.004, T1547.014, T1556.008, T1574.001, T1546 | Medium | 23 autostart points, from AppInit DLLs and LSA packages to Group Policy client-side extensions, network provider DLLs, the Safe Mode shell and the RDP initial program. Printer driver installs can write print monitor and processor values through spoolsv.exe. VPN and Citrix installs change the network provider order. Windows servicing is excluded. msiexec isn't, because a malicious MSI can write any of these. A fleet-wide MSI that registers an LSA package, print monitor or network provider will raise one alert per device, so suppress the rule during that rollout. |
| Run key values seen on few devices (hunt) | Hunt | DeviceRegistryEvents | T1547.001 | | Run values found on 3 or fewer devices in 30 days, with user folders, SIDs, GUIDs and version numbers normalized out. |

### 2 Service Creation and Replacement

| File | Type | Table | ATT&CK | Severity | What to expect |
|---|---|---|---|---|---|
| New service runs a shell or user folder binary | Rule | DeviceEvents (ServiceInstalled) | T1543.003, T1569.002 | High | Shells and script hosts, user-writable folders, local admin share paths (Impacket smbexec style), PsExec, PAExec, RemCom and CSExec service names, and binaries in the root of `C:\Windows` (Impacket psexec's default). On this event FolderPath holds only the folder, so the rule joins it with FileName. If your admins use PsExec, exclude by admin account. |
| Service binary path or DLL changed outside the service manager | Rule | DeviceRegistryEvents | T1574.011, T1543.003 | High | ImagePath or ServiceDll written by anything other than the service manager, or pointed at a shell or user folder by anything. Servicing, driver store updates, Defender platform updates, PrintNotify print driver updates and NTDS on domain controllers are excluded. Each one has to come from its real folder and run as SYSTEM. Writing the same value again doesn't fire. |
| Service settings changed from the command line | Rule | DeviceProcessEvents | T1543.003, T1574.011 | Medium | sc.exe, reg.exe and PowerShell changing binary paths, ServiceDll or recovery commands. Admin scripts will fire. |
| Service binary overwritten by an unexpected process (hunt) | Hunt | DeviceProcessEvents, DeviceFileEvents | T1574.010 | | Joins service binaries seen started by services.exe to later writes of the same file. |
| Services installed on few devices (hunt) | Hunt | DeviceEvents | T1543.003 | | Service installs found on 3 or fewer devices in 30 days. |

### 3 Service Failure Recovery

| File | Type | Table | ATT&CK | Severity | What to expect |
|---|---|---|---|---|---|
| Service recovery set to run a program | Rule | DeviceRegistryEvents | T1574.011 | High | Any FailureCommand value. Rare in practice. A few vendor agents set one. Exclude by service name plus value. |
| Service manager started a shell or script host | Rule | DeviceProcessEvents | T1569.002, T1543.003 | High | services.exe starting cmd, PowerShell, wscript, mshta, rundll32 and similar, including renamed copies. This is what a recovery command looks like when it runs. |

### 4 Scheduled Tasks

| File | Type | Table | ATT&CK | Severity | What to expect |
|---|---|---|---|---|---|
| Scheduled task runs a script host or user folder program | Rule | DeviceEvents (ScheduledTaskCreated, ScheduledTaskUpdated) | T1053.005 | Medium | Probably your noisiest rule. It only looks at the task's actions, so a URL in a description won't fire it. Expect vendor tasks that run cmd or PowerShell, per-user updaters in AppData, and built-in `\Microsoft\Windows\` tasks that run rundll32 when something other than Windows servicing re-registers them. Exclude by exact task name plus command. The OneDrive exclusion only applies when the task's command is the OneDrive executable itself. |
| Scheduled task hidden or created through the registry | Rule | DeviceRegistryEvents | T1053.005 | High | TaskCache writes by anything other than Task Scheduler and known Windows writers. The writer list comes from SigmaHQ's real-world false positives. Deleting an SD or Index value is never excluded. See the delete note under telemetry limits: test this one before you trust it. |
| Scheduled task commands seen on few devices (hunt) | Hunt | DeviceEvents | T1053.005 | | Task commands found on 3 or fewer devices in 30 days. |

### 5 DLL Hijacking

| File | Type | Table | ATT&CK | Severity | What to expect |
|---|---|---|---|---|---|
| Windows DLL name dropped outside Windows folders | Rule | DeviceFileEvents | T1574.001 | Medium | 49 DLL names from HijackLibs that attackers side-load, written outside the Windows, upgrade and Defender folders. The 12 user-writable folders inside System32 and SysWOW64 (like `spool\drivers\color`) still fire. Upgrade folders like `C:\$WINDOWS.~BT` are only trusted when SYSTEM writes to them, because any user can create that folder. A few apps ship their own copy of one of these DLLs. Exclude by folder. |
| Phantom DLL planted | Rule | DeviceFileEvents | T1574.001 | High | 10 DLLs that Windows tries to load but doesn't ship, plus oci.dll in the Windows folder and the DLL per-user OneDrive tries to load from its own folder. |
| Windows program run from a user folder (hunt) | Hunt | DeviceProcessEvents | T1574.001 | | Signed Windows binaries copied into user folders, the usual first step of side-loading. |
| Windows DLL loaded from an unusual folder (hunt) | Hunt | DeviceImageLoadEvents | T1574.001 | | Sampled data. Treat hits as leads. Treat empty results as nothing. |

### 6 WMI Event Consumers

| File | Type | Table | ATT&CK | Severity | What to expect |
|---|---|---|---|---|---|
| WMI subscription runs a command or script | Rule | DeviceEvents (WmiBindEventFilterToConsumer) | T1546.003 | High | Only CommandLine and ActiveScript consumers. The built-in SCM Event Log consumer doesn't fire. Some older management agents use these consumers. Exclude by consumer name. |
| WMI script consumer host started | Rule | DeviceProcessEvents | T1546.003 | High | scrcons.exe starting, or anything it starts. It almost never runs. |
| WMI subscription created from the command line | Rule | DeviceProcessEvents | T1546.003 | Medium | Needs a create or set verb next to a subscription class, so read-only enumeration by IR tools doesn't fire. Also fires on mofcomp compiling a file from a user-writable folder, whatever the file extension. |

### 7a Local Group Policy and Logon Scripts

| File | Type | Table | ATT&CK | Severity | What to expect |
|---|---|---|---|---|---|
| Local Group Policy script added | Rule | DeviceFileEvents | T1037 | High | scripts.ini, psscripts.ini or any file in the local GPO Startup, Shutdown, Logon or Logoff script folders. The domain GPO cache (DataStore) is excluded. |
| Group Policy script ran from a local path | Rule | DeviceProcessEvents | T1037 | High | gpscript.exe starting anything that doesn't run from a SYSVOL or NETLOGON share. Domain scripts don't fire. Local scripts and other UNC paths, like `\\127.0.0.1\C$`, do. |
| Logon script set in the user Environment key | Rule | DeviceRegistryEvents | T1037.001 | High | Any UserInitMprLogonScript value. |

Group Policy client-side extension DLLs (`Winlogon\GPExtensions`) are covered in "Rarely used autostart point changed".

### 7b Office Add-ins and Outlook

| File | Type | Table | ATT&CK | Severity | What to expect |
|---|---|---|---|---|---|
| Office Test key or add-in autoload set | Rule | DeviceRegistryEvents | T1137.002, T1137.006 | High | The Office Test key, plus Excel OPEN values and PowerPoint add-in paths that point anywhere other than `C:\Program Files`. Per-user add-ins installed into AppData by legitimate vendors will fire. Exclude by path. |
| Outlook macro or home page persistence | Rule | DeviceRegistryEvents | T1137, T1137.004 | High | LoadMacroProviderOnBoot on, macro security at "no warning", a folder home page URL set, or home pages switched back on. |
| File dropped in an Office startup folder | Rule | DeviceFileEvents | T1137.001, T1137.006 | Medium | Word STARTUP and Excel XLSTART (per user and under Program Files), add-ins in the AddIns folder, VbaProject.OTM written by anything but Outlook, and Normal.dotm written by anything but Word or Outlook. Excel saving PERSONAL.XLSB, its default templates and its temp save files is excluded, so a macro that overwrites PERSONAL.XLSB from inside Excel won't fire. Office Click-to-Run updates are excluded. Some legitimate add-ins install templates in Word STARTUP. |
| Office add-ins seen on few devices (hunt) | Hunt | DeviceRegistryEvents | T1137.006 | | COM add-in registrations found on 3 or fewer devices in 30 days. |

### 7c BIOS Firmware and Boot

| File | Type | Table | ATT&CK | Severity | What to expect |
|---|---|---|---|---|---|
| Firmware flash or SPI access tool run | Rule | DeviceProcessEvents | T1542.001 | High | AMI AFU, Intel FPT, Insyde H2OFFT, Phoenix WinPhlash, ASUS WinFlash, RWEverything, flashrom and CHIPSEC, including renamed copies where the binary keeps its original name. OEM BIOS update packages sometimes wrap these. Check the parent process before you escalate. |
| Firmware access driver loaded | Rule | DeviceEvents (DriverLoad) | T1542.001, T1068 | High | Drivers that give user mode raw access to firmware or physical memory: 28 file names plus 91 SHA1 hashes from LOLDrivers and CHIPSEC, so renamed copies still match. A BIOS update can load one legitimately. |
| Boot settings changed or EFI partition mounted | Rule | DeviceProcessEvents | T1553.006, T1490, T1685, T1542.003 | High | bcdedit turning on test signing or turning off integrity checks, the hypervisor or recovery, a changed boot manager path, and mountvol mounting the EFI system partition. Some imaging and repair scripts mount the EFI partition. Exclude by parent. Boot settings changed through the BCD WMI provider never start bcdedit, so they don't fire. |
| Memory integrity or driver blocklist turned off | Rule | DeviceRegistryEvents | T1685, T1553.006 | High | HVCI, VBS or the vulnerable driver blocklist set to 0, locally or by policy. If you change these by Intune or GPO on purpose, expect one alert per device. |
| Firmware and boot alerts by device (hunt) | Hunt | AlertInfo, AlertEvidence | T1542.001, T1542.003 | | MDE's own UEFI, firmware and bootkit alerts, grouped by device. |
| BIOS versions rare for their model (hunt) | Hunt | DeviceTvmHardwareFirmware | T1542.001 | | BIOS versions that aren't the model's most common version and run on under 5% of that model or on 2 devices or fewer, so small models show up too. Mostly finds machines that missed an update. Now and then it finds something worse. |

## What this pack doesn't cover

- **COM hijacking.** HKCU CLSID InprocServer32 overrides and scheduled tasks with ComHandler actions.
- **BITS jobs** (T1197).
- **Accessibility binary swaps.** Replacing sethc.exe or utilman.exe on disk isn't covered. The IFEO Debugger version is.
- **Tasks dropped as XML** straight into `C:\Windows\System32\Tasks` without going through Task Scheduler.
- **Outlook rules and custom forms** (T1137.005, T1137.003). They live in the mailbox, where MDE can't see them. Use Exchange Online and Defender for Office 365 audit data.
- **Domain GPO changes in SYSVOL** (T1484.001). Use Defender for Identity or AD auditing.
- **mofcomp run with a relative path.** The command line doesn't show the folder, so the rule can't judge it.
- **Boot settings changed through WMI.** The BCD WMI provider can turn on test signing without running bcdedit.
- **Smaller autostart points:** screensaver, protocol handlers, codecs, font drivers, Explorer shell extensions and browser extensions.
- **SPI flash writes** and any registry writes MDE doesn't record (see the telemetry section).

## How I checked these

- **Lint.** A linter I wrote checks syntax, column names against Microsoft Learn's schema pages, RE2 regex rules, and Microsoft's NRT operator and function list. All 37 files pass. The 27 rules use 8 functions in total, all on Microsoft's list.
- **Synthetic events.** An evaluator I wrote ran 287 test events through the 27 rules. All pass. I deleted each of the 102 `case()` branches one at a time, and every deletion broke at least one test. I also planted 124 bugs. The tests caught 122. The 2 misses were harmless: one widens a prefilter that later lines re-check, and one changes a word inside a label.
- **Real-world noise.** I compared the exclusions to SigmaHQ's false-positive filters for the same keys and tightened several rules from them.
- **Independent review.** A second reviewer read every file cold and found real bugs. Two branches could never fire, because MDE puts deleted registry keys in the `Previous*` columns. The Program Files branch in the Office startup rule was dead. Several exclusions trusted a process name with a weak folder check. The OneDrive exclusion could be spoofed. Any `\\` in a command line got past the GPO script rule. Renamed firmware drivers slipped past a name-only match. I checked each finding against Microsoft's parser, SigmaHQ, HijackLibs and LOLDrivers, fixed all of them, and added 36 tests built from them.
- **What I couldn't do.** I couldn't run Microsoft's own KQL parser, because my sandbox blocked running code downloaded from GitHub. I also had no real MDE data. Your first run in Advanced Hunting is the real test.

## Test on a VM

Use a test VM that's onboarded to MDE. Run the block below in an **elevated Windows PowerShell 5.1 console** (powershell.exe, not ISE and not PowerShell 7). It takes about 3 to 4 minutes. Every test cleans up after itself. Values that already exist on the machine are left alone and that test is skipped.

Before you run it:

- Tell your SOC. MDE's built-in detections may raise their own alerts for some of these, such as the WMI subscription and the IFEO debugger.
- If the ASR rule "Block persistence through WMI event subscription" is in block mode, the WMI test will fail. That's the ASR rule working.
- The script doesn't touch boot settings, HVCI, drivers or TaskCache. Those need SYSTEM or a reboot to test safely.
- I couldn't run this script here because my sandbox has no Windows. I checked it by reading it line by line, and I ran the events it should produce through the rules with the evaluator. All 25 fire.

```powershell
& {
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this in an elevated Windows PowerShell window on a test VM.' }
if ($PSVersionTable.PSVersion.Major -ne 5) { throw 'Run this in Windows PowerShell 5.1 (powershell.exe), not PowerShell 7.' }
$wait = 10
$state = @{}
$results = New-Object System.Collections.Generic.List[string]
$work = Join-Path $env:TEMP 'KqlTest'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$startupBat = Join-Path ([Environment]::GetFolderPath('Startup')) 'KqlTest.bat'
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\kqltest.exe'
$cmdProc = 'HKCU:\Software\Microsoft\Command Processor'
$gpStartup = Join-Path $env:SystemRoot 'System32\GroupPolicy\Machine\Scripts\Startup'
$officeTest = 'HKCU:\Software\Microsoft\Office test'
$outlook = 'HKCU:\Software\Microsoft\Office\16.0\Outlook'
$wordStartup = Join-Path $env:APPDATA 'Microsoft\Word\STARTUP'
$wmiScript = @'
$f = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name='KqlTestFilter'; EventNameSpace='root\cimv2'; QueryLanguage='WQL'; Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA ''Win32_LocalTime'' AND TargetInstance.Hour = 23 AND TargetInstance.Minute = 59'}; $c = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{Name='KqlTestConsumer'; CommandLineTemplate='cmd.exe /c echo kqltest'}; Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$f; Consumer=$c} | Out-Null
'@

function Invoke-Exe([string]$File, [string[]]$Arguments) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $File @Arguments 2>&1 | Out-Null; return $LASTEXITCODE } finally { $ErrorActionPreference = $previous }
}
function New-TrackedPath([string]$Path, [string]$ItemType) {
    $missing = @()
    $p = $Path
    while (-not (Test-Path -LiteralPath $p)) { $missing += $p; $p = Split-Path -Path $p -Parent }
    for ($i = $missing.Count - 1; $i -ge 0; $i--) {
        if ($ItemType) { New-Item -ItemType $ItemType -Path $missing[$i] | Out-Null } else { New-Item -Path $missing[$i] | Out-Null }
    }
    return ,$missing
}
function Remove-TrackedPath([string[]]$Paths) {
    foreach ($d in $Paths) {
        if ((Test-Path -LiteralPath $d) -and -not (Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue)) { Remove-Item -LiteralPath $d -Force }
    }
}
function Invoke-KqlTest([string]$TestName, [scriptblock]$DoBlock, [scriptblock]$UndoBlock) {
    Write-Host "Running: $TestName"
    try { & $DoBlock; Start-Sleep -Seconds $wait; $results.Add("OK       $TestName") }
    catch { $results.Add("NOT RUN  $TestName ($($_.Exception.Message))") }
    finally { try { & $UndoBlock } catch { $results.Add("CHECK    $TestName cleanup ($($_.Exception.Message))") } }
}

New-Item -ItemType Directory -Path $work -Force | Out-Null

Invoke-KqlTest 'Run key that starts PowerShell' {
    New-ItemProperty -Path $runKey -Name 'KqlTest' -Value 'powershell.exe -NoProfile -WindowStyle Hidden -Command "exit"' -PropertyType String -Force | Out-Null
} {
    Remove-ItemProperty -Path $runKey -Name 'KqlTest' -ErrorAction SilentlyContinue
}

Invoke-KqlTest 'Winlogon Taskman value' {
    if ($null -ne (Get-ItemProperty -Path $winlogon -Name 'Taskman' -ErrorAction SilentlyContinue)) { throw 'Taskman is already set on this machine' }
    New-ItemProperty -Path $winlogon -Name 'Taskman' -Value (Join-Path $env:SystemRoot 'System32\Taskmgr.exe') -PropertyType String -Force | Out-Null
    $state.Taskman = $true
} {
    if ($state.Taskman) { Remove-ItemProperty -Path $winlogon -Name 'Taskman' }
}

Invoke-KqlTest 'Batch file in the Startup folder' {
    Set-Content -LiteralPath $startupBat -Value 'exit' -Encoding Ascii
} {
    Remove-Item -LiteralPath $startupBat -Force -ErrorAction SilentlyContinue
}

Invoke-KqlTest 'IFEO debugger on a program that does not exist' {
    if (Test-Path -LiteralPath $ifeo) { throw 'The kqltest.exe IFEO key already exists' }
    New-Item -Path $ifeo | Out-Null
    $state.Ifeo = $true
    New-ItemProperty -Path $ifeo -Name 'Debugger' -Value (Join-Path $env:SystemRoot 'System32\cmd.exe') -PropertyType String -Force | Out-Null
} {
    if ($state.Ifeo) { Remove-Item -LiteralPath $ifeo -Recurse -Force }
}

Invoke-KqlTest 'cmd.exe AutoRun value' {
    $state.CmdProcKeys = New-TrackedPath $cmdProc ''
    if ($null -ne (Get-ItemProperty -Path $cmdProc -Name 'AutoRun' -ErrorAction SilentlyContinue)) { throw 'AutoRun is already set on this machine' }
    New-ItemProperty -Path $cmdProc -Name 'AutoRun' -Value 'rem kqltest' -PropertyType String -Force | Out-Null
    $state.AutoRun = $true
} {
    if ($state.AutoRun) { Remove-ItemProperty -Path $cmdProc -Name 'AutoRun' }
    Remove-TrackedPath $state.CmdProcKeys
}

Invoke-KqlTest 'Service that runs cmd.exe, with a recovery command and a direct ImagePath write' {
    $code = Invoke-Exe 'sc.exe' @('create', 'KqlTestSvc', 'binPath=', 'cmd.exe /c echo kqltest', 'start=', 'demand')
    if ($code -ne 0) { throw "sc.exe create failed with exit code $code" }
    $state.Service = $true
    Invoke-Exe 'sc.exe' @('failure', 'KqlTestSvc', 'reset=', '0', 'actions=', 'run/60000', 'command=', 'cmd.exe /c echo kqltest') | Out-Null
    Invoke-Exe 'reg.exe' @('add', 'HKLM\SYSTEM\CurrentControlSet\Services\KqlTestSvc', '/v', 'ImagePath', '/t', 'REG_EXPAND_SZ', '/d', 'cmd.exe /c echo kqltest2', '/f') | Out-Null
    Invoke-Exe 'sc.exe' @('start', 'KqlTestSvc') | Out-Null
} {
    if ($state.Service) { Invoke-Exe 'sc.exe' @('stop', 'KqlTestSvc') | Out-Null; Invoke-Exe 'sc.exe' @('delete', 'KqlTestSvc') | Out-Null }
}

Invoke-KqlTest 'Scheduled task that runs PowerShell' {
    $code = Invoke-Exe 'schtasks.exe' @('/Create', '/TN', 'KqlTest', '/TR', 'powershell.exe -NoProfile -Command exit', '/SC', 'ONCE', '/ST', '23:59', '/F')
    if ($code -ne 0) { throw "schtasks.exe /Create failed with exit code $code" }
    $state.Task = $true
} {
    if ($state.Task) { Invoke-Exe 'schtasks.exe' @('/Delete', '/TN', 'KqlTest', '/F') | Out-Null }
}

Invoke-KqlTest 'Windows DLL names copied to a temp folder' {
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\version.dll') -Destination (Join-Path $work 'version.dll') -Force
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\version.dll') -Destination (Join-Path $work 'wlbsctrl.dll') -Force
} {
    Remove-Item -LiteralPath (Join-Path $work 'version.dll'), (Join-Path $work 'wlbsctrl.dll') -Force -ErrorAction SilentlyContinue
}

Invoke-KqlTest 'WMI subscription that runs cmd.exe, created from a child PowerShell' {
    $code = Invoke-Exe 'powershell.exe' @('-NoProfile', '-Command', $wmiScript)
    if ($code -ne 0) { throw "creating the subscription failed with exit code $code (an ASR rule may have blocked it)" }
} {
    Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like '*KqlTestFilter*' } | Remove-WmiObject
    Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='KqlTestConsumer'" | Remove-WmiObject
    Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='KqlTestFilter'" | Remove-WmiObject
}

Invoke-KqlTest 'File in the local Group Policy Startup scripts folder' {
    $state.GpDirs = New-TrackedPath $gpStartup 'Directory'
    Set-Content -LiteralPath (Join-Path $gpStartup 'KqlTest.txt') -Value 'kqltest' -Encoding Ascii
} {
    Remove-Item -LiteralPath (Join-Path $gpStartup 'KqlTest.txt') -Force -ErrorAction SilentlyContinue
    Remove-TrackedPath $state.GpDirs
}

Invoke-KqlTest 'Logon script in the user Environment key' {
    if ($null -ne (Get-ItemProperty -Path 'HKCU:\Environment' -Name 'UserInitMprLogonScript' -ErrorAction SilentlyContinue)) { throw 'UserInitMprLogonScript is already set on this machine' }
    New-ItemProperty -Path 'HKCU:\Environment' -Name 'UserInitMprLogonScript' -Value 'cmd.exe /c rem kqltest' -PropertyType String -Force | Out-Null
    $state.Mpr = $true
} {
    if ($state.Mpr) { Remove-ItemProperty -Path 'HKCU:\Environment' -Name 'UserInitMprLogonScript' }
}

Invoke-KqlTest 'Office Test key' {
    if (Test-Path -LiteralPath $officeTest) { throw 'The Office test key already exists on this machine' }
    $state.OfficeTestKeys = New-TrackedPath "$officeTest\Special\Perf" ''
    Set-ItemProperty -Path "$officeTest\Special\Perf" -Name '(default)' -Value (Join-Path $env:SystemRoot 'System32\kqltest.dll')
} {
    if ($state.OfficeTestKeys) { Remove-Item -LiteralPath $officeTest -Recurse -Force }
}

Invoke-KqlTest 'Outlook VBA project set to load at startup' {
    $state.OutlookKeys = New-TrackedPath $outlook ''
    if ($null -ne (Get-ItemProperty -Path $outlook -Name 'LoadMacroProviderOnBoot' -ErrorAction SilentlyContinue)) { throw 'LoadMacroProviderOnBoot is already set on this machine' }
    New-ItemProperty -Path $outlook -Name 'LoadMacroProviderOnBoot' -Value 1 -PropertyType DWord -Force | Out-Null
    $state.Lmp = $true
} {
    if ($state.Lmp) { Remove-ItemProperty -Path $outlook -Name 'LoadMacroProviderOnBoot' }
    Remove-TrackedPath $state.OutlookKeys
}

Invoke-KqlTest 'File in the Word STARTUP folder' {
    $state.WordDirs = New-TrackedPath $wordStartup 'Directory'
    Set-Content -LiteralPath (Join-Path $wordStartup 'KqlTest.txt') -Value 'kqltest' -Encoding Ascii
} {
    Remove-Item -LiteralPath (Join-Path $wordStartup 'KqlTest.txt') -Force -ErrorAction SilentlyContinue
    Remove-TrackedPath $state.WordDirs
}

Invoke-KqlTest 'Program named like a firmware flash tool' {
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\whoami.exe') -Destination (Join-Path $work 'afuwinx64.exe') -Force
    Invoke-Exe (Join-Path $work 'afuwinx64.exe') @() | Out-Null
} {
    Remove-Item -LiteralPath (Join-Path $work 'afuwinx64.exe') -Force -ErrorAction SilentlyContinue
}

Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
Write-Host ''
$results | ForEach-Object { Write-Host $_ }
Write-Host ''
Write-Host 'Done. Wait 30 minutes, then run the check query from the README in Advanced Hunting.'
}
```

Wait 30 minutes, then run this in Advanced Hunting. Put the VM's name on the first line.

```kusto
let TestDevice = "PUT-THE-VM-NAME-HERE";
union withsource=SourceTable DeviceRegistryEvents, DeviceFileEvents, DeviceProcessEvents, DeviceEvents
| where Timestamp > ago(1d)
| where DeviceName startswith TestDevice
| where RegistryKey contains "kqltest" or RegistryValueName contains "kqltest" or RegistryValueData contains "kqltest"
    or RegistryKey contains @"\Office test\Special\Perf" or RegistryValueName in~ ("Taskman", "LoadMacroProviderOnBoot")
    or FileName contains "kqltest" or FolderPath contains @"\KqlTest\" or ProcessCommandLine contains "kqltest" or AdditionalFields contains "kqltest"
| project Timestamp, SourceTable, ActionType, FileName, FolderPath, ProcessCommandLine, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, AdditionalFields
| order by Timestamp asc
```

Then run each rule over the last day. This is what each test should trigger:

| Test | Rules it should fire |
|---|---|
| Run key that starts PowerShell | Run key points to a script or temp folder |
| Winlogon Taskman value | Winlogon Userinit or Shell changed |
| Batch file in the Startup folder | File dropped in a Startup folder |
| IFEO debugger | Debugger or exit monitor attached to a program |
| cmd.exe AutoRun value | Rarely used autostart point changed |
| Service test | New service runs a shell or user folder binary; Service settings changed from the command line; Service binary path or DLL changed outside the service manager; Service recovery set to run a program; Service manager started a shell or script host |
| Scheduled task | Scheduled task runs a script host or user folder program |
| DLL copies | Windows DLL name dropped outside Windows folders; Phantom DLL planted |
| WMI subscription | WMI subscription runs a command or script; WMI subscription created from the command line |
| Local GPO Startup folder file | Local Group Policy script added |
| UserInitMprLogonScript | Logon script set in the user Environment key |
| Office Test key | Office Test key or add-in autoload set |
| LoadMacroProviderOnBoot | Outlook macro or home page persistence |
| Word STARTUP file | File dropped in an Office startup folder |
| afuwinx64.exe | Firmware flash or SPI access tool run |

If the check query shows the raw event but the rule doesn't fire, the rule has a bug. Send me the row. If the check query shows nothing for a test, MDE didn't record that event in your tenant. No rule can catch it there.

## Sources

- Microsoft Learn: [Create custom detection rules](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules) (required columns, 150 alerts per run, NRT tables and limits, dynamic titles, custom details)
- Microsoft Learn: [Supported KQL features in Azure Monitor transformations](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-transformations-structure) (the NRT operator and function list)
- Microsoft Learn: [DeviceRegistryEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table) and the other advanced hunting schema pages
- Microsoft Learn: [Aggregated reporting](https://learn.microsoft.com/en-us/defender-endpoint/aggregated-reporting)
- Microsoft Learn: [Custom data collection](https://learn.microsoft.com/en-us/defender-endpoint/custom-data-collection) and [Create custom data collection rules](https://learn.microsoft.com/en-us/defender-endpoint/create-custom-data-collection-rules)
- Microsoft Learn: [Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules)
- Microsoft Tech Community: [DeviceRegistryEvents table](https://techcommunity.microsoft.com/discussions/microsoftthreatprotection/deviceregistryevents-table/4382673) (no public list of recorded registry writes)
- Microsoft: [ASIM registry parser for Defender data](https://github.com/Azure/Azure-Sentinel/blob/master/Parsers/ASimRegistryEvent/Parsers/ASimRegistryEventMicrosoft365D.yaml) (deletes come from `PreviousRegistryKey` and `PreviousRegistryValueName`)
- threathunt.blog: [Hunt for a hidden scheduled task](https://threathunt.blog/hunt-for-a-hidden-scheduled-task/) (MDE didn't record a SYSTEM-level SD deletion in 2022)
- [UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList) (user-writable folders inside System32 and SysWOW64)
- FalconForce: [MDE Internals 0x03, telemetry unreliability and log augmentation](https://medium.com/falconforce/microsoft-defender-for-endpoint-internals-0x03-mde-telemetry-unreliability-and-log-augmentation-ec6e7e5f406f)
- FalconForce: [MDE Internals 0x02, audit settings and telemetry](https://medium.com/falconforce/microsoft-defender-for-endpoint-internals-0x02-audit-settings-and-telemetry-1d0af3ebfb27)
- MITRE: [ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data) (Enterprise v20) and technique pages such as [T1053.005](https://attack.mitre.org/techniques/T1053/005/) and [T1574.001](https://attack.mitre.org/techniques/T1574/001/)
- SigmaHQ: [Sigma rules](https://github.com/SigmaHQ/sigma), especially the TaskCache, ASEP, ServiceDll and blocklist registry rules
- [HijackLibs](https://github.com/wietze/HijackLibs) (snapshot of October 28, 2026)
- [LOLDrivers](https://github.com/magicsword-io/LOLDrivers) (snapshot of October 27, 2026)
- [CHIPSEC](https://github.com/chipsec/chipsec)
- [Impacket](https://github.com/fortra/impacket) (smbexec and psexec service behaviour)
- Microsoft Security Blog: [Tarrask malware uses scheduled tasks for defense evasion](https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/)
