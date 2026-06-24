# Defender Control
Open source Windows Defender disabler.
Tested on Windows 10 (20H2+) and Windows 11.

## ⚠️ Microsoft flags this tool (expected)
This project has been public for years, so Microsoft ships a dedicated signature for it
(`HackTool:Win32/DefenderControl`). Defender will quarantine `disable-defender.exe` on
sight, and the behavioural engine may stop it mid-run. This is a **category** detection —
*any* Defender-disabler trips it — not evidence the code is unsafe. It's open source;
review it or compile it yourself.

Because of this you must get Defender out of the way **before** running the tool (next
section). Turning off Real-time protection temporarily also stops Defender from eating the
`.exe` while you run it.

## Before you run (required)
Modern Windows protects Defender in **two layers**:

- **Layer 1 — Tamper Protection.** A kernel mini-filter that silently blocks writes to
  RTP / `Set-MpPreference`-style settings while it's on. There is no reliable way to turn
  it off from code — it must be toggled manually.
- **Layer 2 — Defender self-protection (PPL / `WdFilter`).** While `MsMpEng.exe` is
  running, Windows guards Defender's own service keys, its program-folder binaries, the
  ETW autologgers and `HKLM\SOFTWARE\Microsoft\Windows Defender` — blocking even SYSTEM and
  TrustedInstaller. The tool gets past this by renaming Defender's **drivers** (see
  "How it disables permanently").

### Steps
1. Open **Windows Security → Virus & threat protection → Manage settings**.
2. Turn **Tamper Protection** → **Off**.
3. Turn **Real-time protection** → **Off** (temporary — also keeps Defender from
   quarantining the tool while it runs).
4. Run **`disable-defender.exe`** (elevated). It relaunches itself as TrustedInstaller
   automatically.
5. **Reboot** (optional, but do it for full effect — the running engine stays in memory
   until then).

> If Defender is managed by your organisation (Intune / MDM / Group Policy), Tamper
> Protection may be greyed out and cannot be disabled at all.

## How it disables permanently (Layer 2, no Safe Mode)
Older approaches needed Safe Mode to write the protected `Wd*` service keys. This tool
instead **soft-deletes Defender's binaries**: it takes ownership as TrustedInstaller and
renames the boot/minifilter drivers (`WdFilter.sys`, `WdBoot.sys`, `WdNisDrv.sys`,
`WdDevFlt.sys`, the `ELAMBKUP` copy) and the engine binaries to `.OLD`. On the next boot
those drivers don't load, so `MsMpEng` can't complete its protected launch and its
self-protection never comes up — **no Safe Mode required.**

- The running engine stays in memory until you **reboot**, which is why a reboot is needed
  to finish the disable.
- Files inside the guarded Defender program folders (`MsMpEng.exe`, the `Mp*.dll`s) can't
  be renamed while the engine runs — that's expected and harmless; renaming the drivers is
  what actually stops Defender at boot.
- A restore manifest is written to `%ProgramData%\defender-control\` so the enable build
  can put everything back.

## What it does
1. Relaunches as TrustedInstaller (via the Task Scheduler service).
2. Disables Defender services + SmartScreen via the registry.
3. Writes policy + UI-lockdown keys (the Windows Security UI becomes inaccessible).
4. Disables VBS/HVCI/Device Guard, the firewall (registry only, so Docker/WSL/Sandbox/
   winget keep working), Defender scheduled tasks, AMSI and ETW autologgers.
5. Soft-deletes Defender's drivers/binaries (rename to `.OLD`) so the engine can't relaunch.
6. Seizes TrustedInstaller-owned keys and files via take-ownership before writing.

## Checking status
After disabling + rebooting the Security UI is locked down, so use the `-c` (or `-check`)
flag from an elevated terminal to print a status report instead:

```
disable-defender.exe -c
```

It reports the live WMI state (antivirus enabled, real-time protection, behaviour
monitoring, tamper protection, AM running mode) plus whether `MsMpEng.exe` is running, the
`WinDefend` start type, and a one-line verdict. Add `-s` to skip the pause.

## Re-enabling Defender
Build and run the **`DEFENDER_ENABLE`** configuration (set in `settings.hpp`). The enable
path:
- restores the renamed `.OLD` binaries/drivers (manifest replay + a `*.OLD` scan fallback,
  so it recovers even if the manifest is lost) and hands ownership back to TrustedInstaller,
- clears the UI-lockdown / policy keys (the Security UI returns),
- clears the leftover `Real-Time Protection\Disable*` values and resets
  `Features\TamperProtection`,
- recreates the `MpDefenderCoreService` key if it was deregistered (resolved from the live
  `InstallLocation` platform path),
- restores `WinDefend` / `Wd*` / `Sense` key ownership and sets `WinDefend` to auto-start.

Then **reboot** — boot-time auto-start is the path that reliably works (a live `sc start`
often times out). Re-check with `-c`.

## If Defender still won't come back
The enable path does everything that doesn't need a live engine, but if the install was
left deeply broken you can fall back to Windows' own repair tooling (run elevated):

```
DISM /Online /Cleanup-Image /RestoreHealth
sfc /scannow
```

- `DISM /RestoreHealth` re-provisions the Defender OS components from Windows Update
  (needs internet, ~5–20 min).
- `sfc /scannow` repairs protected system files.
- **Reboot**, then re-check with `disable-defender.exe -c`.

If the damage is purely registry/state, DISM may report "no corruption found." The
guaranteed fix is an **in-place repair upgrade**: download the Windows ISO or Installation
Assistant, run `setup.exe`, and choose **"Keep personal files and apps."** This rebuilds OS
components (including Defender) without touching your files or installed programs.

## On Windows updates
Windows sometimes updates and turns Defender (and Tamper Protection) back on. If a run
doesn't fully take effect, re-check that Tamper Protection is **Off**, then run
`disable-defender.exe` again before opening an issue.

## Is it safe?
Yes — review the code in this repository. Anti-virus will flag it because it disables
Defender (see the note at the top); compile it yourself with Visual Studio if you prefer.

## Compiling
Open the project in Visual Studio 2022.
Set the configuration to **Release / x64**.
Choose disable vs. enable in `settings.hpp` (`DEFENDER_CONFIG`).
Build.

## Demo
![Demo](https://github.com/pgkt04/defender-control/blob/main/resources/demo.gif?raw=true)

## Release
You can find releases on the right, or [here](https://github.com/pgkt04/defender-control/releases/tag/v1.2).
