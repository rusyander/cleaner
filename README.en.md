# Windows Process Cleaner

[🇷🇺 Русский](README.md) · 🇬🇧 English

A Windows utility that finds and terminates **forgotten / stuck processes** and
purges **Standby Memory**. Works both with development processes (node, python,
java, vite, webpack, npm/pnpm/yarn…) and — in global mode — with **any** orphaned
and idle processes.

Written in **C# + WinForms** and built with the **compiler that ships with
Windows, `csc.exe`** (.NET Framework 4.x). **Nothing to install** — no Node.js,
no Rust, no Visual Studio. The result is a self-contained `.exe`.

---

## What this program is for

One tool to tidy up a developer's machine: kill processes left hanging, free up RAM
and wipe accumulated disk junk — without installing anything and without third-party
"optimizers". All in one window, with Russian and English UI, tray operation and a
schedule.

## What it can do

- **Processes.** Finds forgotten/abandoned processes (dev runtimes, or — in global
  mode — any of yours) and terminates them safely: gracefully first (WM_CLOSE), then
  forcefully. Shows for each: PID, PPID, path, uptime, CPU, RAM, windows, TCP ports,
  child processes, owner.
- **RAM.** Purges Standby Memory via WinAPI (`NtSetSystemInformation`), no third-party exe.
- **Dev Cleanup.** Bulk-terminates Node/Python/Java/Vite/Webpack/npm/pnpm/yarn and frees
  busy dev ports (3000, 5173, 8080, 4200 …).
- **Disk cleanup.** Analyzes and deletes known junk: dev caches (npm/pnpm/yarn/pip/
  gradle/cargo/go/NuGet), system junk (temp, Recycle Bin, Windows Update, dumps),
  browser and app caches (Discord/Slack/Teams/Spotify), old logs, driver installer
  leftovers and `Windows.old`.
- **Docker.** Shows disk usage (`docker system df`) and removes unused data: stopped
  containers, images, volumes, build cache, everything at once.
- **Programs.** Lists installed software and uninstalls it via its own uninstaller.
- **Automation.** Process auto-clean timer (every 1–24 h), start with Windows (via Task
  Scheduler), tray operation, cleanup history, flexible settings.
- **Look & feel.** Dark/light theme (or system) + dark title bar; RU/EN UI language.

## What it does NOT do (safety boundaries)

- **Doesn't break Windows.** System processes (SYSTEM/services), components under
  `C:\Windows`, critical and protected processes (shell, clouds, drivers, messengers)
  are never eligible for termination in global mode; the guards fail safe.
- **Doesn't kill active things by mistake.** A scan candidate is picked only when all
  criteria match at once (dead parent + idle + no windows/ports/children), with
  confirmation. The exception is the Dev Cleanup buttons — a deliberate by-name sledgehammer.
- **Doesn't do disk-wide duplicate search** and never deletes anything from your projects,
  code, `DriverStore`, System32 or drive roots. Only known junk paths are cleaned.
- **Doesn't clean disk or uninstall programs on a schedule** — manual only, with preview
  and confirmation. The timer only runs process cleanup.
- **Docker: removes only unused data** (`prune`) — running containers and used images are
  never touched. Kubernetes is not included.

---

## Quick start (one command)

Double-click **`run.bat`** — on first launch it builds
`WindowsProcessCleaner.exe` and starts it. After that you can run the `.exe`
directly.

Build only, without running:

```
build.bat
```

> ⚠️ The app runs **as administrator** (required to purge Standby Memory). A UAC
> prompt on launch is expected.

---

## Features

### Scanning
For each process it collects: name, PID, PPID, path, uptime, CPU %, RAM, whether
it has a window, listening TCP ports, whether it has child processes, and owner.

### "Abandoned" criteria
A process becomes a termination candidate only when **all** conditions hold:
1. the parent process has exited;
2. CPU below the threshold for longer than the idle time;
3. no user windows;
4. not listening on TCP ports;
5. no child processes;
6. not in the whitelist and older than the minimum lifetime.

### Two scan modes
- **Dev mode** (default) — only processes from the watchlist (node, python, java,
  vite, webpack, npm, pnpm, yarn, bun, cargo, go, deno, ruby, php…).
- **Global mode** (the "All processes (global)" checkbox) — scans **every**
  process. Here **strengthened guards** apply: only processes owned by the **current
  user**, **not** in Windows system folders and **not** in `Program Files` (installed
  software, configurable), idle for **≥ 30 minutes** (configurable), and not in the
  expanded protected list (Windows core, shell, clouds, messengers, drivers, launchers,
  password managers). This is how orphaned groups are caught — those whose parent died
  long ago while the children keep hanging around, burning CPU/RAM while being used by
  nothing.

### Cleanup buttons
- **Clean selected** — terminate the checked rows.
- **Auto-clean all inactive** — terminate every found candidate in one click
  (with a confirmation and a list).
- **Select all / Clear selection** — checkbox control.
- **Purge memory** — Standby Memory purge only, without terminating processes.

Termination itself: first gracefully (WM_CLOSE), wait up to 3 seconds, then force.

### Dev Cleanup
Bulk termination by group: all Node / Python / Java / Vite / Webpack / npm / pnpm /
yarn·bun / Docker Compose / Go·Cargo·Deno. Plus a list of processes holding popular
dev ports (3000, 5173, 8080, 4200 …) that you can terminate.

> Dev Cleanup terminates **by name regardless of activity** (except the whitelist) —
> a deliberate sledgehammer.

### Disk cleanup (manual only)
A dedicated tab. Flow: **Analyze → preview with sizes → delete selected**. There is
intentionally no automatic disk cleanup (files are less reversible than processes).
Only **known junk paths** are cleaned — no disk-wide duplicate search. Categories:
- **Dev caches** — npm / pnpm / yarn / pip / gradle / cargo / go / NuGet (regenerated).
- **System junk** — `%TEMP%`, `Windows\Temp`, Recycle Bin, Windows Update cache,
  crash dumps, error reports.
- **Browser caches** — Chrome / Edge / Brave / Firefox, cache only (no passwords/cookies).
- **App caches** — Discord / Slack / Teams / Spotify, cache only.
- **Old logs** — CBS/DISM logs, npm/yarn, install reports.
- **Old drivers + Windows.old** — NVIDIA/AMD installer leftovers, old Windows folder.

Guards: locked files and reparse points (junctions) are skipped; `DriverStore`,
System32, drive roots, code and projects are never touched.

### Programs (uninstall)
A tab listing installed programs (name, version, publisher, size). Check and uninstall
them through the app — the program's own uninstaller is launched.

### Docker
A tab for Docker cleanup (requires the Docker CLI + a running daemon). Buttons: disk
usage overview (`docker system df`), remove stopped containers, unused images, unused
volumes, clear build cache, full cleanup of everything unused. Only **unused** data is
removed (`prune`) — running containers and used images are never touched. Kubernetes is
not included (its cleanup affects a live cluster).

### Interface language
Russian / English — switchable in settings (applied after restart). The documentation
is bilingual too: [README.md](README.md) / [README.en.md](README.en.md).

### Auto-clean timer
Set a number of hours (1..24). Every N hours the app scans **processes** (in the chosen
mode), terminates candidates, purges memory and writes to history. Disk cleanup and
uninstallation are **never** run by the timer — manual only.

### System tray
The tray icon changes color: green — clean, orange — candidates found. Double-click
opens the window. Right-click menu: Scan, Clean, Purge Standby Memory, toggle
auto-clean, restart as administrator, exit. Closing the window minimizes the app to
tray (it keeps running in the background).

### Start with Windows
A checkbox in settings. Implemented via **Task Scheduler** with highest privileges
(`schtasks /RL HIGHEST`), so there is no UAC prompt at logon.

### Themes
Light / dark / **system** (default — follows the Windows theme). Switchable in
settings, applied immediately, including the window title bar.

### Settings (saved)
CPU threshold, idle time, minimum lifetime, auto-clean interval, watchlist,
whitelist, dev ports, theme, autostart, start-in-tray, global mode.

### History
After each cleanup it saves date/time, number of terminated processes, amount of
freed memory and the list of processes.

---

## Is it safe?

**The scan / auto-clean mode — yes.** A candidate is picked only when **all**
criteria match at once, so an active process (with a window, listening on a port,
using CPU, or with a live parent) will never be selected. Global mode additionally
protects system processes and other users' processes. Termination always asks for
confirmation.

**Dev Cleanup — no**, it is intentionally a sledgehammer: the buttons hit everything
by name (except the whitelist). Use consciously.

---

## Where data lives

`%APPDATA%\WindowsProcessCleaner\` — `config.json` (settings) and `history.json`
(history). The "Data folder" button in settings opens it.

---

## Administrator rights

The app always runs as administrator. This is required to purge Standby Memory via
`ntdll!NtSetSystemInformation`. Terminating the current user's processes also works.

---

## Technical notes

- **WinAPI:** `CreateToolhelp32Snapshot`, `EnumWindows`, `GetExtendedTcpTable`,
  `OpenProcessToken`/`GetTokenInformation` (process owner),
  `SendMessageTimeout(WM_CLOSE)`, `TerminateProcess` (via `Process.Kill`),
  `NtSetSystemInformation` (Standby Memory), `GlobalMemoryStatusEx`,
  `DwmSetWindowAttribute` (dark title bar).
- **Single-instance** via local port **49876** (usually free): a second launch just
  brings the existing window to front.
- CPU/idle monitoring updates on a 10-second tick, so "5 minutes idle" is counted
  from the moment the app started observing the process.

## Project files

| File | Purpose |
|------|---------|
| `ProcessCleaner.cs` | the entire application code |
| `app.manifest` | manifest (requireAdministrator, DPI) |
| `build.bat` | build via the built-in csc.exe |
| `run.bat` | build if needed and run |
| `README.md` / `README.en.md` | documentation (RU / EN) |
