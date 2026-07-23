// Windows Process Cleaner
// Единый файл. Компилируется встроенным в Windows csc.exe (.NET Framework 4.x).
// Никакой сторонней установки не требуется. См. build.bat / run.bat.
//
// Возможности:
//  - Поиск забытых процессов разработки (node/python/java/vite/webpack/...).
//  - Критерии "заброшенности": мёртвый родитель, простой CPU, нет окон, нет
//    слушающих TCP-портов, нет дочерних процессов, белый список, мин. время жизни.
//  - Корректное завершение (WM_CLOSE) -> ожидание 3с -> принудительно (Kill).
//  - Очистка Standby Memory через ntdll!NtSetSystemInformation (нужны права админа).
//  - Dev Cleanup: массовое завершение по группам + занятые dev-порты.
//  - Таймер автоочистки: каждые N часов (1..24), сохраняется в конфиге.
//  - Системный трей с индикацией активности и меню.
//  - Автозапуск вместе с Windows (HKCU\...\Run).
//  - История очисток и настройки в JSON (%APPDATA%\WindowsProcessCleaner).
//  - Single-instance через локальный TCP-порт 49876 (обычно свободен).

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;

namespace WindowsProcessCleaner
{
    // ------------------------------------------------------------------ //
    //  Локализация: Tr.S("русский", "english") возвращает строку по языку.
    // ------------------------------------------------------------------ //
    internal static class Tr
    {
        public static bool En;
        public static string S(string ru, string en) { return En ? en : ru; }
    }

    // ------------------------------------------------------------------ //
    //  Конфигурация и история (сериализуются в JSON)
    // ------------------------------------------------------------------ //
    [DataContract]
    public class AppConfig
    {
        [DataMember] public double CpuThresholdPercent;   // порог CPU %
        [DataMember] public int IdleMinutes;              // время простоя, мин
        [DataMember] public int MinLifetimeMinutes;       // мин. время жизни процесса, мин
        [DataMember] public int AutoIntervalHours;        // период автоочистки, 1..24
        [DataMember] public bool AutoEnabled;             // включена ли автоочистка
        [DataMember] public bool Autostart;               // автозапуск с Windows
        [DataMember] public bool StartMinimized;          // стартовать свёрнутым в трей
        [DataMember] public string Theme;                 // "system" | "light" | "dark"
        [DataMember] public bool GlobalScan;              // сканировать ВСЕ процессы, не только dev
        [DataMember] public int GlobalIdleMinutes;        // мин. простой для глобального режима (безопасность)
        [DataMember] public bool GlobalExcludeInstalled;  // не трогать установленный софт (Program Files)
        [DataMember] public string Language;              // "ru" | "en"
        [DataMember] public List<string> Watchlist;       // отслеживаемые процессы
        [DataMember] public List<string> Whitelist;       // белый список (не трогать)
        [DataMember] public List<int> DevPorts;           // популярные dev-порты

        public static AppConfig Default()
        {
            AppConfig c = new AppConfig();
            c.CpuThresholdPercent = 0.1;
            c.IdleMinutes = 5;
            c.MinLifetimeMinutes = 5;
            c.AutoIntervalHours = 4;
            c.AutoEnabled = false;
            c.Autostart = false;
            c.StartMinimized = false;
            c.Theme = "system";
            c.GlobalScan = false;
            c.GlobalIdleMinutes = 30;
            c.GlobalExcludeInstalled = true;
            c.Language = "ru";
            c.Watchlist = new List<string>(new string[] {
                "node.exe","npm.exe","pnpm.exe","yarn.exe","bun.exe",
                "python.exe","pythonw.exe","java.exe","gradle.exe",
                "vite.exe","webpack.exe","next.exe","cargo.exe",
                "go.exe","deno.exe","ruby.exe","php.exe"
            });
            c.Whitelist = new List<string>(new string[] {
                "explorer.exe","wininit.exe","svchost.exe","dwm.exe","System","Registry",
                "docker.exe","com.docker.backend.exe","vmmem.exe","wsl.exe",
                "postgres.exe","mysqld.exe","redis-server.exe",
                "steam.exe","discord.exe","chrome.exe","firefox.exe","msedge.exe"
            });
            c.DevPorts = new List<int>(new int[] {
                3000,3001,3002,4173,5173,5174,8080,8000,8888,4200,4300,5000,5555,9000,9090,1337,19006
            });
            return c;
        }

        public void Normalize()
        {
            if (Watchlist == null) Watchlist = Default().Watchlist;
            if (Whitelist == null) Whitelist = Default().Whitelist;
            if (DevPorts == null) DevPorts = Default().DevPorts;
            if (string.IsNullOrEmpty(Theme)) Theme = "system";
            if (string.IsNullOrEmpty(Language)) Language = "ru";
            if (GlobalIdleMinutes < 1) GlobalIdleMinutes = 30;
            if (AutoIntervalHours < 1) AutoIntervalHours = 1;
            if (AutoIntervalHours > 24) AutoIntervalHours = 24;
            if (IdleMinutes < 0) IdleMinutes = 0;
            if (MinLifetimeMinutes < 0) MinLifetimeMinutes = 0;
            if (CpuThresholdPercent < 0) CpuThresholdPercent = 0;
        }
    }

    [DataContract]
    public class HistoryEntry
    {
        [DataMember] public string DateTime;
        [DataMember] public int TerminatedCount;
        [DataMember] public long FreedBytes;
        [DataMember] public List<string> Processes;
    }

    [DataContract]
    public class HistoryFile
    {
        [DataMember] public List<HistoryEntry> Entries;
    }

    // ------------------------------------------------------------------ //
    //  Модель найденного процесса
    // ------------------------------------------------------------------ //
    public class ProcInfo
    {
        public int Pid;
        public int ParentPid;
        public string Name;        // node.exe
        public string Category;    // Node.js
        public string Path;
        public TimeSpan Uptime;
        public double CpuPercent;
        public long RamBytes;
        public bool HasWindow;
        public bool ListensTcp;
        public bool HasChildren;
        public bool ParentAlive;
        public TimeSpan IdleFor;
        public bool Whitelisted;
        public bool UserOwned;     // принадлежит текущему пользователю
        public bool IsSystemPath;  // лежит в системной папке Windows
        public bool IsCandidate;   // кандидат на завершение
        public string Reason;      // почему кандидат / почему нет
    }

    // ------------------------------------------------------------------ //
    //  WinAPI
    // ------------------------------------------------------------------ //
    internal static class Native
    {
        // --- Toolhelp снимок процессов ---
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }

        public const uint TH32CS_SNAPPROCESS = 0x00000002;

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Process32First(IntPtr snap, ref PROCESSENTRY32 e);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool Process32Next(IntPtr snap, ref PROCESSENTRY32 e);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr h);

        // --- Окна ---
        public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
        [DllImport("user32.dll")]
        public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);
        [DllImport("user32.dll", SetLastError = true)]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
        [DllImport("user32.dll")]
        public static extern bool IsWindowVisible(IntPtr hWnd);
        [DllImport("user32.dll")]
        public static extern IntPtr GetWindow(IntPtr hWnd, uint cmd);
        [DllImport("user32.dll")]
        public static extern int GetWindowTextLength(IntPtr hWnd);

        // --- TCP таблица (владелец PID) ---
        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern uint GetExtendedTcpTable(IntPtr pTable, ref int size,
            bool order, int af, int tableClass, int reserved);

        public const int AF_INET = 2;
        public const int TCP_TABLE_OWNER_PID_ALL = 5;
        public const int MIB_TCP_STATE_LISTEN = 2;

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;   // сетевой порядок байт, значимы младшие 2 байта
            public uint remoteAddr;
            public uint remotePort;
            public uint owningPid;
        }

        // --- Завершение по WM_CLOSE ---
        public const uint WM_CLOSE = 0x0010;
        [DllImport("user32.dll")]
        public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, IntPtr wParam,
            IntPtr lParam, uint flags, uint timeout, out IntPtr result);

        // --- Standby Memory (ntdll) ---
        [DllImport("ntdll.dll")]
        public static extern int NtSetSystemInformation(int infoClass, IntPtr info, int length);
        public const int SystemMemoryListInformation = 0x50;
        public const int MemoryPurgeStandbyList = 4;
        public const int MemoryEmptyWorkingSets = 2;

        // --- Привилегии ---
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID { public uint LowPart; public int HighPart; }
        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES { public uint Count; public LUID Luid; public uint Attributes; }

        public const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        public const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const uint TOKEN_QUERY = 0x0008;

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr proc, uint access, out IntPtr token);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupPrivilegeValue(string host, string name, out LUID luid);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll,
            ref TOKEN_PRIVILEGES newState, uint len, IntPtr prev, IntPtr retLen);
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        // --- Владелец процесса (SID) ---
        public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll")]
        public static extern IntPtr LocalFree(IntPtr h);

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }
        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_USER { public SID_AND_ATTRIBUTES User; }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(IntPtr token, int infoClass,
            IntPtr buf, int len, out int retLen);
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr str);
        public const int TokenUser = 1;

        public static string GetProcessUserSid(int pid)
        {
            IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) return null;
            try
            {
                IntPtr token;
                if (!OpenProcessToken(h, TOKEN_QUERY, out token)) return null;
                try
                {
                    int len = 0;
                    GetTokenInformation(token, TokenUser, IntPtr.Zero, 0, out len);
                    if (len <= 0) return null;
                    IntPtr buf = Marshal.AllocHGlobal(len);
                    try
                    {
                        if (!GetTokenInformation(token, TokenUser, buf, len, out len)) return null;
                        TOKEN_USER tu = (TOKEN_USER)Marshal.PtrToStructure(buf, typeof(TOKEN_USER));
                        IntPtr sidStr;
                        if (!ConvertSidToStringSid(tu.User.Sid, out sidStr)) return null;
                        try { return Marshal.PtrToStringAuto(sidStr); }
                        finally { LocalFree(sidStr); }
                    }
                    finally { Marshal.FreeHGlobal(buf); }
                }
                finally { CloseHandle(token); }
            }
            finally { CloseHandle(h); }
        }

        // --- Память системы ---
        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORYSTATUSEX
        {
            public uint dwLength;
            public uint dwMemoryLoad;
            public ulong ullTotalPhys;
            public ulong ullAvailPhys;
            public ulong ullTotalPageFile;
            public ulong ullAvailPageFile;
            public ulong ullTotalVirtual;
            public ulong ullAvailVirtual;
            public ulong ullAvailExtendedVirtual;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX buf);

        // --- Тёмный заголовок окна (DWM) ---
        [DllImport("dwmapi.dll")]
        public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int val, int size);
        public const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;
        public const int DWMWA_USE_IMMERSIVE_DARK_MODE_OLD = 19;

        // --- Корзина ---
        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct SHQUERYRBINFO { public int cbSize; public long i64Size; public long i64NumItems; }
        [DllImport("shell32.dll", CharSet = CharSet.Auto)]
        public static extern int SHQueryRecycleBin(string rootPath, ref SHQUERYRBINFO info);
        [DllImport("shell32.dll", CharSet = CharSet.Auto)]
        public static extern int SHEmptyRecycleBin(IntPtr hwnd, string rootPath, uint flags);
        public const uint SHERB_NOCONFIRMATION = 0x1;
        public const uint SHERB_NOPROGRESSUI = 0x2;
        public const uint SHERB_NOSOUND = 0x4;

        public static bool EnablePrivilege(string name)
        {
            IntPtr token;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
                return false;
            try
            {
                LUID luid;
                if (!LookupPrivilegeValue(null, name, out luid)) return false;
                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
                tp.Count = 1;
                tp.Luid = luid;
                tp.Attributes = SE_PRIVILEGE_ENABLED;
                return AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            }
            finally { CloseHandle(token); }
        }
    }

    // ------------------------------------------------------------------ //
    //  Строка занятого порта (для Dev Cleanup)
    // ------------------------------------------------------------------ //
    public class PortRow
    {
        public int Port;
        public int Pid;
        public string ProcName;
    }

    // Категория очистки диска (набор известных мусорных путей).
    public class CleanTarget { public string Path; public bool ContentsOnly; }
    public class CleanCategory
    {
        public string Id;
        public string Title;
        public string Desc;
        public List<CleanTarget> Targets = new List<CleanTarget>();
        public bool RecycleBin;
        public bool Recommended;
        public long Size;
        public int FileCount;
    }
    public class CleanResult { public long Freed; public int Errors; }

    // Установленная программа (для деинсталляции / автозапуска).
    public class InstalledApp
    {
        public string Name;
        public string Version;
        public string Publisher;
        public string UninstallCmd;
        public string QuietCmd;
        public string ExePath;   // главный exe (из DisplayIcon), если удалось определить
        public long EstimatedSizeBytes;
        public bool InAutostart; // вычисляется во вкладке автозапуска
    }

    // Запись автозапуска (реестр Run или папка «Автозагрузка»).
    public class AutostartEntry
    {
        public string Name;
        public string Command;
        public string ExePath;
        public string SourceLabel;
        public int Kind;        // 0 HKCU Run, 1 HKLM Run, 2 HKLM WOW Run, 3 Startup(user), 4 Startup(common)
        public string RegName;  // имя значения в реестре
        public string LnkPath;  // путь к ярлыку в папке автозагрузки
    }

    // ------------------------------------------------------------------ //
    //  Тема оформления (светлая / тёмная / по системе)
    // ------------------------------------------------------------------ //
    public class Theme
    {
        public bool Dark;
        public Color Bg;          // фон окна
        public Color Surface;     // фон полей/списков
        public Color Text;        // основной текст
        public Color Subtle;      // приглушённый текст
        public Color Accent;      // акцент (кнопки, выделение)
        public Color AccentText;  // текст на акценте
        public Color Border;      // границы
        public Color CandidateBg; // строка-кандидат
        public Color WhiteBg;     // строка из белого списка
        public Color Header;      // фон заголовков колонок

        public static Theme Light()
        {
            Theme t = new Theme();
            t.Dark = false;
            t.Bg = Color.FromArgb(243, 244, 246);
            t.Surface = Color.FromArgb(255, 255, 255);
            t.Text = Color.FromArgb(28, 30, 34);
            t.Subtle = Color.FromArgb(110, 116, 124);
            t.Accent = Color.FromArgb(37, 99, 235);
            t.AccentText = Color.White;
            t.Border = Color.FromArgb(214, 218, 224);
            t.CandidateBg = Color.FromArgb(255, 243, 214);
            t.WhiteBg = Color.FromArgb(226, 240, 228);
            t.Header = Color.FromArgb(233, 236, 240);
            return t;
        }

        public static Theme DarkTheme()
        {
            Theme t = new Theme();
            t.Dark = true;
            t.Bg = Color.FromArgb(24, 25, 28);
            t.Surface = Color.FromArgb(37, 39, 44);
            t.Text = Color.FromArgb(228, 230, 234);
            t.Subtle = Color.FromArgb(150, 156, 164);
            t.Accent = Color.FromArgb(59, 130, 246);
            t.AccentText = Color.White;
            t.Border = Color.FromArgb(58, 61, 68);
            t.CandidateBg = Color.FromArgb(74, 60, 30);
            t.WhiteBg = Color.FromArgb(38, 54, 40);
            t.Header = Color.FromArgb(45, 47, 53);
            return t;
        }

        // Разрешить "system" через реестр Windows.
        public static Theme Resolve(string mode)
        {
            if (mode == "light") return Light();
            if (mode == "dark") return DarkTheme();
            // system
            return SystemIsLight() ? Light() : DarkTheme();
        }

        public static bool SystemIsLight()
        {
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"))
                {
                    if (k != null)
                    {
                        object v = k.GetValue("AppsUseLightTheme");
                        if (v is int) return ((int)v) != 0;
                    }
                }
            }
            catch { }
            return true; // по умолчанию светлая
        }
    }

    // ------------------------------------------------------------------ //
    //  Ядро: сканер и операции над процессами
    // ------------------------------------------------------------------ //
    public class Engine
    {
        public AppConfig Config;
        private readonly string _dir;
        private readonly string _configPath;
        private readonly string _historyPath;

        // Мониторинг CPU/простоя между тиками
        private class CpuSample { public TimeSpan Cpu; public DateTime At; }
        private readonly Dictionary<int, CpuSample> _lastCpu = new Dictionary<int, CpuSample>();
        private readonly Dictionary<int, double> _cpuPercent = new Dictionary<int, double>();
        private readonly Dictionary<int, DateTime> _idleSince = new Dictionary<int, DateTime>();

        private string _currentUserSid;
        private string _winDir;
        private string _programFiles;
        private string _programFilesX86;
        private int _selfPid;

        // Никогда не завершать в глобальном режиме (сверх белого списка):
        // критичные системные/оболочечные процессы + типовые фоновые утилиты,
        // которые обычно должны работать постоянно (облака, драйверы, мессенджеры).
        private static readonly HashSet<string> _critical = new HashSet<string>(
            new string[] {
                // --- ядро Windows и оболочка ---
                "system","registry","idle","smss.exe","csrss.exe","wininit.exe","winlogon.exe",
                "services.exe","lsass.exe","lsaiso.exe","fontdrvhost.exe","dwm.exe","explorer.exe",
                "taskhostw.exe","taskhost.exe","sihost.exe","ctfmon.exe","runtimebroker.exe","conhost.exe",
                "dllhost.exe","searchhost.exe","searchapp.exe","startmenuexperiencehost.exe","shellexperiencehost.exe",
                "textinputhost.exe","applicationframehost.exe","searchindexer.exe","lockapp.exe",
                "wudfhost.exe","spoolsv.exe","audiodg.exe","memcompression","sechealthsystray.exe",
                "securityhealthservice.exe","msmpeng.exe","nissrv.exe","widgets.exe","widgetservice.exe",
                "windowsprocesscleaner.exe","dax3api.exe","phoneexperiencehost.exe",
                // --- облака / синхронизация ---
                "onedrive.exe","dropbox.exe","dropboxupdate.exe","googledrivefs.exe","googledrivesync.exe",
                "yandexdisk.exe","yandexdisk2.exe","megasync.exe","nextcloud.exe",
                // --- мессенджеры / медиа (обычно свёрнуты в трей без окна) ---
                "telegram.exe","discord.exe","slack.exe","teams.exe","ms-teams.exe","whatsapp.exe",
                "spotify.exe","zoom.exe","viber.exe","skype.exe",
                // --- драйверы / вендорские службы ---
                "nvcontainer.exe","nvsphelper64.exe","nvidia web helper.exe","nvdisplay.container.exe",
                "rtkauduservice64.exe","ravbg64.exe","igfxem.exe","igfxext.exe","igfxtray.exe",
                "lghub.exe","lghub_agent.exe","logioptionsplus_agent.exe","logi_lamparray_service.exe",
                "razer synapse service.exe","razercentralservice.exe","steelseriesgg.exe",
                "armourycrate.service.exe","asus","icue.exe","corsair.service.exe",
                // --- прочее ПО, которому нужен фон ---
                "steam.exe","steamwebhelper.exe","epicgameslauncher.exe","msedgewebview2.exe",
                "adobeupdateservice.exe","creative cloud.exe","ccxprocess.exe","acrotray.exe",
                "1password.exe","bitwarden.exe","keepass.exe","keepassxc.exe"
            }, StringComparer.OrdinalIgnoreCase);

        public Engine()
        {
            _dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                                 "WindowsProcessCleaner");
            Directory.CreateDirectory(_dir);
            _configPath = Path.Combine(_dir, "config.json");
            _historyPath = Path.Combine(_dir, "history.json");
            LoadConfig();

            try { _currentUserSid = WindowsIdentity.GetCurrent().User.Value; } catch { _currentUserSid = null; }
            try { _winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows); } catch { _winDir = @"C:\Windows"; }
            try { _programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles); } catch { _programFiles = @"C:\Program Files"; }
            try { _programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86); } catch { _programFilesX86 = @"C:\Program Files (x86)"; }
            try { _selfPid = Process.GetCurrentProcess().Id; } catch { _selfPid = 0; }
        }

        public string DataDir { get { return _dir; } }

        // ---------- Конфиг ----------
        public void LoadConfig()
        {
            try
            {
                if (File.Exists(_configPath))
                {
                    using (FileStream fs = File.OpenRead(_configPath))
                    {
                        DataContractJsonSerializer s = new DataContractJsonSerializer(typeof(AppConfig));
                        Config = (AppConfig)s.ReadObject(fs);
                    }
                }
            }
            catch { Config = null; }
            if (Config == null) Config = AppConfig.Default();
            Config.Normalize();
        }

        public void SaveConfig()
        {
            Config.Normalize();
            using (FileStream fs = File.Create(_configPath))
            {
                DataContractJsonSerializer s = new DataContractJsonSerializer(typeof(AppConfig));
                s.WriteObject(fs, Config);
            }
        }

        // ---------- История ----------
        public HistoryFile LoadHistory()
        {
            try
            {
                if (File.Exists(_historyPath))
                {
                    using (FileStream fs = File.OpenRead(_historyPath))
                    {
                        DataContractJsonSerializer s = new DataContractJsonSerializer(typeof(HistoryFile));
                        HistoryFile h = (HistoryFile)s.ReadObject(fs);
                        if (h.Entries == null) h.Entries = new List<HistoryEntry>();
                        return h;
                    }
                }
            }
            catch { }
            HistoryFile empty = new HistoryFile();
            empty.Entries = new List<HistoryEntry>();
            return empty;
        }

        public void AppendHistory(HistoryEntry e)
        {
            HistoryFile h = LoadHistory();
            h.Entries.Insert(0, e);
            if (h.Entries.Count > 500) h.Entries = h.Entries.Take(500).ToList();
            using (FileStream fs = File.Create(_historyPath))
            {
                DataContractJsonSerializer s = new DataContractJsonSerializer(typeof(HistoryFile));
                s.WriteObject(fs, h);
            }
        }

        // ---------- Категории для отображения ----------
        public static string Categorize(string exe)
        {
            string n = exe.ToLowerInvariant();
            if (n == "node.exe" || n == "next.exe") return "Node.js";
            if (n == "npm.exe") return "npm";
            if (n == "pnpm.exe") return "pnpm";
            if (n == "yarn.exe") return "yarn";
            if (n == "bun.exe") return "Bun";
            if (n == "python.exe" || n == "pythonw.exe") return "Python";
            if (n == "java.exe" || n == "gradle.exe") return "Java";
            if (n == "vite.exe") return "Vite";
            if (n == "webpack.exe") return "Webpack";
            if (n == "cargo.exe") return "Cargo";
            if (n == "go.exe") return "Go";
            if (n == "deno.exe") return "Deno";
            if (n == "ruby.exe") return "Ruby";
            if (n == "php.exe") return "PHP";
            return exe;
        }

        // ---------- Снимок процессов ----------
        private class RawProc { public int Pid; public int Ppid; public string Name; }

        private List<RawProc> Snapshot()
        {
            List<RawProc> list = new List<RawProc>();
            IntPtr snap = Native.CreateToolhelp32Snapshot(Native.TH32CS_SNAPPROCESS, 0);
            if (snap == IntPtr.Zero || snap == new IntPtr(-1)) return list;
            try
            {
                Native.PROCESSENTRY32 e = new Native.PROCESSENTRY32();
                e.dwSize = (uint)Marshal.SizeOf(typeof(Native.PROCESSENTRY32));
                if (Native.Process32First(snap, ref e))
                {
                    do
                    {
                        RawProc r = new RawProc();
                        r.Pid = (int)e.th32ProcessID;
                        r.Ppid = (int)e.th32ParentProcessID;
                        r.Name = e.szExeFile;
                        list.Add(r);
                    } while (Native.Process32Next(snap, ref e));
                }
            }
            finally { Native.CloseHandle(snap); }
            return list;
        }

        // visible  — процессы с видимым озаглавленным окном (для dev-режима);
        // anyTop   — процессы с любым верхнеуровневым окном, в т.ч. скрытым
        //            (для глобального режима: защищает свёрнутые в трей приложения).
        private void WindowPids(out HashSet<int> visible, out HashSet<int> anyTop)
        {
            HashSet<int> v = new HashSet<int>();
            HashSet<int> a = new HashSet<int>();
            Native.EnumWindows(delegate(IntPtr h, IntPtr l)
            {
                uint pid;
                Native.GetWindowThreadProcessId(h, out pid);
                a.Add((int)pid);
                if (Native.IsWindowVisible(h) && Native.GetWindowTextLength(h) > 0)
                    v.Add((int)pid);
                return true;
            }, IntPtr.Zero);
            visible = v;
            anyTop = a;
        }

        private bool IsUnderSystem(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string p = path.ToLowerInvariant();
            if (!string.IsNullOrEmpty(_winDir) && p.StartsWith(_winDir.ToLowerInvariant())) return true;
            if (p.Contains("\\windowsapps\\") || p.Contains("\\systemapps\\")) return true;
            return false;
        }

        private bool IsInstalledLocation(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string p = path.ToLowerInvariant();
            if (!string.IsNullOrEmpty(_programFiles) && p.StartsWith(_programFiles.ToLowerInvariant())) return true;
            if (!string.IsNullOrEmpty(_programFilesX86) && p.StartsWith(_programFilesX86.ToLowerInvariant())) return true;
            return false;
        }

        // Возвращает пары (pid, port) всех строк TCP; listeners — множество PID со LISTEN.
        public List<PortRow> TcpRows(out HashSet<int> listeners)
        {
            listeners = new HashSet<int>();
            List<PortRow> rows = new List<PortRow>();
            int size = 0;
            Native.GetExtendedTcpTable(IntPtr.Zero, ref size, false, Native.AF_INET,
                Native.TCP_TABLE_OWNER_PID_ALL, 0);
            if (size <= 0) return rows;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                uint ret = Native.GetExtendedTcpTable(buf, ref size, false, Native.AF_INET,
                    Native.TCP_TABLE_OWNER_PID_ALL, 0);
                if (ret != 0) return rows;
                int count = Marshal.ReadInt32(buf);
                IntPtr rowPtr = new IntPtr(buf.ToInt64() + 4);
                int rowSize = Marshal.SizeOf(typeof(Native.MIB_TCPROW_OWNER_PID));
                for (int i = 0; i < count; i++)
                {
                    Native.MIB_TCPROW_OWNER_PID row = (Native.MIB_TCPROW_OWNER_PID)
                        Marshal.PtrToStructure(new IntPtr(rowPtr.ToInt64() + i * rowSize),
                                               typeof(Native.MIB_TCPROW_OWNER_PID));
                    int port = ((int)(row.localPort & 0xFF) << 8) | (int)((row.localPort >> 8) & 0xFF);
                    if (row.state == Native.MIB_TCP_STATE_LISTEN)
                    {
                        listeners.Add((int)row.owningPid);
                        PortRow pr = new PortRow();
                        pr.Port = port;
                        pr.Pid = (int)row.owningPid;
                        rows.Add(pr);
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
            return rows;
        }

        // ---------- Тик мониторинга: обновляет CPU% и время простоя ----------
        public void MonitorTick()
        {
            List<RawProc> snap = Snapshot();
            HashSet<int> alive = new HashSet<int>(snap.Select(p => p.Pid));
            DateTime now = DateTime.Now;

            foreach (RawProc r in snap)
            {
                if (r.Pid <= 4) continue; // System Idle / System
                try
                {
                    Process p = Process.GetProcessById(r.Pid);
                    TimeSpan cpu = p.TotalProcessorTime;
                    CpuSample prev;
                    if (_lastCpu.TryGetValue(r.Pid, out prev))
                    {
                        double wall = (now - prev.At).TotalMilliseconds;
                        if (wall > 0)
                        {
                            double pct = (cpu - prev.Cpu).TotalMilliseconds
                                         / (wall * Environment.ProcessorCount) * 100.0;
                            if (pct < 0) pct = 0;
                            _cpuPercent[r.Pid] = pct;
                            if (pct < Config.CpuThresholdPercent)
                            {
                                if (!_idleSince.ContainsKey(r.Pid)) _idleSince[r.Pid] = now;
                            }
                            else { _idleSince.Remove(r.Pid); }
                        }
                    }
                    CpuSample cur = new CpuSample();
                    cur.Cpu = cpu; cur.At = now;
                    _lastCpu[r.Pid] = cur;
                }
                catch { }
            }

            // чистим умершие PID
            List<int> dead = _lastCpu.Keys.Where(k => !alive.Contains(k)).ToList();
            foreach (int k in dead) { _lastCpu.Remove(k); _cpuPercent.Remove(k); _idleSince.Remove(k); }
        }

        private HashSet<string> WatchSet()
        {
            HashSet<string> s = new HashSet<string>();
            foreach (string w in Config.Watchlist) s.Add(w.Trim().ToLowerInvariant());
            return s;
        }

        private bool IsWhitelisted(string exe)
        {
            string n = exe.ToLowerInvariant();
            string noext = n.EndsWith(".exe") ? n.Substring(0, n.Length - 4) : n;
            foreach (string w in Config.Whitelist)
            {
                string ww = w.Trim().ToLowerInvariant();
                if (ww.Length == 0) continue;
                string wwNoext = ww.EndsWith(".exe") ? ww.Substring(0, ww.Length - 4) : ww;
                if (n == ww || noext == wwNoext) return true;
            }
            return false;
        }

        // ---------- Полное сканирование ----------
        // global=false — только процессы из watchlist (dev-режим).
        // global=true  — ВСЕ процессы; кандидаты отбираются с усиленными
        //                предохранителями (только свои процессы, не системные пути).
        public List<ProcInfo> Scan(bool global)
        {
            List<RawProc> snap = Snapshot();
            HashSet<string> watch = WatchSet();
            HashSet<int> visible, anyTop;
            WindowPids(out visible, out anyTop);
            HashSet<int> listeners;
            TcpRows(out listeners);

            HashSet<int> alive = new HashSet<int>(snap.Select(p => p.Pid));
            HashSet<int> parents = new HashSet<int>(snap.Select(p => p.Ppid));

            DateTime now = DateTime.Now;
            List<ProcInfo> result = new List<ProcInfo>();

            foreach (RawProc r in snap)
            {
                bool inWatch = watch.Contains(r.Name.ToLowerInvariant());
                if (!global && !inWatch) continue;
                if (r.Pid <= 4 || r.Pid == _selfPid) continue;

                ProcInfo info = new ProcInfo();
                info.Pid = r.Pid;
                info.ParentPid = r.Ppid;
                info.Name = r.Name;
                info.Category = Categorize(r.Name);
                info.HasWindow = global ? anyTop.Contains(r.Pid) : visible.Contains(r.Pid);
                info.ListensTcp = listeners.Contains(r.Pid);
                info.HasChildren = parents.Contains(r.Pid);
                info.ParentAlive = r.Ppid != 0 && alive.Contains(r.Ppid);
                info.Whitelisted = IsWhitelisted(r.Name);
                info.UserOwned = true;

                double pct;
                info.CpuPercent = _cpuPercent.TryGetValue(r.Pid, out pct) ? pct : 0;
                DateTime since;
                info.IdleFor = _idleSince.TryGetValue(r.Pid, out since) ? (now - since) : TimeSpan.Zero;

                try
                {
                    Process p = Process.GetProcessById(r.Pid);
                    info.RamBytes = p.WorkingSet64;
                    try { info.Uptime = now - p.StartTime; } catch { info.Uptime = TimeSpan.Zero; }
                    try { info.Path = p.MainModule != null ? p.MainModule.FileName : ""; }
                    catch { info.Path = ""; }
                }
                catch { }

                if (global)
                {
                    info.IsSystemPath = IsUnderSystem(info.Path);
                    string sid = Native.GetProcessUserSid(r.Pid);
                    info.UserOwned = _currentUserSid != null && sid != null && sid == _currentUserSid;
                }

                EvaluateCandidate(info, global);
                result.Add(info);
            }
            return result;
        }

        private void EvaluateCandidate(ProcInfo p, bool global)
        {
            List<string> reasons = new List<string>();
            if (p.Whitelisted) { p.IsCandidate = false; p.Reason = Tr.S("в белом списке", "whitelisted"); return; }

            if (global)
            {
                if (_critical.Contains(p.Name)) { p.IsCandidate = false; p.Reason = Tr.S("защищённый процесс", "protected process"); return; }
                if (!p.UserOwned) { p.IsCandidate = false; p.Reason = Tr.S("не ваш процесс", "not your process"); return; }
                if (p.IsSystemPath) { p.IsCandidate = false; p.Reason = Tr.S("системный компонент", "system component"); return; }
                if (string.IsNullOrEmpty(p.Path)) { p.IsCandidate = false; p.Reason = Tr.S("нет доступа к пути", "no path access"); return; }
                if (Config.GlobalExcludeInstalled && IsInstalledLocation(p.Path))
                { p.IsCandidate = false; p.Reason = Tr.S("установленное приложение", "installed application"); return; }
            }

            if (p.Uptime.TotalMinutes < Config.MinLifetimeMinutes)
            { p.IsCandidate = false; p.Reason = Tr.S("молодой процесс", "too young"); return; }

            int idleReq = global ? Math.Max(Config.IdleMinutes, Config.GlobalIdleMinutes) : Config.IdleMinutes;
            bool parentDead = !p.ParentAlive;
            bool idleEnough = p.CpuPercent < Config.CpuThresholdPercent
                              && p.IdleFor.TotalMinutes >= idleReq;
            bool noWindow = !p.HasWindow;
            bool noTcp = !p.ListensTcp;
            bool noChildren = !p.HasChildren;

            if (parentDead && idleEnough && noWindow && noTcp && noChildren)
            {
                p.IsCandidate = true;
                p.Reason = Tr.S("родитель мёртв, простой, без окон/портов/детей",
                                "orphaned, idle, no windows/ports/children");
            }
            else
            {
                p.IsCandidate = false;
                if (p.ParentAlive) reasons.Add(Tr.S("жив родитель", "parent alive"));
                if (!idleEnough) reasons.Add(Tr.S("активен/мало простоя", "active/low idle"));
                if (p.HasWindow) reasons.Add(Tr.S("есть окно", "has window"));
                if (p.ListensTcp) reasons.Add(Tr.S("слушает порт", "listens on port"));
                if (p.HasChildren) reasons.Add(Tr.S("есть дочерние", "has children"));
                p.Reason = string.Join(", ", reasons.ToArray());
            }
        }

        // ---------- Завершение ----------
        // Возвращает true, если процесс завершён. freed — освобождённая RAM (WorkingSet до убийства).
        public bool TerminateProcess(int pid, out long freed)
        {
            freed = 0;
            Process p;
            try { p = Process.GetProcessById(pid); }
            catch { return true; } // уже нет
            try { freed = p.WorkingSet64; } catch { }

            // 1) корректное завершение через WM_CLOSE всем окнам процесса
            try
            {
                List<IntPtr> wins = new List<IntPtr>();
                Native.EnumWindows(delegate(IntPtr h, IntPtr l)
                {
                    uint wp;
                    Native.GetWindowThreadProcessId(h, out wp);
                    if ((int)wp == pid) wins.Add(h);
                    return true;
                }, IntPtr.Zero);
                foreach (IntPtr h in wins)
                {
                    IntPtr res;
                    Native.SendMessageTimeout(h, Native.WM_CLOSE, IntPtr.Zero, IntPtr.Zero, 0, 1000, out res);
                }
            }
            catch { }

            // 2) ждём до 3 секунд
            try { if (p.WaitForExit(3000)) return true; } catch { return true; }

            // 3) принудительно
            try { p.Kill(); p.WaitForExit(3000); return true; }
            catch
            {
                try { return p.HasExited; } catch { return false; }
            }
        }

        // ---------- Очистка Standby Memory ----------
        public class MemResult { public bool Ok; public long FreedBytes; public string Message; }

        public MemResult PurgeStandby()
        {
            MemResult mr = new MemResult();
            Native.MEMORYSTATUSEX before = new Native.MEMORYSTATUSEX();
            before.dwLength = (uint)Marshal.SizeOf(typeof(Native.MEMORYSTATUSEX));
            Native.GlobalMemoryStatusEx(ref before);

            Native.EnablePrivilege("SeProfileSingleProcessPrivilege");
            Native.EnablePrivilege("SeIncreaseQuotaPrivilege");

            int rc = SetMemoryList(Native.MemoryEmptyWorkingSets);
            int rc2 = SetMemoryList(Native.MemoryPurgeStandbyList);

            Native.MEMORYSTATUSEX after = new Native.MEMORYSTATUSEX();
            after.dwLength = (uint)Marshal.SizeOf(typeof(Native.MEMORYSTATUSEX));
            Native.GlobalMemoryStatusEx(ref after);

            long freed = (long)after.ullAvailPhys - (long)before.ullAvailPhys;
            mr.FreedBytes = freed > 0 ? freed : 0;

            if (rc2 == 0)
            {
                mr.Ok = true;
                mr.Message = Tr.S("Standby Memory очищена", "Standby Memory purged");
            }
            else if ((uint)rc2 == 0xC0000061)
            {
                mr.Ok = false;
                mr.Message = Tr.S("Нужны права администратора (перезапустите от админа)",
                                   "Administrator rights required (restart as admin)");
            }
            else
            {
                mr.Ok = false;
                mr.Message = "NtSetSystemInformation вернул 0x" + ((uint)rc2).ToString("X8");
            }
            return mr;
        }

        private int SetMemoryList(int command)
        {
            IntPtr p = Marshal.AllocHGlobal(sizeof(int));
            try
            {
                Marshal.WriteInt32(p, command);
                return Native.NtSetSystemInformation(Native.SystemMemoryListInformation, p, sizeof(int));
            }
            finally { Marshal.FreeHGlobal(p); }
        }

        // ---------- Массовое завершение по группе (Dev Cleanup) ----------
        public int TerminateByNames(string[] names, out long freed)
        {
            freed = 0;
            int killed = 0;
            HashSet<string> want = new HashSet<string>(names.Select(n => n.ToLowerInvariant()));
            foreach (RawProc r in Snapshot())
            {
                if (want.Contains(r.Name.ToLowerInvariant()) && !IsWhitelisted(r.Name))
                {
                    long f;
                    if (TerminateProcess(r.Pid, out f)) { killed++; freed += f; }
                }
            }
            return killed;
        }

        // ---------- Занятые dev-порты ----------
        public List<PortRow> DevPortRows()
        {
            HashSet<int> listeners;
            List<PortRow> rows = TcpRows(out listeners);
            HashSet<int> devPorts = new HashSet<int>(Config.DevPorts);
            Dictionary<int, string> names = new Dictionary<int, string>();
            foreach (RawProc r in Snapshot()) names[r.Pid] = r.Name;

            List<PortRow> outRows = new List<PortRow>();
            HashSet<string> seen = new HashSet<string>();
            foreach (PortRow pr in rows)
            {
                if (!devPorts.Contains(pr.Port)) continue;
                string key = pr.Port + ":" + pr.Pid;
                if (seen.Contains(key)) continue;
                seen.Add(key);
                string nm;
                pr.ProcName = names.TryGetValue(pr.Pid, out nm) ? nm : "(pid " + pr.Pid + ")";
                outRows.Add(pr);
            }
            outRows.Sort(delegate(PortRow a, PortRow b) { return a.Port.CompareTo(b.Port); });
            return outRows;
        }

        // ================= ОЧИСТКА ДИСКА =================
        // Только известные мусорные пути. Никакого поиска дубликатов по диску.

        private void AddDir(CleanCategory c, string path, bool contentsOnly)
        {
            try { if (Directory.Exists(path)) c.Targets.Add(new CleanTarget { Path = path, ContentsOnly = contentsOnly }); }
            catch { }
        }

        private void AddChromium(CleanCategory c, string userData)
        {
            if (!Directory.Exists(userData)) return;
            string[] profiles = null;
            try { profiles = Directory.GetDirectories(userData); } catch { }
            if (profiles == null) return;
            foreach (string p in profiles)
            {
                AddDir(c, Path.Combine(p, "Cache"), true);
                AddDir(c, Path.Combine(p, "Code Cache"), true);
                AddDir(c, Path.Combine(p, "GPUCache"), true);
                AddDir(c, Path.Combine(p, "Service Worker\\CacheStorage"), true);
            }
        }

        private void AddFirefox(CleanCategory c, string profilesDir)
        {
            if (!Directory.Exists(profilesDir)) return;
            string[] ps = null;
            try { ps = Directory.GetDirectories(profilesDir); } catch { }
            if (ps == null) return;
            foreach (string p in ps) AddDir(c, Path.Combine(p, "cache2"), true);
        }

        // Кэш Electron-приложения (Discord/Slack/Teams и т.п.)
        private void AddElectronCache(CleanCategory c, string dir)
        {
            AddDir(c, Path.Combine(dir, "Cache"), true);
            AddDir(c, Path.Combine(dir, "Code Cache"), true);
            AddDir(c, Path.Combine(dir, "GPUCache"), true);
            AddDir(c, Path.Combine(dir, "Service Worker\\CacheStorage"), true);
        }

        public List<CleanCategory> BuildCleanCategories()
        {
            string lad = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string ad = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string up = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string pd = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string temp = Path.GetTempPath();
            string sysDrive = Path.GetPathRoot(_winDir);
            List<CleanCategory> list = new List<CleanCategory>();

            // Dev-кэши
            CleanCategory dev = new CleanCategory();
            dev.Id = "dev"; dev.Title = Tr.S("Dev-кэши", "Dev caches"); dev.Recommended = true;
            dev.Desc = Tr.S("npm / pnpm / yarn / pip / gradle / cargo / go / NuGet (пересоздаются)",
                            "npm / pnpm / yarn / pip / gradle / cargo / go / NuGet (regenerated)");
            AddDir(dev, Path.Combine(lad, "npm-cache"), true);
            AddDir(dev, Path.Combine(ad, "npm-cache"), true);
            AddDir(dev, Path.Combine(up, ".npm\\_cacache"), true);
            AddDir(dev, Path.Combine(lad, "Yarn\\Cache"), true);
            AddDir(dev, Path.Combine(lad, "Yarn\\berry\\cache"), true);
            AddDir(dev, Path.Combine(up, ".yarn\\cache"), true);
            AddDir(dev, Path.Combine(lad, "pnpm\\store"), true);
            AddDir(dev, Path.Combine(lad, "pnpm-store"), true);
            AddDir(dev, Path.Combine(up, ".pnpm-store"), true);
            AddDir(dev, Path.Combine(lad, "pip\\Cache"), true);
            AddDir(dev, Path.Combine(up, ".gradle\\caches"), true);
            AddDir(dev, Path.Combine(up, ".cargo\\registry\\cache"), true);
            AddDir(dev, Path.Combine(up, ".cargo\\registry\\src"), true);
            AddDir(dev, Path.Combine(up, "go\\pkg\\mod\\cache\\download"), true);
            AddDir(dev, Path.Combine(up, ".nuget\\packages"), true);
            AddDir(dev, Path.Combine(lad, "NuGet\\Cache"), true);
            AddDir(dev, Path.Combine(lad, "NuGet\\v3-cache"), true);
            if (dev.Targets.Count > 0) list.Add(dev);

            // Системный мусор
            CleanCategory sys = new CleanCategory();
            sys.Id = "sys"; sys.Title = Tr.S("Системный мусор", "System junk"); sys.Recommended = true; sys.RecycleBin = true;
            sys.Desc = Tr.S("temp, Корзина, кэш Windows Update, crash dumps, отчёты об ошибках",
                            "temp, Recycle Bin, Windows Update cache, crash dumps, error reports");
            AddDir(sys, temp, true);
            AddDir(sys, Path.Combine(_winDir, "Temp"), true);
            AddDir(sys, Path.Combine(_winDir, "SoftwareDistribution\\Download"), true);
            AddDir(sys, Path.Combine(lad, "CrashDumps"), true);
            AddDir(sys, Path.Combine(lad, "Microsoft\\Windows\\WER"), true);
            AddDir(sys, Path.Combine(pd, "Microsoft\\Windows\\WER"), true);
            AddDir(sys, Path.Combine(lad, "Temp"), true);
            list.Add(sys);

            // Кэши браузеров
            CleanCategory br = new CleanCategory();
            br.Id = "browser"; br.Title = Tr.S("Кэши браузеров", "Browser caches");
            br.Desc = Tr.S("Chrome / Edge / Brave / Firefox — только кэш (без паролей и куки)",
                           "Chrome / Edge / Brave / Firefox — cache only (no passwords/cookies)");
            AddChromium(br, Path.Combine(lad, "Google\\Chrome\\User Data"));
            AddChromium(br, Path.Combine(lad, "Microsoft\\Edge\\User Data"));
            AddChromium(br, Path.Combine(lad, "BraveSoftware\\Brave-Browser\\User Data"));
            AddChromium(br, Path.Combine(lad, "Yandex\\YandexBrowser\\User Data"));
            AddFirefox(br, Path.Combine(lad, "Mozilla\\Firefox\\Profiles"));
            if (br.Targets.Count > 0) list.Add(br);

            // Кэши приложений (Electron/медиа)
            CleanCategory apps = new CleanCategory();
            apps.Id = "appcache"; apps.Title = Tr.S("Кэши приложений", "App caches");
            apps.Desc = Tr.S("Discord / Slack / Teams / Spotify — только кэш",
                             "Discord / Slack / Teams / Spotify — cache only");
            AddElectronCache(apps, Path.Combine(ad, "discord"));
            AddElectronCache(apps, Path.Combine(ad, "discordptb"));
            AddElectronCache(apps, Path.Combine(ad, "discordcanary"));
            AddElectronCache(apps, Path.Combine(ad, "Slack"));
            AddElectronCache(apps, Path.Combine(ad, "Microsoft\\Teams"));
            AddDir(apps, Path.Combine(lad, "Spotify\\Storage"), true);
            AddDir(apps, Path.Combine(lad, "Spotify\\Data"), true);
            AddDir(apps, Path.Combine(lad, "Spotify\\Browser"), true);
            if (apps.Targets.Count > 0) list.Add(apps);

            // Старые логи
            CleanCategory logs = new CleanCategory();
            logs.Id = "logs"; logs.Title = Tr.S("Старые логи", "Old logs");
            logs.Desc = Tr.S("логи CBS/DISM, npm/yarn, отчёты об установке",
                             "CBS/DISM logs, npm/yarn, install reports");
            AddDir(logs, Path.Combine(_winDir, "Logs\\CBS"), true);
            AddDir(logs, Path.Combine(_winDir, "Logs\\DISM"), true);
            AddDir(logs, Path.Combine(lad, "npm-cache\\_logs"), true);
            AddDir(logs, Path.Combine(up, ".npm\\_logs"), true);
            AddDir(logs, Path.Combine(lad, "Yarn\\logs"), true);
            if (logs.Targets.Count > 0) list.Add(logs);

            // Старые драйверы + Windows.old
            CleanCategory drv = new CleanCategory();
            drv.Id = "drivers"; drv.Title = Tr.S("Старые драйверы + Windows.old", "Old drivers + Windows.old");
            drv.Desc = Tr.S("installer-мусор NVIDIA/AMD, папка старой Windows (не трогает DriverStore)",
                            "NVIDIA/AMD installer leftovers, old Windows folder (DriverStore untouched)");
            AddDir(drv, Path.Combine(sysDrive, "NVIDIA"), false);
            AddDir(drv, Path.Combine(pd, "NVIDIA Corporation\\Downloader"), true);
            AddDir(drv, Path.Combine(sysDrive, "AMD"), false);
            AddDir(drv, Path.Combine(sysDrive, "Intel"), false);
            AddDir(drv, Path.Combine(sysDrive, "Windows.old"), false);
            if (drv.Targets.Count > 0) list.Add(drv);

            return list;
        }

        // Обход каталога с пропуском ошибок и точек повторного разбора (junction/symlink).
        private void WalkDir(string dir, List<string> files, List<string> dirs)
        {
            try
            {
                DirectoryInfo di = new DirectoryInfo(dir);
                if ((di.Attributes & FileAttributes.ReparsePoint) != 0) return;
            }
            catch { return; }
            string[] fs = null, ds = null;
            try { fs = Directory.GetFiles(dir); } catch { }
            if (fs != null) files.AddRange(fs);
            try { ds = Directory.GetDirectories(dir); } catch { }
            if (ds != null)
                foreach (string s in ds) { dirs.Add(s); WalkDir(s, files, dirs); }
        }

        private long DirSize(string dir, out int count)
        {
            count = 0;
            List<string> files = new List<string>();
            List<string> dirs = new List<string>();
            WalkDir(dir, files, dirs);
            long total = 0;
            foreach (string f in files)
            {
                try { total += new FileInfo(f).Length; count++; } catch { }
            }
            return total;
        }

        public void AnalyzeCategory(CleanCategory c)
        {
            long total = 0; int cnt = 0;
            foreach (CleanTarget t in c.Targets) { int n; total += DirSize(t.Path, out n); cnt += n; }
            if (c.RecycleBin)
            {
                Native.SHQUERYRBINFO info = new Native.SHQUERYRBINFO();
                info.cbSize = Marshal.SizeOf(typeof(Native.SHQUERYRBINFO));
                try { if (Native.SHQueryRecycleBin(null, ref info) == 0) { total += info.i64Size; cnt += (int)info.i64NumItems; } }
                catch { }
            }
            c.Size = total; c.FileCount = cnt;
        }

        // Предохранитель: не удаляем корни дисков и ключевые системные папки целиком.
        private bool IsSafeToDelete(string path)
        {
            if (string.IsNullOrEmpty(path)) return false;
            string p;
            try { p = Path.GetFullPath(path).TrimEnd('\\'); } catch { return false; }
            if (p.Length < 4) return false;
            string root = (Path.GetPathRoot(p) ?? "").TrimEnd('\\');
            if (string.Equals(p, root, StringComparison.OrdinalIgnoreCase)) return false;
            string pl = p.ToLowerInvariant();
            if (pl == _winDir.ToLowerInvariant()) return false;
            if (pl == Path.Combine(_winDir, "System32").ToLowerInvariant()) return false;
            if (!string.IsNullOrEmpty(_programFiles) && pl == _programFiles.ToLowerInvariant()) return false;
            if (!string.IsNullOrEmpty(_programFilesX86) && pl == _programFilesX86.ToLowerInvariant()) return false;
            return true;
        }

        private long DeletePath(string path, bool contentsOnly, ref int errors)
        {
            long freed = 0;
            if (!Directory.Exists(path)) return 0;
            List<string> files = new List<string>();
            List<string> dirs = new List<string>();
            WalkDir(path, files, dirs);
            foreach (string f in files)
            {
                try
                {
                    FileInfo fi = new FileInfo(f);
                    long l = fi.Length;
                    if ((fi.Attributes & FileAttributes.ReadOnly) != 0) fi.Attributes = FileAttributes.Normal;
                    fi.Delete();
                    freed += l;
                }
                catch { errors++; }
            }
            dirs.Sort(delegate(string a, string b) { return b.Length.CompareTo(a.Length); });
            foreach (string d in dirs) { try { Directory.Delete(d, false); } catch { errors++; } }
            if (!contentsOnly) { try { Directory.Delete(path, false); } catch { errors++; } }
            return freed;
        }

        public CleanResult CleanCategories(List<CleanCategory> cats)
        {
            CleanResult res = new CleanResult();
            foreach (CleanCategory c in cats)
            {
                foreach (CleanTarget t in c.Targets)
                {
                    if (!IsSafeToDelete(t.Path)) { res.Errors++; continue; }
                    res.Freed += DeletePath(t.Path, t.ContentsOnly, ref res.Errors);
                }
                if (c.RecycleBin)
                {
                    try
                    {
                        Native.SHEmptyRecycleBin(IntPtr.Zero, null,
                            Native.SHERB_NOCONFIRMATION | Native.SHERB_NOPROGRESSUI | Native.SHERB_NOSOUND);
                    }
                    catch { }
                }
            }
            return res;
        }

        // ================= ДЕИНСТАЛЛЯЦИЯ ПРОГРАММ =================
        public List<InstalledApp> GetInstalledApps()
        {
            Dictionary<string, InstalledApp> map = new Dictionary<string, InstalledApp>(StringComparer.OrdinalIgnoreCase);
            ReadUninstall(Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", map);
            ReadUninstall(Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", map);
            ReadUninstall(Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", map);
            List<InstalledApp> list = new List<InstalledApp>(map.Values);
            list.Sort(delegate(InstalledApp a, InstalledApp b)
            { return string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase); });
            return list;
        }

        private void ReadUninstall(RegistryKey root, string sub, Dictionary<string, InstalledApp> map)
        {
            try
            {
                using (RegistryKey k = root.OpenSubKey(sub))
                {
                    if (k == null) return;
                    foreach (string name in k.GetSubKeyNames())
                    {
                        try
                        {
                            using (RegistryKey s = k.OpenSubKey(name))
                            {
                                if (s == null) continue;
                                object sysComp = s.GetValue("SystemComponent");
                                if (sysComp is int && (int)sysComp == 1) continue;
                                if (s.GetValue("ParentKeyName") != null) continue; // патчи/апдейты
                                if (s.GetValue("ReleaseType") as string == "Security Update") continue;
                                string disp = s.GetValue("DisplayName") as string;
                                string unins = s.GetValue("UninstallString") as string;
                                if (string.IsNullOrEmpty(disp) || string.IsNullOrEmpty(unins)) continue;
                                InstalledApp app = new InstalledApp();
                                app.Name = disp;
                                app.Version = s.GetValue("DisplayVersion") as string;
                                app.Publisher = s.GetValue("Publisher") as string;
                                app.UninstallCmd = unins;
                                app.QuietCmd = s.GetValue("QuietUninstallString") as string;
                                app.ExePath = ResolveAppExe(s.GetValue("DisplayIcon") as string,
                                                            s.GetValue("InstallLocation") as string, disp);
                                object es = s.GetValue("EstimatedSize");
                                if (es is int) app.EstimatedSizeBytes = ((long)(int)es) * 1024L;
                                map[disp] = app;
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        public void RunUninstall(InstalledApp app)
        {
            string cmd = app.UninstallCmd;
            if (string.IsNullOrEmpty(cmd)) return;
            ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + cmd);
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            Process.Start(psi);
        }

        // ================= АВТОЗАПУСК =================
        private string ResolveAppExe(string displayIcon, string installLoc, string name)
        {
            // 1) из DisplayIcon ("C:\...\app.exe,0")
            if (!string.IsNullOrEmpty(displayIcon))
            {
                string ip = displayIcon.Trim().Trim('"');
                int comma = ip.LastIndexOf(',');
                if (comma > 0)
                {
                    int idx;
                    if (int.TryParse(ip.Substring(comma + 1).Trim(), out idx)) ip = ip.Substring(0, comma);
                }
                ip = ip.Trim().Trim('"');
                try { if (ip.ToLowerInvariant().EndsWith(".exe") && File.Exists(ip)) return ip; }
                catch { }
            }
            // 2) поиск exe в InstallLocation по имени программы
            try
            {
                if (!string.IsNullOrEmpty(installLoc) && Directory.Exists(installLoc))
                {
                    string[] exes = Directory.GetFiles(installLoc, "*.exe", SearchOption.TopDirectoryOnly);
                    if (exes.Length == 1) return exes[0];
                    if (exes.Length > 1 && !string.IsNullOrEmpty(name))
                    {
                        string key = new string(name.ToLowerInvariant().Where(char.IsLetterOrDigit).ToArray());
                        foreach (string e in exes)
                        {
                            string fn = new string(Path.GetFileNameWithoutExtension(e).ToLowerInvariant().Where(char.IsLetterOrDigit).ToArray());
                            if (key.Length > 2 && (key.Contains(fn) || fn.Contains(key))) return e;
                        }
                    }
                }
            }
            catch { }
            return null;
        }

        private string ParseExeFromCommand(string cmd)
        {
            if (string.IsNullOrEmpty(cmd)) return null;
            cmd = cmd.Trim();
            if (cmd.StartsWith("\""))
            {
                int end = cmd.IndexOf('"', 1);
                if (end > 0) return cmd.Substring(1, end - 1);
            }
            int sp = cmd.IndexOf(' ');
            string p = sp > 0 ? cmd.Substring(0, sp) : cmd;
            return p.Trim();
        }

        private string ResolveLnk(string lnkPath)
        {
            try
            {
                Type t = Type.GetTypeFromProgID("WScript.Shell");
                if (t == null) return null;
                object shell = Activator.CreateInstance(t);
                object sc = t.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell,
                    new object[] { lnkPath });
                string target = (string)sc.GetType().InvokeMember("TargetPath", BindingFlags.GetProperty,
                    null, sc, null);
                return target;
            }
            catch { return null; }
        }

        private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string RunKeyPathWow = @"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run";

        public List<AutostartEntry> GetAutostartEntries()
        {
            List<AutostartEntry> list = new List<AutostartEntry>();
            ReadRun(Registry.CurrentUser, RunKeyPath, 0, "HKCU\\Run", list);
            ReadRun(Registry.LocalMachine, RunKeyPath, 1, "HKLM\\Run", list);
            ReadRun(Registry.LocalMachine, RunKeyPathWow, 2, "HKLM\\Run (32-bit)", list);
            ReadStartupFolder(Environment.SpecialFolder.Startup, 3, "Автозагрузка (пользователь)", list);
            ReadStartupFolder(Environment.SpecialFolder.CommonStartup, 4, "Автозагрузка (общая)", list);
            return list;
        }

        private void ReadRun(RegistryKey root, string sub, int kind, string label, List<AutostartEntry> list)
        {
            try
            {
                using (RegistryKey k = root.OpenSubKey(sub))
                {
                    if (k == null) return;
                    foreach (string name in k.GetValueNames())
                    {
                        string cmd = k.GetValue(name) as string;
                        if (string.IsNullOrEmpty(cmd)) continue;
                        AutostartEntry e = new AutostartEntry();
                        e.Name = name; e.Command = cmd; e.ExePath = ParseExeFromCommand(cmd);
                        e.Kind = kind; e.SourceLabel = label; e.RegName = name;
                        list.Add(e);
                    }
                }
            }
            catch { }
        }

        private void ReadStartupFolder(Environment.SpecialFolder folder, int kind, string label, List<AutostartEntry> list)
        {
            try
            {
                string dir = Environment.GetFolderPath(folder);
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return;
                foreach (string f in Directory.GetFiles(dir))
                {
                    string ext = Path.GetExtension(f).ToLowerInvariant();
                    if (ext == ".ini") continue;
                    string target = ext == ".lnk" ? ResolveLnk(f) : f;
                    AutostartEntry e = new AutostartEntry();
                    e.Name = Path.GetFileNameWithoutExtension(f);
                    e.Command = target != null ? target : f;
                    e.ExePath = target; e.Kind = kind; e.SourceLabel = label; e.LnkPath = f;
                    list.Add(e);
                }
            }
            catch { }
        }

        private static string NormPath(string p)
        {
            if (string.IsNullOrEmpty(p)) return null;
            try { return Path.GetFullPath(p).TrimEnd('\\').ToLowerInvariant(); }
            catch { return p.Trim().TrimEnd('\\').ToLowerInvariant(); }
        }

        public bool IsExeInAutostart(string exe, List<AutostartEntry> entries)
        {
            string np = NormPath(exe);
            if (np == null) return false;
            foreach (AutostartEntry e in entries)
            {
                string ep = NormPath(e.ExePath);
                if (ep != null && ep == np) return true;
            }
            return false;
        }

        private static string SanitizeName(string name)
        {
            if (string.IsNullOrEmpty(name)) return "App";
            string s = name.Replace('\\', ' ').Replace('/', ' ').Trim();
            if (s.Length > 60) s = s.Substring(0, 60);
            return s;
        }

        public void AddAutostart(string name, string exe)
        {
            if (string.IsNullOrEmpty(exe)) return;
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(RunKeyPath, true))
                {
                    if (k != null) k.SetValue(SanitizeName(name), "\"" + exe + "\"");
                }
            }
            catch { }
        }

        public void RemoveAutostart(string exe, string name)
        {
            RemoveFromRun(Registry.CurrentUser, RunKeyPath, exe, name);
            RemoveFromRun(Registry.LocalMachine, RunKeyPath, exe, name);
            RemoveFromRun(Registry.LocalMachine, RunKeyPathWow, exe, name);
            RemoveStartupLnk(Environment.SpecialFolder.Startup, exe);
            RemoveStartupLnk(Environment.SpecialFolder.CommonStartup, exe);
        }

        private void RemoveFromRun(RegistryKey root, string sub, string exe, string name)
        {
            try
            {
                using (RegistryKey k = root.OpenSubKey(sub, true))
                {
                    if (k == null) return;
                    string np = NormPath(exe);
                    string san = SanitizeName(name);
                    List<string> toDelete = new List<string>();
                    foreach (string vn in k.GetValueNames())
                    {
                        string cmd = k.GetValue(vn) as string;
                        string ep = NormPath(ParseExeFromCommand(cmd));
                        if ((np != null && ep == np) || vn == san) toDelete.Add(vn);
                    }
                    foreach (string vn in toDelete) k.DeleteValue(vn, false);
                }
            }
            catch { }
        }

        private void RemoveStartupLnk(Environment.SpecialFolder folder, string exe)
        {
            try
            {
                string dir = Environment.GetFolderPath(folder);
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return;
                string np = NormPath(exe);
                foreach (string f in Directory.GetFiles(dir, "*.lnk"))
                {
                    string target = NormPath(ResolveLnk(f));
                    if (target != null && target == np) { try { File.Delete(f); } catch { } }
                }
            }
            catch { }
        }

        // ================= DOCKER =================
        public string RunCapture(string exe, string args, out int exit)
        {
            exit = -1;
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(exe, args);
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.CreateNoWindow = true;
                psi.StandardOutputEncoding = Encoding.UTF8;
                psi.StandardErrorEncoding = Encoding.UTF8;
                Process p = Process.Start(psi);
                string o = p.StandardOutput.ReadToEnd();
                string e = p.StandardError.ReadToEnd();
                p.WaitForExit(120000);
                exit = p.HasExited ? p.ExitCode : -1;
                string res = o;
                if (!string.IsNullOrEmpty(e)) res += (res.Length > 0 ? "\r\n" : "") + e;
                return res.Trim();
            }
            catch (Exception ex)
            {
                return "[ошибка] " + ex.Message +
                    "\r\nВозможно, CLI не установлен или отсутствует в PATH.";
            }
        }

        public string Docker(string args)
        {
            int ec;
            string outp = RunCapture("docker", args, out ec);
            // docker печатает LF; TextBox требует CRLF, иначе строки слипаются
            outp = outp.Replace("\r\n", "\n").Replace("\n", "\r\n");
            return "> docker " + args + "\r\n" + outp + "\r\n";
        }

        // Находит самый большой виртуальный диск Docker (WSL2).
        public string FindDockerVhdx()
        {
            string lad = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string[] cands = {
                Path.Combine(lad, "Docker\\wsl\\disk\\docker_data.vhdx"),
                Path.Combine(lad, "Docker\\wsl\\data\\ext4.vhdx"),
                Path.Combine(lad, "Docker\\wsl\\main\\ext4.vhdx")
            };
            string best = null; long bestSize = -1;
            foreach (string c in cands)
            {
                try { if (File.Exists(c)) { long s = new FileInfo(c).Length; if (s > bestSize) { bestSize = s; best = c; } } }
                catch { }
            }
            return best;
        }

        // Останавливает Docker (WSL) и сжимает vhdx через diskpart — реально
        // возвращает место на диске Windows (prune освобождает только ВНУТРИ vhdx).
        public string CompactDockerDisk()
        {
            string vhdx = FindDockerVhdx();
            if (vhdx == null)
                return Tr.S("Не найден виртуальный диск Docker (docker_data.vhdx / ext4.vhdx).\r\n" +
                            "Возможно, Docker Desktop не установлен или использует другой backend.",
                            "Docker virtual disk not found (docker_data.vhdx / ext4.vhdx).\r\n" +
                            "Docker Desktop may not be installed or uses a different backend.");
            long before = 0;
            try { before = new FileInfo(vhdx).Length; } catch { }
            StringBuilder sb = new StringBuilder();
            sb.AppendLine(Tr.S("Диск: ", "Disk: ") + vhdx);
            sb.AppendLine(Tr.S("Размер до: ", "Size before: ") + FormatBytes(before));
            sb.AppendLine();

            int ec;
            sb.AppendLine("> wsl --shutdown");
            sb.AppendLine(RunCapture("wsl", "--shutdown", out ec));
            System.Threading.Thread.Sleep(4000);

            string script = "select vdisk file=\"" + vhdx + "\"\r\n" +
                            "attach vdisk readonly\r\ncompact vdisk\r\ndetach vdisk\r\nexit\r\n";
            string scriptPath = Path.Combine(Path.GetTempPath(), "wpc_compact.txt");
            try { File.WriteAllText(scriptPath, script); } catch { }
            sb.AppendLine("> diskpart compact vdisk …");
            string dp = RunCapture("diskpart", "/s \"" + scriptPath + "\"", out ec);
            dp = dp.Replace("\r\n", "\n").Replace("\n", "\r\n");
            sb.AppendLine(dp);
            try { File.Delete(scriptPath); } catch { }

            long after = before;
            try { after = new FileInfo(vhdx).Length; } catch { }
            sb.AppendLine();
            sb.AppendLine(Tr.S("Размер после: ", "Size after: ") + FormatBytes(after));
            long freed = before - after;
            sb.AppendLine(Tr.S("Освобождено на диске Windows: ", "Reclaimed on Windows disk: ") +
                          FormatBytes(freed > 0 ? freed : 0));
            if (freed <= 0)
                sb.AppendLine(Tr.S("(если 0 — закройте Docker Desktop полностью и повторите: файл был занят)",
                                   "(if 0 — fully quit Docker Desktop and retry: the file was locked)"));
            return sb.ToString();
        }

        // ---------- Автозапуск с Windows ----------
        // Приложение запускается от администратора (requireAdministrator), поэтому
        // ключ реестра Run для автозапуска не годится (Windows не запускает из него
        // приложения с повышенными правами). Используем Планировщик задач с
        // наивысшими правами — тогда при входе в систему UAC не появляется.
        private const string TaskName = "WindowsProcessCleaner";

        public void ApplyAutostart(bool enabled)
        {
            // почистить возможный устаревший Run-ключ
            try
            {
                using (RegistryKey k = Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Run", true))
                {
                    if (k != null && k.GetValue(TaskName) != null) k.DeleteValue(TaskName, false);
                }
            }
            catch { }

            try
            {
                string args;
                if (enabled)
                {
                    string exe = Application.ExecutablePath;
                    args = "/Create /TN \"" + TaskName + "\" /TR \"\\\"" + exe +
                           "\\\" /tray\" /SC ONLOGON /RL HIGHEST /F";
                }
                else
                {
                    args = "/Delete /TN \"" + TaskName + "\" /F";
                }
                ProcessStartInfo psi = new ProcessStartInfo("schtasks.exe", args);
                psi.CreateNoWindow = true;
                psi.UseShellExecute = false;
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                Process p = Process.Start(psi);
                if (p != null) p.WaitForExit(5000);
            }
            catch { }
        }

        public static string FormatBytes(long b)
        {
            double v = b;
            string[] u = Tr.En ? new string[] { "B", "KB", "MB", "GB", "TB" }
                                : new string[] { "Б", "КБ", "МБ", "ГБ", "ТБ" };
            int i = 0;
            while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
            return v.ToString("0.0", CultureInfo.InvariantCulture) + " " + u[i];
        }
    }

    // ------------------------------------------------------------------ //
    //  Главная форма
    // ------------------------------------------------------------------ //
    public class MainForm : Form
    {
        private readonly Engine _engine;
        private NotifyIcon _tray;
        private Icon _iconIdle, _iconActive;
        private System.Windows.Forms.Timer _monitorTimer;   // тик мониторинга CPU
        private System.Windows.Forms.Timer _autoTimer;      // автоочистка
        private DateTime _nextAuto = DateTime.MaxValue;
        private bool _reallyExit = false;

        private Panel _content;
        private Button[] _navButtons;
        private Control[] _pages;
        private int _currentPage;
        private ListView _lvScan;
        private Label _lblSummary, _lblResult;
        private ListView _lvPorts;
        private ListView _lvHistory;
        private ListView _lvClean;
        private Label _lblCleanTotal;
        private List<CleanCategory> _cleanCats;
        private ListView _lvApps;
        private Label _lblAppsInfo;
        private List<InstalledApp> _apps;
        private RichTextBox _txtDocker;
        private ListView _lvStartup;
        private Label _lblStartupInfo;
        private bool _suppressStartup;
        private Panel _navPanel;

        // Настройки — контролы
        private NumericUpDown _numCpu, _numIdle, _numMinLife, _numInterval, _numGlobalIdle;
        private CheckBox _chkAuto, _chkAutostart, _chkStartMin, _chkExcludeInstalled;
        private TextBox _txtWatch, _txtWhite, _txtPorts;
        private ComboBox _cmbTheme;
        private ComboBox _cmbLang;
        private CheckBox _chkGlobal;
        private MenuItem _miAuto;

        // Тема оформления
        private Theme _theme;

        public MainForm(Engine engine)
        {
            _engine = engine;
            _theme = Theme.Resolve(engine.Config.Theme);
            BuildIcons();
            BuildUi();
            BuildTray();
            ApplyThemeAll();

            _monitorTimer = new System.Windows.Forms.Timer();
            _monitorTimer.Interval = 10000; // 10 c
            _monitorTimer.Tick += delegate { SafeMonitorTick(); };
            _monitorTimer.Start();
            SafeMonitorTick();

            _autoTimer = new System.Windows.Forms.Timer();
            _autoTimer.Interval = 30000; // проверяем расписание каждые 30 c
            _autoTimer.Tick += delegate { CheckAutoSchedule(); };
            _autoTimer.Start();
            RescheduleAuto();

            LoadSettingsToUi();
        }

        // ---------- Иконки трея ----------
        private Icon _iconWindow;

        private void BuildIcons()
        {
            _iconIdle = MakeIcon(Color.FromArgb(58, 166, 85));    // зелёная — чисто
            _iconActive = MakeIcon(Color.FromArgb(224, 150, 40)); // оранжевая — есть кандидаты
            _iconWindow = MakeIcon(Color.FromArgb(45, 120, 224));  // синяя — иконка окна/панели задач
        }

        // Многоразмерная иконка из файла (крипче в трее/на панели задач); фолбэк — рисованная.
        private Icon LoadAppIcon()
        {
            try
            {
                string path = Path.Combine(Application.StartupPath, "icon.ico");
                if (File.Exists(path)) return new Icon(path);
            }
            catch { }
            return _iconWindow;
        }

        private static GraphicsPath RoundedRect(Rectangle r, int radius)
        {
            GraphicsPath p = new GraphicsPath();
            int d = radius * 2;
            p.AddArc(r.X, r.Y, d, d, 180, 90);
            p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
            p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
            p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
            p.CloseFigure();
            return p;
        }

        // Чёткая иконка с настоящим альфа-каналом: собираем многоразмерный .ico
        // из PNG (16..64px). GetHicon НЕ используем — он теряет прозрачность и даёт
        // чёрный ореол/невидимость в трее.
        private Icon MakeIcon(Color c)
        {
            int[] sizes = { 16, 20, 24, 32, 48, 64 };
            Bitmap[] bmps = new Bitmap[sizes.Length];
            for (int i = 0; i < sizes.Length; i++) bmps[i] = DrawIconBitmap(sizes[i], c);
            Icon ico = IconFromBitmaps(bmps);
            foreach (Bitmap b in bmps) b.Dispose();
            return ico;
        }

        private Bitmap DrawIconBitmap(int S, Color c)
        {
            Bitmap bmp = new Bitmap(S, S);
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.Clear(Color.Transparent);
                int m = Math.Max(1, (int)Math.Round(S * 0.07));
                int rad = Math.Max(2, (int)Math.Round(S * 0.24));
                Rectangle rect = new Rectangle(m, m, S - 2 * m, S - 2 * m);
                using (GraphicsPath gp = RoundedRect(rect, rad))
                using (LinearGradientBrush br = new LinearGradientBrush(
                    rect, ControlPaint.Light(c, 0.28f), ControlPaint.Dark(c, 0.10f), 90f))
                    g.FillPath(br, gp);
                using (Pen p = new Pen(Color.White, Math.Max(1.4f, S * 0.11f)))
                {
                    p.StartCap = LineCap.Round; p.EndCap = LineCap.Round; p.LineJoin = LineJoin.Round;
                    g.DrawLines(p, new PointF[] {
                        new PointF(S * 0.30f, S * 0.53f),
                        new PointF(S * 0.44f, S * 0.68f),
                        new PointF(S * 0.72f, S * 0.33f) });
                }
            }
            return bmp;
        }

        // Сборка .ico из набора PNG (сохраняет альфу) и создание Icon из потока.
        private static Icon IconFromBitmaps(Bitmap[] sizes)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                BinaryWriter bw = new BinaryWriter(ms);
                bw.Write((ushort)0); bw.Write((ushort)1); bw.Write((ushort)sizes.Length);
                byte[][] pngs = new byte[sizes.Length][];
                for (int i = 0; i < sizes.Length; i++)
                {
                    using (MemoryStream s = new MemoryStream())
                    {
                        sizes[i].Save(s, ImageFormat.Png);
                        pngs[i] = s.ToArray();
                    }
                }
                int offset = 6 + 16 * sizes.Length;
                for (int i = 0; i < sizes.Length; i++)
                {
                    int S = sizes[i].Width;
                    bw.Write((byte)(S >= 256 ? 0 : S));
                    bw.Write((byte)(S >= 256 ? 0 : S));
                    bw.Write((byte)0); bw.Write((byte)0);
                    bw.Write((ushort)1); bw.Write((ushort)32);
                    bw.Write((uint)pngs[i].Length);
                    bw.Write((uint)offset);
                    offset += pngs[i].Length;
                }
                for (int i = 0; i < sizes.Length; i++) bw.Write(pngs[i]);
                bw.Flush();
                ms.Position = 0;
                return new Icon(ms);
            }
        }

        // ---------- Красивая отрисовка таблиц (owner-draw под тему) ----------
        private void SetupOwnerDraw(ListView lv)
        {
            lv.OwnerDraw = true;
            lv.GridLines = false;
            lv.ShowItemToolTips = true; // полный текст обрезанных ячеек по наведению
            lv.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            lv.DrawColumnHeader += Lv_DrawColumnHeader;
            lv.DrawItem += delegate(object s, DrawListViewItemEventArgs e) { e.DrawDefault = false; };
            lv.DrawSubItem += Lv_DrawSubItem;
            // последняя колонка занимает всю оставшуюся ширину — без белой "добивки" заголовка
            lv.Resize += delegate { AutoFillLastColumn(lv); };
        }

        private void AutoFillLastColumn(ListView lv)
        {
            if (lv == null || lv.Columns.Count == 0) return;
            // -2 = LVSCW_AUTOSIZE_USEHEADER: последняя колонка занимает остаток ширины
            // (нативно, с корректной перерисовкой заголовка — без белой "добивки").
            lv.Columns[lv.Columns.Count - 1].Width = -2;
        }

        private void Lv_DrawColumnHeader(object sender, DrawListViewColumnHeaderEventArgs e)
        {
            using (SolidBrush b = new SolidBrush(_theme.Header)) e.Graphics.FillRectangle(b, e.Bounds);
            using (Pen p = new Pen(_theme.Border))
            {
                e.Graphics.DrawLine(p, e.Bounds.Right - 1, e.Bounds.Top + 4, e.Bounds.Right - 1, e.Bounds.Bottom - 4);
                e.Graphics.DrawLine(p, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);
            }
            Rectangle tr = new Rectangle(e.Bounds.X + 8, e.Bounds.Y, e.Bounds.Width - 12, e.Bounds.Height);
            using (Font hf = new Font(((ListView)sender).Font, FontStyle.Bold))
                TextRenderer.DrawText(e.Graphics, e.Header.Text, hf, tr, _theme.Subtle,
                    TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
        }

        private void Lv_DrawSubItem(object sender, DrawListViewSubItemEventArgs e)
        {
            ListView lv = (ListView)sender;
            bool selected = e.Item.Selected;
            Color bg = e.Item.BackColor;
            if (bg.IsEmpty || bg.A == 0) bg = _theme.Surface;
            if (selected)
                bg = _theme.Dark ? ControlPaint.Light(_theme.Accent, 0.15f)
                                 : ControlPaint.Light(_theme.Accent, 0.72f);
            using (SolidBrush b = new SolidBrush(bg)) e.Graphics.FillRectangle(b, e.Bounds);
            using (Pen p = new Pen(_theme.Border))
                e.Graphics.DrawLine(p, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);

            int textX = e.Bounds.Left + 8;
            if (e.ColumnIndex == 0 && lv.CheckBoxes)
            {
                int box = 17;
                int bx = e.Bounds.Left + 6;
                int by = e.Bounds.Top + (e.Bounds.Height - box) / 2;
                DrawCheck(e.Graphics, new Rectangle(bx, by, box, box), e.Item.Checked);
                textX = bx + box + 8;
            }

            Color fg = e.Item.ForeColor;
            if (fg.IsEmpty || fg.A == 0) fg = _theme.Text;
            Rectangle rt = new Rectangle(textX, e.Bounds.Top, e.Bounds.Right - textX - 6, e.Bounds.Height);
            TextRenderer.DrawText(e.Graphics, e.SubItem != null ? e.SubItem.Text : "", lv.Font, rt, fg,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
        }

        private void DrawCheck(Graphics g, Rectangle r, bool check)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (GraphicsPath gp = RoundedRect(r, 4))
            {
                using (SolidBrush b = new SolidBrush(check ? _theme.Accent : _theme.Surface))
                    g.FillPath(b, gp);
                using (Pen p = new Pen(check ? _theme.Accent : _theme.Border, 1.6f))
                    g.DrawPath(p, gp);
            }
            if (check)
                using (Pen p = new Pen(_theme.AccentText, 2.2f))
                {
                    p.StartCap = LineCap.Round; p.EndCap = LineCap.Round; p.LineJoin = LineJoin.Round;
                    g.DrawLines(p, new Point[] {
                        new Point(r.Left + 4, r.Top + 9),
                        new Point(r.Left + 7, r.Top + 12),
                        new Point(r.Left + 13, r.Top + 5) });
                }
            g.SmoothingMode = SmoothingMode.Default;
        }

        private void RoundControl(Control c, int radius)
        {
            try
            {
                if (c.Width <= 2 || c.Height <= 2) return;
                using (GraphicsPath gp = RoundedRect(new Rectangle(0, 0, c.Width, c.Height), radius))
                    c.Region = new Region(gp);
            }
            catch { }
        }

        // ---------- Навигация ----------
        private void ShowPage(int index)
        {
            _currentPage = index;
            for (int i = 0; i < _pages.Length; i++) _pages[i].Visible = (i == index);
            UpdateNav();
            FillColumns();
            RefreshCurrentPage(index);
        }

        // Авто-обновление списка при переходе на вкладку (лёгкие источники).
        private void RefreshCurrentPage(int index)
        {
            if (!_ready) return;
            try
            {
                switch (index)
                {
                    case 1: RefreshPorts(); break;    // Dev Cleanup — занятые порты
                    case 4: RefreshApps(); break;     // Программы
                    case 5: RefreshStartup(); break;  // Автозапуск
                    case 7: RefreshHistory(); break;  // История
                }
            }
            catch { }
        }

        private bool _ready;

        private void FillColumns()
        {
            AutoFillLastColumn(_lvScan);
            AutoFillLastColumn(_lvPorts);
            AutoFillLastColumn(_lvHistory);
            AutoFillLastColumn(_lvClean);
            AutoFillLastColumn(_lvApps);
        }

        private void UpdateNav()
        {
            if (_navButtons == null) return;
            for (int i = 0; i < _navButtons.Length; i++)
            {
                Button b = _navButtons[i];
                if (b == null) continue;
                b.UseVisualStyleBackColor = false;
                b.FlatAppearance.BorderSize = 0;
                b.BackColor = _theme.Bg;
                if (i == _currentPage)
                {
                    b.ForeColor = _theme.Accent;
                    b.FlatAppearance.MouseOverBackColor = _theme.Bg;
                }
                else
                {
                    b.ForeColor = _theme.Subtle;
                    b.FlatAppearance.MouseOverBackColor = _theme.Dark
                        ? ControlPaint.Light(_theme.Bg, 0.30f)
                        : ControlPaint.Dark(_theme.Bg, 0.04f);
                }
            }
            if (_navPanel != null) _navPanel.Invalidate();
        }

        // ---------- Тема ----------
        private void ApplyThemeAll()
        {
            BackColor = _theme.Bg;
            ForeColor = _theme.Text;
            ApplyThemeTo(this);
            Control nav = null;
            foreach (Control c in Controls) if (c.Name == "nav") { nav = c; break; }
            if (nav != null) nav.BackColor = _theme.Bg;
            UpdateNav();
            ApplyTitleBar();
            Invalidate();
        }

        private void ApplyTitleBar()
        {
            if (!IsHandleCreated) return;
            try
            {
                int on = _theme.Dark ? 1 : 0;
                if (Native.DwmSetWindowAttribute(Handle, Native.DWMWA_USE_IMMERSIVE_DARK_MODE, ref on, 4) != 0)
                    Native.DwmSetWindowAttribute(Handle, Native.DWMWA_USE_IMMERSIVE_DARK_MODE_OLD, ref on, 4);
            }
            catch { }
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            ApplyTitleBar();
        }

        private void ApplyThemeTo(Control root)
        {
            foreach (Control c in root.Controls)
            {
                if (c is Button)
                {
                    Button b = (Button)c;
                    b.FlatStyle = FlatStyle.Flat;
                    b.FlatAppearance.BorderSize = 1;
                    b.UseVisualStyleBackColor = false;
                    bool primary = (b.Tag as string) == "primary";
                    if (primary)
                    {
                        b.BackColor = _theme.Accent;
                        b.ForeColor = _theme.AccentText;
                        b.FlatAppearance.BorderColor = _theme.Accent;
                        b.FlatAppearance.MouseOverBackColor = ControlPaint.Light(_theme.Accent, 0.1f);
                    }
                    else
                    {
                        b.BackColor = _theme.Surface;
                        b.ForeColor = _theme.Text;
                        b.FlatAppearance.BorderColor = _theme.Border;
                        b.FlatAppearance.MouseOverBackColor = _theme.Dark
                            ? ControlPaint.Light(_theme.Surface, 0.15f)
                            : ControlPaint.Dark(_theme.Surface, 0.03f);
                    }
                    RoundControl(b, 8);
                }
                else if (c is RichTextBox)
                {
                    c.BackColor = _theme.Surface;
                    c.ForeColor = _theme.Text;
                }
                else if (c is TextBox)
                {
                    c.BackColor = _theme.Surface;
                    c.ForeColor = _theme.Text;
                    ((TextBox)c).BorderStyle = BorderStyle.FixedSingle;
                }
                else if (c is NumericUpDown)
                {
                    c.BackColor = _theme.Surface;
                    c.ForeColor = _theme.Text;
                    ((NumericUpDown)c).BorderStyle = BorderStyle.FixedSingle;
                }
                else if (c is ComboBox)
                {
                    c.BackColor = _theme.Surface;
                    c.ForeColor = _theme.Text;
                    ((ComboBox)c).FlatStyle = FlatStyle.Flat;
                }
                else if (c is ListView)
                {
                    c.BackColor = _theme.Surface;
                    c.ForeColor = _theme.Text;
                    ((ListView)c).BorderStyle = BorderStyle.FixedSingle;
                }
                else if (c is Label)
                {
                    c.BackColor = Color.Transparent;
                    if (c.Name == "section") c.ForeColor = _theme.Accent;
                    else if (c.Name == "warn" || c.Name == "muted") c.ForeColor = _theme.Subtle;
                    else c.ForeColor = _theme.Text;
                }
                else if (c is CheckBox)
                {
                    c.BackColor = Color.Transparent;
                    c.ForeColor = _theme.Text;
                }
                else if (c is TabControl)
                {
                    c.BackColor = _theme.Bg;
                    c.ForeColor = _theme.Text;
                }
                else if (c is TabPage || c is Panel || c is FlowLayoutPanel)
                {
                    c.BackColor = _theme.Bg;
                    c.ForeColor = _theme.Text;
                }
                if (c.Controls.Count > 0) ApplyThemeTo(c);
            }
        }

        // ---------- UI ----------
        private void BuildUi()
        {
            Text = "Windows Process Cleaner";
            Width = 1060;
            Height = 740;
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Segoe UI", 10.5F);
            MinimumSize = new Size(940, 620);
            Icon = _iconWindow;
            ShowIcon = true;

            // Собственная навигация вместо TabControl (полностью тематизируется).
            Panel nav = new Panel();
            nav.Dock = DockStyle.Top;
            nav.Height = 48;
            nav.Name = "nav";

            _content = new Panel();
            _content.Dock = DockStyle.Fill;

            _pages = new Control[] { BuildScanTab(), BuildDevTab(), BuildCleanTab(), BuildDockerTab(), BuildAppsTab(), BuildStartupTab(), BuildSettingsTab(), BuildHistoryTab() };
            string[] titles = { Tr.S("Сканирование", "Scan"), "Dev Cleanup", Tr.S("Очистка диска", "Disk Cleanup"), "Docker", Tr.S("Программы", "Programs"), Tr.S("Автозапуск", "Startup"), Tr.S("Настройки", "Settings"), Tr.S("История", "History") };
            int[] widths = { 130, 118, 128, 82, 115, 118, 110, 95 };
            _navButtons = new Button[titles.Length];
            int nx = 8;
            for (int i = 0; i < titles.Length; i++)
            {
                Button b = new Button();
                b.Text = titles[i];
                b.Left = nx; b.Top = 4; b.Width = widths[i]; b.Height = 40;
                b.FlatStyle = FlatStyle.Flat;
                b.FlatAppearance.BorderSize = 0;
                b.Font = new Font(Font, FontStyle.Bold);
                int idx = i;
                b.Click += delegate { ShowPage(idx); };
                nav.Controls.Add(b);
                _navButtons[i] = b;
                nx += widths[i] + 4;
            }
            _navPanel = nav;
            nav.Paint += delegate(object s, PaintEventArgs pe)
            {
                if (_navButtons == null || _currentPage < 0 || _currentPage >= _navButtons.Length) return;
                Button b = _navButtons[_currentPage];
                using (SolidBrush br = new SolidBrush(_theme.Accent))
                    pe.Graphics.FillRectangle(br, b.Left, nav.Height - 3, b.Width, 3);
                using (Pen pen = new Pen(_theme.Border))
                    pe.Graphics.DrawLine(pen, 0, nav.Height - 1, nav.Width, nav.Height - 1);
            };

            foreach (Control page in _pages)
            {
                page.Dock = DockStyle.Fill;
                page.Visible = false;
                _content.Controls.Add(page);
            }

            Controls.Add(_content);
            Controls.Add(nav);
            ShowPage(0);

            FormClosing += delegate(object s, FormClosingEventArgs e)
            {
                if (!_reallyExit && e.CloseReason == CloseReason.UserClosing)
                {
                    e.Cancel = true;
                    Hide();
                    _tray.ShowBalloonTip(2000, "Windows Process Cleaner",
                        Tr.S("Свёрнуто в трей. Работает в фоне.", "Minimized to tray. Running in background."), ToolTipIcon.Info);
                }
            };
        }

        private Button MkButton(string text, int x, int y, int w, bool primary)
        {
            Button b = new Button();
            b.Text = text;
            b.Left = x; b.Top = y; b.Width = w; b.Height = 36;
            if (primary) b.Tag = "primary";
            return b;
        }

        private Control BuildScanTab()
        {
            Panel tab = new Panel();
            tab.Padding = new Padding(14, 12, 14, 12);

            Panel top = new Panel();
            top.Dock = DockStyle.Top;
            top.Height = 128;

            // ряд 1
            Button btnScan = MkButton(Tr.S("Сканировать", "Scan"), 0, 6, 150, true);
            btnScan.Click += delegate { DoScan(); };
            Button btnSelAll = MkButton(Tr.S("Выбрать все", "Select all"), 160, 6, 130, false);
            btnSelAll.Click += delegate { SetAllChecks(true); };
            Button btnSelNone = MkButton(Tr.S("Снять выбор", "Clear"), 298, 6, 130, false);
            btnSelNone.Click += delegate { SetAllChecks(false); };

            _chkGlobal = new CheckBox();
            _chkGlobal.Text = Tr.S("Все процессы (глобально)", "All processes (global)");
            _chkGlobal.Left = 450; _chkGlobal.Top = 6; _chkGlobal.Width = 280; _chkGlobal.Height = 22;
            _chkGlobal.CheckedChanged += delegate
            {
                _engine.Config.GlobalScan = _chkGlobal.Checked;
                _engine.SaveConfig();
            };
            Label lblWarn = new Label();
            lblWarn.Name = "warn";
            lblWarn.Text = Tr.S("⚠ завершает любые ваши простаивающие/осиротевшие процессы",
                                "⚠ terminates any of your idle/orphaned processes");
            lblWarn.Left = 450; lblWarn.Top = 30; lblWarn.Width = 460; lblWarn.Height = 18;
            lblWarn.Font = new Font(Font.FontFamily, 9.5F);
            lblWarn.AutoEllipsis = true;

            // ряд 2
            Button btnClean = MkButton(Tr.S("Очистить выбранные", "Clean selected"), 0, 52, 200, true);
            btnClean.Click += delegate { DoClean(); };
            Button btnAuto = MkButton(Tr.S("Автоочистка всех неактивных", "Auto-clean all inactive"), 210, 52, 250, true);
            btnAuto.Click += delegate { DoAutoCleanButton(); };
            Button btnPurge = MkButton(Tr.S("Очистить память", "Purge memory"), 470, 52, 170, false);
            btnPurge.Click += delegate { DoPurgeOnly(); };

            top.Controls.Add(btnScan);
            top.Controls.Add(btnSelAll);
            top.Controls.Add(btnSelNone);
            top.Controls.Add(_chkGlobal);
            top.Controls.Add(lblWarn);
            _lblSummary = new Label();
            _lblSummary.Left = 0; _lblSummary.Top = 98; _lblSummary.Width = 980; _lblSummary.Height = 26;
            _lblSummary.TextAlign = ContentAlignment.MiddleLeft;
            _lblSummary.Text = Tr.S("Нажмите «Сканировать»", "Click “Scan”");

            top.Controls.Add(btnClean);
            top.Controls.Add(btnAuto);
            top.Controls.Add(btnPurge);
            top.Controls.Add(_lblSummary);

            _lvScan = new ListView();
            _lvScan.Dock = DockStyle.Fill;
            _lvScan.View = View.Details;
            _lvScan.CheckBoxes = true;
            _lvScan.FullRowSelect = true;
            _lvScan.Columns.Add(Tr.S("Категория", "Category"), 120);
            _lvScan.Columns.Add(Tr.S("Имя", "Name"), 130);
            _lvScan.Columns.Add("PID", 65);
            _lvScan.Columns.Add("PPID", 65);
            _lvScan.Columns.Add("CPU %", 65);
            _lvScan.Columns.Add("RAM", 85);
            _lvScan.Columns.Add(Tr.S("Простой", "Idle"), 80);
            _lvScan.Columns.Add(Tr.S("Окно", "Window"), 55);
            _lvScan.Columns.Add(Tr.S("Порт", "Port"), 55);
            _lvScan.Columns.Add(Tr.S("Дети", "Children"), 55);
            _lvScan.Columns.Add(Tr.S("Статус", "Status"), 330);
            SetupOwnerDraw(_lvScan);

            _lblResult = new Label();
            _lblResult.Dock = DockStyle.Bottom;
            _lblResult.Height = 32;
            _lblResult.TextAlign = ContentAlignment.MiddleLeft;
            _lblResult.Padding = new Padding(2, 0, 0, 0);
            _lblResult.Text = "";

            tab.Controls.Add(_lvScan);
            tab.Controls.Add(_lblResult);
            tab.Controls.Add(top);
            return tab;
        }

        private Control BuildDevTab()
        {
            Panel tab = new Panel();
            tab.Padding = new Padding(14, 12, 14, 12);

            FlowLayoutPanel flow = new FlowLayoutPanel();
            flow.Dock = DockStyle.Top;
            flow.Height = 140;
            flow.Padding = new Padding(6);

            AddDevButton(flow, Tr.S("Все Node", "All Node"), new string[] { "node.exe", "next.exe" });
            AddDevButton(flow, Tr.S("Все Python", "All Python"), new string[] { "python.exe", "pythonw.exe" });
            AddDevButton(flow, Tr.S("Все Java", "All Java"), new string[] { "java.exe", "gradle.exe" });
            AddDevButton(flow, Tr.S("Все Vite", "All Vite"), new string[] { "vite.exe" });
            AddDevButton(flow, Tr.S("Все Webpack", "All Webpack"), new string[] { "webpack.exe" });
            AddDevButton(flow, Tr.S("Весь npm", "All npm"), new string[] { "npm.exe" });
            AddDevButton(flow, Tr.S("Весь pnpm", "All pnpm"), new string[] { "pnpm.exe" });
            AddDevButton(flow, Tr.S("Весь yarn/bun", "All yarn/bun"), new string[] { "yarn.exe", "bun.exe" });
            AddDevButton(flow, "Docker Compose", new string[] { "docker-compose.exe", "docker.exe" });
            AddDevButton(flow, "Go / Cargo / Deno", new string[] { "go.exe", "cargo.exe", "deno.exe" });

            Panel portsBar = new Panel();
            portsBar.Dock = DockStyle.Top;
            portsBar.Height = 40;
            Label lblP = new Label();
            lblP.Text = Tr.S("Занятые dev-порты:", "Busy dev ports:");
            lblP.Left = 8; lblP.Top = 12; lblP.Width = 160;
            Button btnRefresh = new Button();
            btnRefresh.Text = Tr.S("Обновить", "Refresh");
            btnRefresh.Left = 170; btnRefresh.Top = 8; btnRefresh.Width = 100; btnRefresh.Height = 26;
            btnRefresh.Click += delegate { RefreshPorts(); };
            Button btnKillPort = new Button();
            btnKillPort.Text = Tr.S("Завершить выбранные порты", "Kill selected ports");
            btnKillPort.Left = 278; btnKillPort.Top = 8; btnKillPort.Width = 220; btnKillPort.Height = 26;
            btnKillPort.Click += delegate { KillSelectedPorts(); };
            portsBar.Controls.Add(lblP);
            portsBar.Controls.Add(btnRefresh);
            portsBar.Controls.Add(btnKillPort);

            _lvPorts = new ListView();
            _lvPorts.Dock = DockStyle.Fill;
            _lvPorts.View = View.Details;
            _lvPorts.CheckBoxes = true;
            _lvPorts.FullRowSelect = true;
            _lvPorts.Columns.Add(Tr.S("Порт", "Port"), 90);
            _lvPorts.Columns.Add("PID", 90);
            _lvPorts.Columns.Add(Tr.S("Процесс", "Process"), 340);
            SetupOwnerDraw(_lvPorts);

            tab.Controls.Add(_lvPorts);
            tab.Controls.Add(portsBar);
            tab.Controls.Add(flow);
            return tab;
        }

        private void AddDevButton(FlowLayoutPanel flow, string title, string[] names)
        {
            Button b = new Button();
            b.Text = title;
            b.Width = 150; b.Height = 32;
            b.Margin = new Padding(4);
            b.Click += delegate
            {
                long freed;
                int n = _engine.TerminateByNames(names, out freed);
                string msg = Tr.S("Завершено: ", "Terminated: ") + n + Tr.S(" · освобождено ~", " · freed ~") + Engine.FormatBytes(freed);
                _tray.ShowBalloonTip(2000, title, msg, ToolTipIcon.Info);
                MessageBox.Show(msg, title, MessageBoxButtons.OK, MessageBoxIcon.Information);
            };
            flow.Controls.Add(b);
        }

        private Control BuildSettingsTab()
        {
            Panel tab = new Panel();
            tab.Padding = new Padding(18, 14, 18, 14);

            // ---- ЛЕВАЯ КОЛОНКА ----
            int lx = 18, cx = 280, y = 8;
            SectionHeader(tab, Tr.S("Критерии заброшенности", "Abandonment criteria"), lx, ref y);
            _numCpu = MakeNum(tab, Tr.S("Порог CPU, %:", "CPU threshold, %:"), lx, cx, ref y, 0, 100, 2, 0.1M);
            _numIdle = MakeNum(tab, Tr.S("Время простоя, мин:", "Idle time, min:"), lx, cx, ref y, 0, 1440, 0, 1);
            _numMinLife = MakeNum(tab, Tr.S("Мин. время жизни, мин:", "Min lifetime, min:"), lx, cx, ref y, 0, 1440, 0, 1);
            _numGlobalIdle = MakeNum(tab, Tr.S("Простой для глобального режима, мин:", "Idle for global mode, min:"), lx, cx, ref y, 1, 1440, 0, 1);

            y += 12;
            SectionHeader(tab, Tr.S("Автоматизация", "Automation"), lx, ref y);
            _numInterval = MakeNum(tab, Tr.S("Автоочистка каждые (часов, 1..24):", "Auto-clean every (hours, 1..24):"), lx, cx, ref y, 1, 24, 0, 1);
            _chkAuto = MakeCheck(tab, Tr.S("Включить автоочистку по таймеру", "Enable auto-clean timer"), lx, ref y);
            _chkExcludeInstalled = MakeCheck(tab, Tr.S("Глобально: не трогать Program Files", "Global: don't touch Program Files"), lx, ref y);
            _chkAutostart = MakeCheck(tab, Tr.S("Запускать вместе с Windows", "Start with Windows"), lx, ref y);
            _chkStartMin = MakeCheck(tab, Tr.S("Стартовать свёрнутым в трей", "Start minimized to tray"), lx, ref y);

            y += 12;
            SectionHeader(tab, Tr.S("Оформление", "Appearance"), lx, ref y);
            Label lblTheme = new Label();
            lblTheme.Text = Tr.S("Тема оформления:", "Theme:"); lblTheme.Left = lx; lblTheme.Top = y + 4; lblTheme.Width = 250;
            tab.Controls.Add(lblTheme);
            _cmbTheme = new ComboBox();
            _cmbTheme.DropDownStyle = ComboBoxStyle.DropDownList;
            _cmbTheme.Left = cx; _cmbTheme.Top = y; _cmbTheme.Width = 200;
            _cmbTheme.Items.AddRange(new object[] { Tr.S("По системе", "System"), Tr.S("Светлая", "Light"), Tr.S("Тёмная", "Dark") });
            _cmbTheme.SelectedIndexChanged += delegate { PreviewTheme(); };
            tab.Controls.Add(_cmbTheme);
            y += 36;

            Label lblLang = new Label();
            lblLang.Text = "Язык / Language:"; lblLang.Left = lx; lblLang.Top = y + 4; lblLang.Width = 250;
            tab.Controls.Add(lblLang);
            _cmbLang = new ComboBox();
            _cmbLang.DropDownStyle = ComboBoxStyle.DropDownList;
            _cmbLang.Left = cx; _cmbLang.Top = y; _cmbLang.Width = 200;
            _cmbLang.Items.AddRange(new object[] { "Русский", "English" });
            tab.Controls.Add(_cmbLang);
            y += 40;
            int leftBottom = y;

            // ---- ПРАВАЯ КОЛОНКА ----
            int rx = 540, ry = 8, rw = 400;
            SectionHeader(tab, Tr.S("Списки", "Lists"), rx, ref ry);
            AddLabel(tab, Tr.S("Отслеживаемые процессы (по одному в строке):", "Watched processes (one per line):"), rx, ref ry);
            _txtWatch = MakeMultilineAt(tab, rx, ref ry, rw, 150);
            AddLabel(tab, Tr.S("Белый список — никогда не завершать:", "Whitelist — never terminate:"), rx, ref ry);
            _txtWhite = MakeMultilineAt(tab, rx, ref ry, rw, 150);
            AddLabel(tab, Tr.S("Dev-порты (через запятую):", "Dev ports (comma-separated):"), rx, ref ry);
            _txtPorts = new TextBox();
            _txtPorts.Left = rx; _txtPorts.Top = ry; _txtPorts.Width = rw;
            tab.Controls.Add(_txtPorts);
            ry += 36;

            // ---- КНОПКИ ----
            int by = Math.Max(leftBottom, ry) + 14;
            Button save = new Button();
            save.Text = Tr.S("Сохранить настройки", "Save settings");
            save.Tag = "primary";
            save.Left = lx; save.Top = by; save.Width = 210; save.Height = 36;
            save.Click += delegate { SaveSettingsFromUi(); };
            tab.Controls.Add(save);

            Button openDir = new Button();
            openDir.Text = Tr.S("Папка данных", "Data folder");
            openDir.Left = lx + 222; openDir.Top = by; openDir.Width = 160; openDir.Height = 36;
            openDir.Click += delegate { try { Process.Start("explorer.exe", _engine.DataDir); } catch { } };
            tab.Controls.Add(openDir);

            return tab;
        }

        private void SectionHeader(Panel tab, string text, int lx, ref int y)
        {
            Label l = new Label();
            l.Text = text; l.Left = lx; l.Top = y; l.AutoSize = true;
            l.Font = new Font(Font.FontFamily, 11F, FontStyle.Bold);
            l.Name = "section";
            tab.Controls.Add(l);
            y += 30;
        }

        private NumericUpDown MakeNum(Panel tab, string label, int lx, int cx, ref int y,
            decimal min, decimal max, int dec, decimal step)
        {
            Label l = new Label();
            l.Text = label; l.Left = lx; l.Top = y + 4; l.Width = cx - lx - 8;
            tab.Controls.Add(l);
            NumericUpDown n = new NumericUpDown();
            n.Left = cx; n.Top = y; n.Width = 120;
            n.Minimum = min; n.Maximum = max; n.DecimalPlaces = dec; n.Increment = step;
            tab.Controls.Add(n);
            y += 34;
            return n;
        }

        private CheckBox MakeCheck(Panel tab, string label, int lx, ref int y)
        {
            CheckBox c = new CheckBox();
            c.Text = label; c.Left = lx; c.Top = y; c.Width = 480; c.Height = 24;
            tab.Controls.Add(c);
            y += 30;
            return c;
        }

        private void AddLabel(Panel tab, string text, int lx, ref int y)
        {
            Label l = new Label();
            l.Text = text; l.Left = lx; l.Top = y; l.Width = 500; l.Height = 20;
            tab.Controls.Add(l);
            y += 24;
        }

        private TextBox MakeMultilineAt(Panel tab, int lx, ref int y, int w, int h)
        {
            TextBox t = new TextBox();
            t.Multiline = true; t.ScrollBars = ScrollBars.Vertical;
            t.Left = lx; t.Top = y; t.Width = w; t.Height = h;
            tab.Controls.Add(t);
            y += h + 12;
            return t;
        }

        private Control BuildHistoryTab()
        {
            Panel tab = new Panel();
            Panel bar = new Panel();
            bar.Dock = DockStyle.Top; bar.Height = 40;
            Button refresh = new Button();
            refresh.Text = Tr.S("Обновить", "Refresh"); refresh.Left = 8; refresh.Top = 8; refresh.Width = 100; refresh.Height = 26;
            refresh.Click += delegate { RefreshHistory(); };
            bar.Controls.Add(refresh);

            _lvHistory = new ListView();
            _lvHistory.Dock = DockStyle.Fill;
            _lvHistory.View = View.Details;
            _lvHistory.FullRowSelect = true;
            _lvHistory.Columns.Add(Tr.S("Дата и время", "Date and time"), 175);
            _lvHistory.Columns.Add(Tr.S("Завершено", "Terminated"), 100);
            _lvHistory.Columns.Add(Tr.S("Освобождено", "Freed"), 120);
            _lvHistory.Columns.Add(Tr.S("Процессы", "Processes"), 460);
            SetupOwnerDraw(_lvHistory);

            tab.Controls.Add(_lvHistory);
            tab.Controls.Add(bar);
            return tab;
        }

        // ---------- Вкладка: Очистка диска ----------
        private Control BuildCleanTab()
        {
            Panel tab = new Panel();
            tab.Padding = new Padding(14, 12, 14, 12);

            Panel top = new Panel();
            top.Dock = DockStyle.Top;
            top.Height = 96;

            Button btnAnalyze = MkButton(Tr.S("Анализировать", "Analyze"), 0, 6, 160, true);
            btnAnalyze.Click += delegate { DoAnalyzeDisk(); };
            Button btnClean = MkButton(Tr.S("Удалить выбранное", "Delete selected"), 170, 6, 200, true);
            btnClean.Click += delegate { DoCleanDisk(); };
            Button btnAll = MkButton(Tr.S("Выбрать все", "Select all"), 380, 6, 130, false);
            btnAll.Click += delegate { foreach (ListViewItem it in _lvClean.Items) it.Checked = true; };
            Button btnNone = MkButton(Tr.S("Снять выбор", "Clear"), 518, 6, 130, false);
            btnNone.Click += delegate { foreach (ListViewItem it in _lvClean.Items) it.Checked = false; };

            Label warn = new Label();
            warn.Name = "muted";
            warn.Text = Tr.S("⚠ Файлы удаляются безвозвратно. Код, проекты, DriverStore и системные папки не трогаются. Закройте браузеры для полной очистки их кэша.",
                             "⚠ Files are deleted permanently. Code, projects, DriverStore and system folders are never touched. Close browsers to fully clear their cache.");
            warn.Left = 0; warn.Top = 48; warn.Width = 980; warn.Height = 18;
            warn.Font = new Font(Font.FontFamily, 9.5F);
            warn.AutoEllipsis = true;

            _lblCleanTotal = new Label();
            _lblCleanTotal.Left = 0; _lblCleanTotal.Top = 70; _lblCleanTotal.Width = 980; _lblCleanTotal.Height = 24;
            _lblCleanTotal.Text = Tr.S("Нажмите «Анализировать»", "Click “Analyze”");

            top.Controls.Add(btnAnalyze);
            top.Controls.Add(btnClean);
            top.Controls.Add(btnAll);
            top.Controls.Add(btnNone);
            top.Controls.Add(warn);
            top.Controls.Add(_lblCleanTotal);

            _lvClean = new ListView();
            _lvClean.Dock = DockStyle.Fill;
            _lvClean.View = View.Details;
            _lvClean.CheckBoxes = true;
            _lvClean.FullRowSelect = true;
            _lvClean.Columns.Add(Tr.S("Категория", "Category"), 230);
            _lvClean.Columns.Add(Tr.S("Размер", "Size"), 110);
            _lvClean.Columns.Add(Tr.S("Файлов", "Files"), 90);
            _lvClean.Columns.Add(Tr.S("Что чистится", "What is cleaned"), 520);
            SetupOwnerDraw(_lvClean);

            tab.Controls.Add(_lvClean);
            tab.Controls.Add(top);
            return tab;
        }

        private void DoAnalyzeDisk()
        {
            _lblCleanTotal.Text = Tr.S("Анализ… (может занять время для больших кэшей)",
                                       "Analyzing… (may take a while for large caches)");
            _lvClean.Items.Clear();
            Cursor = Cursors.WaitCursor;
            List<CleanCategory> cats = _engine.BuildCleanCategories();
            Thread t = new Thread(delegate()
            {
                foreach (CleanCategory c in cats) { try { _engine.AnalyzeCategory(c); } catch { } }
                try { BeginInvoke((MethodInvoker)delegate { PopulateClean(cats); }); } catch { }
            });
            t.IsBackground = true;
            t.Start();
        }

        private void PopulateClean(List<CleanCategory> cats)
        {
            _cleanCats = cats;
            _lvClean.Items.Clear();
            long total = 0;
            foreach (CleanCategory c in cats)
            {
                ListViewItem it = new ListViewItem(c.Title);
                it.SubItems.Add(Engine.FormatBytes(c.Size));
                it.SubItems.Add(c.FileCount.ToString());
                it.SubItems.Add(c.Desc);
                it.Tag = c;
                it.ForeColor = _theme.Text;
                it.BackColor = _theme.Surface;
                it.Checked = c.Recommended && c.Size > 0;
                _lvClean.Items.Add(it);
                total += c.Size;
            }
            _lblCleanTotal.Text = Tr.S("Всего мусора найдено: ", "Total junk found: ") + Engine.FormatBytes(total) +
                Tr.S("   ·   отметьте категории и нажмите «Удалить выбранное»",
                     "   ·   check categories and click “Delete selected”");
            Cursor = Cursors.Default;
        }

        private void DoCleanDisk()
        {
            if (_cleanCats == null) { MessageBox.Show(Tr.S("Сначала нажмите «Анализировать».", "Click “Analyze” first.")); return; }
            List<CleanCategory> sel = new List<CleanCategory>();
            long size = 0;
            foreach (ListViewItem it in _lvClean.Items)
                if (it.Checked && it.Tag is CleanCategory) { CleanCategory c = (CleanCategory)it.Tag; sel.Add(c); size += c.Size; }
            if (sel.Count == 0) { MessageBox.Show(Tr.S("Не выбрано ни одной категории.", "No categories selected.")); return; }

            DialogResult dr = MessageBox.Show(
                Tr.S("Удалить ", "Delete ") + Engine.FormatBytes(size) +
                Tr.S(" в " + sel.Count + " категориях?\r\nДействие необратимо (файлы удаляются мимо Корзины).",
                     " across " + sel.Count + " categories?\r\nThis is irreversible (files bypass the Recycle Bin)."),
                Tr.S("Очистка диска", "Disk Cleanup"), MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (dr != DialogResult.Yes) return;

            _lblCleanTotal.Text = Tr.S("Удаление…", "Deleting…");
            Cursor = Cursors.WaitCursor;
            Thread t = new Thread(delegate()
            {
                CleanResult res = _engine.CleanCategories(sel);
                try
                {
                    BeginInvoke((MethodInvoker)delegate
                    {
                        Cursor = Cursors.Default;
                        _lblCleanTotal.Text = Tr.S("✓ Освобождено: ", "✓ Freed: ") + Engine.FormatBytes(res.Freed) +
                            (res.Errors > 0 ? Tr.S("   ·   пропущено (заняты/нет доступа): ", "   ·   skipped (locked/no access): ") + res.Errors : "");
                        _tray.ShowBalloonTip(3000, Tr.S("Очистка диска", "Disk Cleanup"),
                            Tr.S("Освобождено ~", "Freed ~") + Engine.FormatBytes(res.Freed), ToolTipIcon.Info);
                        DoAnalyzeDisk();
                    });
                }
                catch { }
            });
            t.IsBackground = true;
            t.Start();
        }

        // ---------- Вкладка: Программы (деинсталляция) ----------
        private Control BuildAppsTab()
        {
            Panel tab = new Panel();
            tab.Padding = new Padding(14, 12, 14, 12);

            Panel top = new Panel();
            top.Dock = DockStyle.Top;
            top.Height = 84;

            Button btnRefresh = MkButton(Tr.S("Обновить список", "Refresh list"), 0, 6, 170, true);
            btnRefresh.Click += delegate { RefreshApps(); };
            Button btnUninstall = MkButton(Tr.S("Удалить выбранное", "Uninstall selected"), 180, 6, 200, true);
            btnUninstall.Click += delegate { DoUninstall(); };

            Label warn = new Label();
            warn.Name = "muted";
            warn.Text = Tr.S("Запускается штатный деинсталлятор программы (может открыть своё окно/запросить подтверждение).",
                             "Launches the program's own uninstaller (may open its own window / ask for confirmation).");
            warn.Left = 0; warn.Top = 46; warn.Width = 980; warn.Height = 18;
            warn.Font = new Font(Font.FontFamily, 9.5F);
            warn.AutoEllipsis = true;

            _lblAppsInfo = new Label();
            _lblAppsInfo.Left = 0; _lblAppsInfo.Top = 64; _lblAppsInfo.Width = 980; _lblAppsInfo.Height = 20;
            _lblAppsInfo.Text = Tr.S("Нажмите «Обновить список»", "Click “Refresh list”");

            top.Controls.Add(btnRefresh);
            top.Controls.Add(btnUninstall);
            top.Controls.Add(warn);
            top.Controls.Add(_lblAppsInfo);

            _lvApps = new ListView();
            _lvApps.Dock = DockStyle.Fill;
            _lvApps.View = View.Details;
            _lvApps.CheckBoxes = true;
            _lvApps.FullRowSelect = true;
            _lvApps.Columns.Add(Tr.S("Программа", "Program"), 340);
            _lvApps.Columns.Add(Tr.S("Версия", "Version"), 130);
            _lvApps.Columns.Add(Tr.S("Издатель", "Publisher"), 260);
            _lvApps.Columns.Add(Tr.S("Размер", "Size"), 100);
            SetupOwnerDraw(_lvApps);

            tab.Controls.Add(_lvApps);
            tab.Controls.Add(top);
            return tab;
        }

        private void RefreshApps()
        {
            Cursor = Cursors.WaitCursor;
            try { _apps = _engine.GetInstalledApps(); }
            finally { Cursor = Cursors.Default; }
            _lvApps.Items.Clear();
            foreach (InstalledApp a in _apps)
            {
                ListViewItem it = new ListViewItem(a.Name);
                it.SubItems.Add(a.Version ?? "");
                it.SubItems.Add(a.Publisher ?? "");
                it.SubItems.Add(a.EstimatedSizeBytes > 0 ? Engine.FormatBytes(a.EstimatedSizeBytes) : "");
                it.ToolTipText = a.Name + (string.IsNullOrEmpty(a.ExePath) ? "" : "\r\n" + a.ExePath);
                it.Tag = a;
                it.ForeColor = _theme.Text;
                it.BackColor = _theme.Surface;
                _lvApps.Items.Add(it);
            }
            _lblAppsInfo.Text = Tr.S("Установленных программ: ", "Installed programs: ") + _apps.Count +
                Tr.S("   ·   отметьте и нажмите «Удалить выбранное»", "   ·   check and click “Uninstall selected”");
        }

        private void DoUninstall()
        {
            List<InstalledApp> sel = new List<InstalledApp>();
            foreach (ListViewItem it in _lvApps.Items)
                if (it.Checked && it.Tag is InstalledApp) sel.Add((InstalledApp)it.Tag);
            if (sel.Count == 0) { MessageBox.Show(Tr.S("Не выбрано ни одной программы.", "No programs selected.")); return; }

            foreach (InstalledApp a in sel)
            {
                DialogResult dr = MessageBox.Show(Tr.S("Удалить «", "Uninstall “") + a.Name + Tr.S("»?", "”?"),
                    Tr.S("Деинсталляция", "Uninstall"), MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (dr != DialogResult.Yes) continue;
                try { _engine.RunUninstall(a); }
                catch (Exception ex) { MessageBox.Show(Tr.S("Не удалось запустить деинсталлятор: ", "Failed to launch uninstaller: ") + ex.Message); }
            }
            _lblAppsInfo.Text = Tr.S("Деинсталляторы запущены. Обновите список после завершения.",
                                     "Uninstallers launched. Refresh the list when done.");
        }

        // ---------- Вкладка: Docker ----------
        private Control BuildDockerTab()
        {
            Panel tab = new Panel();
            tab.Padding = new Padding(14, 12, 14, 12);

            FlowLayoutPanel flow = new FlowLayoutPanel();
            flow.Dock = DockStyle.Top;
            flow.Height = 130;

            AddDockerButton(flow, Tr.S("Обзор занятого места", "Disk usage (df)"), "system df", false);
            AddDockerButton(flow, Tr.S("Подробно (df -v)", "Details (df -v)"), "system df -v", false);
            AddDockerButton(flow, Tr.S("Удалить остановленные контейнеры", "Remove stopped containers"), "container prune -f", true);
            AddDockerButton(flow, Tr.S("Удалить неиспользуемые образы", "Remove unused images"), "image prune -a -f", true);
            AddDockerButton(flow, Tr.S("Удалить неиспользуемые тома", "Remove unused volumes"), "volume prune -f", true);
            AddDockerButton(flow, Tr.S("Очистить кэш сборки", "Clear build cache"), "builder prune -a -f", true);
            AddDockerButton(flow, Tr.S("Полная очистка", "Full cleanup"), "system prune -a -f --volumes", true);

            Button bCompact = new Button();
            bCompact.Text = Tr.S("Сжать диск Docker (вернуть место Windows)", "Compact Docker disk (reclaim Windows space)");
            bCompact.Width = 340; bCompact.Height = 34; bCompact.Margin = new Padding(4);
            bCompact.Tag = "primary";
            bCompact.Click += delegate { DoCompactDocker(); };
            flow.Controls.Add(bCompact);

            Label note = new Label();
            note.Name = "muted";
            note.Dock = DockStyle.Top;
            note.Height = 58;
            note.Text = Tr.S(
                "Удаляется только НЕиспользуемое (prune): остановленные контейнеры, образы без тегов/ссылок, " +
                "тома без владельцев, кэш сборки. Запущенные контейнеры и используемые образы не трогаются.\r\n" +
                "⚠ prune освобождает место ВНУТРИ виртуального диска Docker, но сам файл на Windows не уменьшается. " +
                "Чтобы реально вернуть место на диске Windows — «Сжать диск Docker» (остановит Docker и сожмёт vhdx).\r\n" +
                "Kubernetes не включён: его очистка бьёт по живому кластеру.",
                "Only UNUSED data is removed (prune): stopped containers, dangling/unreferenced images, " +
                "unused volumes, build cache. Running containers and used images are never touched.\r\n" +
                "⚠ prune frees space INSIDE Docker's virtual disk, but the file on Windows doesn't shrink. " +
                "To actually reclaim Windows disk space use “Compact Docker disk” (stops Docker and compacts the vhdx).\r\n" +
                "Kubernetes is not included: its cleanup affects a live cluster.");
            note.Font = new Font(Font.FontFamily, 9.5F);

            _txtDocker = new RichTextBox();
            _txtDocker.Dock = DockStyle.Fill;
            _txtDocker.ReadOnly = true;
            _txtDocker.WordWrap = false;
            _txtDocker.BorderStyle = BorderStyle.FixedSingle;
            _txtDocker.Font = new Font("Consolas", 10F);
            _txtDocker.Text = Tr.S(
                "Нажмите «Обзор занятого места», чтобы увидеть, сколько занимает Docker.\r\n" +
                "Требуется установленный Docker CLI (Docker Desktop) и запущенный демон.",
                "Click “Disk usage (df)” to see how much space Docker uses.\r\n" +
                "Requires an installed Docker CLI (Docker Desktop) and a running daemon.");

            tab.Controls.Add(_txtDocker);
            tab.Controls.Add(note);
            tab.Controls.Add(flow);
            return tab;
        }

        private void AddDockerButton(FlowLayoutPanel flow, string title, string args, bool destructive)
        {
            Button b = new Button();
            b.Text = title;
            b.Width = 230; b.Height = 34;
            b.Margin = new Padding(4);
            b.Click += delegate { RunDocker(title, args, destructive); };
            flow.Controls.Add(b);
        }

        private void RunDocker(string title, string args, bool destructive)
        {
            if (destructive)
            {
                DialogResult dr = MessageBox.Show(
                    Tr.S("Выполнить: docker " + args + " ?\r\nБудут удалены неиспользуемые данные Docker.",
                         "Run: docker " + args + " ?\r\nUnused Docker data will be removed."),
                    "Docker", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
                if (dr != DialogResult.Yes) return;
            }
            _txtDocker.Text = Tr.S("Выполняется: docker ", "Running: docker ") + args + " …";
            Cursor = Cursors.WaitCursor;
            Thread t = new Thread(delegate()
            {
                string res = _engine.Docker(args);
                try
                {
                    BeginInvoke((MethodInvoker)delegate
                    {
                        Cursor = Cursors.Default;
                        _txtDocker.Text = res;
                    });
                }
                catch { }
            });
            t.IsBackground = true;
            t.Start();
        }

        private void DoCompactDocker()
        {
            DialogResult dr = MessageBox.Show(
                Tr.S("Будет остановлен Docker (все запущенные контейнеры завершатся!) и сжат его виртуальный диск, " +
                     "чтобы вернуть свободное место на диске Windows.\r\n\r\nПродолжить?",
                     "Docker will be stopped (all running containers will exit!) and its virtual disk compacted " +
                     "to reclaim free space on the Windows disk.\r\n\r\nContinue?"),
                "Docker", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (dr != DialogResult.Yes) return;

            _txtDocker.Text = Tr.S("Сжатие диска Docker… это может занять минуту, не закрывайте окно.",
                                   "Compacting Docker disk… this may take a minute, don't close the window.");
            Cursor = Cursors.WaitCursor;
            Thread t = new Thread(delegate()
            {
                string res = _engine.CompactDockerDisk();
                try
                {
                    BeginInvoke((MethodInvoker)delegate
                    {
                        Cursor = Cursors.Default;
                        _txtDocker.Text = res;
                    });
                }
                catch { }
            });
            t.IsBackground = true;
            t.Start();
        }

        // ---------- Вкладка: Автозапуск ----------
        private Control BuildStartupTab()
        {
            Panel tab = new Panel();
            tab.Padding = new Padding(14, 12, 14, 12);

            Panel top = new Panel();
            top.Dock = DockStyle.Top;
            top.Height = 84;

            Button btnRefresh = MkButton(Tr.S("Обновить список", "Refresh list"), 0, 6, 170, true);
            btnRefresh.Click += delegate { RefreshStartup(); };

            Label warn = new Label();
            warn.Name = "muted";
            warn.Text = Tr.S("Галочка = программа в автозапуске Windows. Поставьте — добавить, снимите — убрать. По умолчанию выкл.",
                             "Checkbox = program is in Windows startup. Check to add, uncheck to remove. Off by default.");
            warn.Left = 0; warn.Top = 46; warn.Width = 980; warn.Height = 18;
            warn.Font = new Font(Font.FontFamily, 9.5F);
            warn.AutoEllipsis = true;

            _lblStartupInfo = new Label();
            _lblStartupInfo.Left = 0; _lblStartupInfo.Top = 64; _lblStartupInfo.Width = 980; _lblStartupInfo.Height = 20;
            _lblStartupInfo.Text = Tr.S("Нажмите «Обновить список»", "Click “Refresh list”");

            top.Controls.Add(btnRefresh);
            top.Controls.Add(warn);
            top.Controls.Add(_lblStartupInfo);

            _lvStartup = new ListView();
            _lvStartup.Dock = DockStyle.Fill;
            _lvStartup.View = View.Details;
            _lvStartup.CheckBoxes = true;
            _lvStartup.FullRowSelect = true;
            _lvStartup.Columns.Add(Tr.S("Программа", "Program"), 300);
            _lvStartup.Columns.Add(Tr.S("Издатель / источник", "Publisher / source"), 220);
            _lvStartup.Columns.Add(Tr.S("Файл автозапуска", "Startup target"), 460);
            SetupOwnerDraw(_lvStartup);
            _lvStartup.ItemChecked += Startup_ItemChecked;

            tab.Controls.Add(_lvStartup);
            tab.Controls.Add(top);
            return tab;
        }

        private void RefreshStartup()
        {
            Cursor = Cursors.WaitCursor;
            List<InstalledApp> apps;
            List<AutostartEntry> entries;
            try
            {
                apps = _engine.GetInstalledApps();
                entries = _engine.GetAutostartEntries();
            }
            finally { Cursor = Cursors.Default; }

            _suppressStartup = true;
            _lvStartup.Items.Clear();

            HashSet<string> appExes = new HashSet<string>();
            int onCount = 0;
            foreach (InstalledApp a in apps)
            {
                bool on = _engine.IsExeInAutostart(a.ExePath, entries);
                a.InAutostart = on;
                if (!string.IsNullOrEmpty(a.ExePath)) appExes.Add(a.ExePath.ToLowerInvariant());

                ListViewItem it = new ListViewItem(a.Name);
                it.SubItems.Add(a.Publisher != null ? a.Publisher : "");
                it.SubItems.Add(a.ExePath != null ? a.ExePath : Tr.S("(exe не найден)", "(exe not found)"));
                it.ToolTipText = a.Name + (string.IsNullOrEmpty(a.ExePath) ? "" : "\r\n" + a.ExePath);
                it.Tag = a;
                it.Checked = on;
                it.ForeColor = _theme.Text;
                it.BackColor = _theme.Surface;
                _lvStartup.Items.Add(it);
                if (on) onCount++;
            }

            // записи автозапуска, не сопоставленные с установленными программами
            foreach (AutostartEntry e in entries)
            {
                string ep = e.ExePath != null ? e.ExePath.ToLowerInvariant() : null;
                if (ep != null && appExes.Contains(ep)) continue;
                ListViewItem it = new ListViewItem(e.Name);
                it.SubItems.Add(e.SourceLabel != null ? e.SourceLabel : "");
                it.SubItems.Add(e.Command != null ? e.Command : "");
                it.ToolTipText = e.Name + "\r\n" + (e.Command != null ? e.Command : "");
                it.Tag = e;
                it.Checked = true;
                it.ForeColor = _theme.Text;
                it.BackColor = _theme.CandidateBg;
                _lvStartup.Items.Add(it);
                onCount++;
            }

            _suppressStartup = false;
            _lblStartupInfo.Text = Tr.S("Программ: ", "Programs: ") + apps.Count +
                Tr.S("   ·   в автозапуске: ", "   ·   in startup: ") + onCount +
                Tr.S("   ·   оранжевым — записи автозапуска вне списка установленных", "   ·   orange — startup entries outside the installed list");
            AutoFillLastColumn(_lvStartup);
        }

        private void Startup_ItemChecked(object sender, ItemCheckedEventArgs e)
        {
            if (_suppressStartup) return;
            ListViewItem it = e.Item;
            object tag = it.Tag;
            try
            {
                if (tag is InstalledApp)
                {
                    InstalledApp app = (InstalledApp)tag;
                    if (it.Checked)
                    {
                        if (string.IsNullOrEmpty(app.ExePath))
                        {
                            MessageBox.Show(Tr.S("Не удалось определить exe этой программы — добавить в автозапуск нельзя.",
                                                 "Could not determine this program's exe — cannot add to startup."),
                                Tr.S("Автозапуск", "Startup"), MessageBoxButtons.OK, MessageBoxIcon.Warning);
                            _suppressStartup = true; it.Checked = false; _suppressStartup = false;
                            return;
                        }
                        _engine.AddAutostart(app.Name, app.ExePath);
                    }
                    else
                    {
                        _engine.RemoveAutostart(app.ExePath, app.Name);
                    }
                }
                else if (tag is AutostartEntry)
                {
                    AutostartEntry ent = (AutostartEntry)tag;
                    if (it.Checked)
                    {
                        if (!string.IsNullOrEmpty(ent.ExePath)) _engine.AddAutostart(ent.Name, ent.ExePath);
                    }
                    else
                    {
                        _engine.RemoveAutostart(ent.ExePath, ent.Name);
                        if (!string.IsNullOrEmpty(ent.LnkPath)) { try { File.Delete(ent.LnkPath); } catch { } }
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(Tr.S("Ошибка: ", "Error: ") + ex.Message);
            }
        }

        // ---------- Трей ----------
        private void BuildTray()
        {
            _tray = new NotifyIcon();
            _tray.Icon = _iconIdle;
            _tray.Text = "Windows Process Cleaner";
            _tray.Visible = true;
            _tray.DoubleClick += delegate { ShowWindow(); };

            ContextMenu menu = new ContextMenu();
            menu.MenuItems.Add(new MenuItem(Tr.S("Открыть", "Open"), delegate { ShowWindow(); }));
            menu.MenuItems.Add(new MenuItem(Tr.S("Сканировать сейчас", "Scan now"), delegate { ShowWindow(); DoScan(); }));
            menu.MenuItems.Add(new MenuItem(Tr.S("Очистить сейчас", "Clean now"), delegate { RunAutoClean(true); }));
            menu.MenuItems.Add(new MenuItem(Tr.S("Очистить Standby Memory", "Purge Standby Memory"), delegate { DoPurgeOnly(); }));
            _miAuto = new MenuItem(Tr.S("Автоочистка по таймеру", "Auto-clean timer"), delegate { ToggleAuto(); });
            menu.MenuItems.Add(_miAuto);
            menu.MenuItems.Add("-");
            menu.MenuItems.Add(new MenuItem(Tr.S("Перезапустить от администратора", "Restart as administrator"), delegate { RestartAsAdmin(); }));
            menu.MenuItems.Add(new MenuItem(Tr.S("Выход", "Exit"), delegate { ExitApp(); }));
            _tray.ContextMenu = menu;
        }

        public void ShowWindow()
        {
            Show();
            WindowState = FormWindowState.Normal;
            Activate();
            BringToFront();
        }

        private void ExitApp()
        {
            _reallyExit = true;
            _tray.Visible = false;
            Application.Exit();
        }

        private void ToggleAuto()
        {
            _engine.Config.AutoEnabled = !_engine.Config.AutoEnabled;
            _engine.SaveConfig();
            LoadSettingsToUi();
            RescheduleAuto();
        }

        private void RestartAsAdmin()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo(Application.ExecutablePath);
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                Process.Start(psi);
                ExitApp();
            }
            catch { /* пользователь отклонил UAC */ }
        }

        // ---------- Логика ----------
        private void SafeMonitorTick()
        {
            try { _engine.MonitorTick(); UpdateTrayState(); } catch { }
        }

        private List<ProcInfo> _lastScan = new List<ProcInfo>();

        private void DoScan()
        {
            Cursor = Cursors.WaitCursor;
            try { _lastScan = _engine.Scan(_engine.Config.GlobalScan); }
            finally { Cursor = Cursors.Default; }
            _lvScan.Items.Clear();
            Dictionary<string, int> byCat = new Dictionary<string, int>();
            int candidates = 0;
            foreach (ProcInfo p in _lastScan)
            {
                ListViewItem it = new ListViewItem(p.Category);
                it.SubItems.Add(p.Name);
                it.SubItems.Add(p.Pid.ToString());
                it.SubItems.Add(p.ParentPid.ToString());
                it.SubItems.Add(p.CpuPercent.ToString("0.00", CultureInfo.InvariantCulture));
                it.SubItems.Add(Engine.FormatBytes(p.RamBytes));
                it.SubItems.Add(FormatSpan(p.IdleFor));
                it.SubItems.Add(YesNo(p.HasWindow));
                it.SubItems.Add(YesNo(p.ListensTcp));
                it.SubItems.Add(YesNo(p.HasChildren));
                it.SubItems.Add(p.Reason);
                it.ToolTipText = p.Name + " (pid " + p.Pid + ")" +
                    (string.IsNullOrEmpty(p.Path) ? "" : "\r\n" + p.Path) + "\r\n" + p.Reason;
                it.Tag = p;
                it.Checked = p.IsCandidate;
                it.ForeColor = _theme.Text;
                if (p.IsCandidate) it.BackColor = _theme.CandidateBg;
                else if (p.Whitelisted) it.BackColor = _theme.WhiteBg;
                else it.BackColor = _theme.Surface;
                _lvScan.Items.Add(it);

                int c;
                byCat[p.Category] = byCat.TryGetValue(p.Category, out c) ? c + 1 : 1;
                if (p.IsCandidate) candidates++;
            }

            StringBuilder sb = new StringBuilder();
            sb.Append(Tr.S("Найдено: ", "Found: ") + _lastScan.Count +
                      Tr.S("  ·  кандидатов на завершение: ", "  ·  termination candidates: ") + candidates + "   ");
            List<string> parts = new List<string>();
            foreach (KeyValuePair<string, int> kv in byCat) parts.Add(kv.Key + " " + kv.Value);
            sb.Append(string.Join("  ", parts.ToArray()));
            _lblSummary.Text = sb.ToString();
            UpdateTrayState();
        }

        private void SetAllChecks(bool value)
        {
            _lvScan.BeginUpdate();
            foreach (ListViewItem it in _lvScan.Items) it.Checked = value;
            _lvScan.EndUpdate();
            _lvScan.Invalidate();
        }

        private void DoClean()
        {
            List<ProcInfo> toKill = new List<ProcInfo>();
            foreach (ListViewItem it in _lvScan.Items)
                if (it.Checked && it.Tag is ProcInfo) toKill.Add((ProcInfo)it.Tag);

            if (toKill.Count == 0)
            {
                MessageBox.Show(Tr.S("Не выбрано ни одного процесса.", "No processes selected."),
                    Tr.S("Очистка", "Clean"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            DialogResult dr = MessageBox.Show(
                Tr.S("Завершить процессов: ", "Terminate processes: ") + toKill.Count + "?",
                Tr.S("Подтверждение", "Confirm"), MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (dr != DialogResult.Yes) return;
            ExecuteKill(toKill);
        }

        // Автоочистка по кнопке: завершить все найденные неактивные (кандидаты).
        private void DoAutoCleanButton()
        {
            if (_lastScan == null || _lastScan.Count == 0) DoScan();
            List<ProcInfo> cands = _lastScan.Where(p => p.IsCandidate).ToList();
            if (cands.Count == 0)
            {
                MessageBox.Show(Tr.S("Неактивных (заброшенных) процессов не найдено.", "No inactive (abandoned) processes found."),
                    Tr.S("Автоочистка", "Auto-clean"), MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            StringBuilder list = new StringBuilder();
            foreach (ProcInfo p in cands.Take(20)) list.AppendLine("• " + p.Name + " (pid " + p.Pid + ")");
            if (cands.Count > 20) list.AppendLine(Tr.S("… и ещё ", "… and ") + (cands.Count - 20) + Tr.S("", " more"));
            DialogResult dr = MessageBox.Show(
                Tr.S("Найдено неактивных процессов: ", "Inactive processes found: ") + cands.Count +
                Tr.S(".\r\nЗавершить все?\r\n\r\n", ".\r\nTerminate all?\r\n\r\n") + list,
                Tr.S("Автоочистка", "Auto-clean"), MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (dr != DialogResult.Yes) return;
            ExecuteKill(cands);
        }

        // Общий исполнитель: завершает список, чистит память, пишет историю, обновляет UI.
        private void ExecuteKill(List<ProcInfo> list)
        {
            Cursor = Cursors.WaitCursor;
            int killed = 0; long freed = 0;
            List<string> names = new List<string>();
            try
            {
                foreach (ProcInfo p in list)
                {
                    long f;
                    if (_engine.TerminateProcess(p.Pid, out f))
                    {
                        killed++; freed += f;
                        names.Add(p.Name + " (pid " + p.Pid + ")");
                    }
                }
            }
            finally { Cursor = Cursors.Default; }

            Engine.MemResult mr = _engine.PurgeStandby();
            long totalFreed = freed + mr.FreedBytes;
            SaveHistory(killed, totalFreed, names);

            _lblResult.Text = Tr.S("✓ Завершено процессов: ", "✓ Terminated: ") + killed +
                Tr.S("    ✓ Освобождено RAM: ", "    ✓ Freed RAM: ") + Engine.FormatBytes(totalFreed) +
                "    ·  " + mr.Message;
            DoScan();
            RefreshHistory();
        }

        private void DoPurgeOnly()
        {
            Engine.MemResult mr = _engine.PurgeStandby();
            string msg = mr.Message + Tr.S("  ·  освобождено ~", "  ·  freed ~") + Engine.FormatBytes(mr.FreedBytes);
            _tray.ShowBalloonTip(2500, "Standby Memory", msg,
                mr.Ok ? ToolTipIcon.Info : ToolTipIcon.Warning);
        }

        // Автоочистка: сканирует и завершает только кандидатов
        private void RunAutoClean(bool interactive)
        {
            List<ProcInfo> scan = _engine.Scan(_engine.Config.GlobalScan);
            List<ProcInfo> cands = scan.Where(p => p.IsCandidate).ToList();
            int killed = 0; long freed = 0;
            List<string> names = new List<string>();
            foreach (ProcInfo p in cands)
            {
                long f;
                if (_engine.TerminateProcess(p.Pid, out f))
                {
                    killed++; freed += f;
                    names.Add(p.Name + " (pid " + p.Pid + ")");
                }
            }
            Engine.MemResult mr = _engine.PurgeStandby();
            long total = freed + mr.FreedBytes;
            SaveHistory(killed, total, names);

            string msg = Tr.S("Завершено: ", "Terminated: ") + killed + Tr.S("  ·  освобождено ~", "  ·  freed ~") + Engine.FormatBytes(total);
            _tray.ShowBalloonTip(3000, Tr.S("Автоочистка выполнена", "Auto-clean done"), msg, ToolTipIcon.Info);
            if (interactive && Visible) { DoScan(); RefreshHistory(); }
            UpdateTrayState();
        }

        private void SaveHistory(int killed, long freed, List<string> names)
        {
            HistoryEntry e = new HistoryEntry();
            e.DateTime = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
            e.TerminatedCount = killed;
            e.FreedBytes = freed;
            e.Processes = names;
            _engine.AppendHistory(e);
        }

        private void RefreshHistory()
        {
            _lvHistory.Items.Clear();
            HistoryFile h = _engine.LoadHistory();
            foreach (HistoryEntry e in h.Entries)
            {
                ListViewItem it = new ListViewItem(e.DateTime);
                it.SubItems.Add(e.TerminatedCount.ToString());
                it.SubItems.Add(Engine.FormatBytes(e.FreedBytes));
                it.SubItems.Add(e.Processes != null ? string.Join(", ", e.Processes.ToArray()) : "");
                _lvHistory.Items.Add(it);
            }
        }

        private void RefreshPorts()
        {
            _lvPorts.Items.Clear();
            foreach (PortRow pr in _engine.DevPortRows())
            {
                ListViewItem it = new ListViewItem(pr.Port.ToString());
                it.SubItems.Add(pr.Pid.ToString());
                it.SubItems.Add(pr.ProcName);
                it.Tag = pr;
                _lvPorts.Items.Add(it);
            }
        }

        private void KillSelectedPorts()
        {
            List<int> pids = new List<int>();
            foreach (ListViewItem it in _lvPorts.Items)
                if (it.Checked && it.Tag is PortRow) pids.Add(((PortRow)it.Tag).Pid);
            if (pids.Count == 0) { MessageBox.Show(Tr.S("Не выбрано ни одного порта.", "No ports selected.")); return; }

            int killed = 0; long freed = 0;
            foreach (int pid in pids.Distinct())
            {
                long f;
                if (_engine.TerminateProcess(pid, out f)) { killed++; freed += f; }
            }
            MessageBox.Show(Tr.S("Завершено процессов: ", "Terminated: ") + killed +
                Tr.S("  ·  освобождено ~", "  ·  freed ~") + Engine.FormatBytes(freed),
                Tr.S("Порты", "Ports"), MessageBoxButtons.OK, MessageBoxIcon.Information);
            RefreshPorts();
        }

        // ---------- Настройки <-> UI ----------
        private void LoadSettingsToUi()
        {
            AppConfig c = _engine.Config;
            _numCpu.Value = (decimal)Math.Min(100, Math.Max(0, c.CpuThresholdPercent));
            _numIdle.Value = Math.Min(1440, Math.Max(0, c.IdleMinutes));
            _numMinLife.Value = Math.Min(1440, Math.Max(0, c.MinLifetimeMinutes));
            _numInterval.Value = Math.Min(24, Math.Max(1, c.AutoIntervalHours));
            _numGlobalIdle.Value = Math.Min(1440, Math.Max(1, c.GlobalIdleMinutes));
            _chkAuto.Checked = c.AutoEnabled;
            _chkExcludeInstalled.Checked = c.GlobalExcludeInstalled;
            _chkAutostart.Checked = c.Autostart;
            _chkStartMin.Checked = c.StartMinimized;
            _txtWatch.Text = string.Join("\r\n", c.Watchlist.ToArray());
            _txtWhite.Text = string.Join("\r\n", c.Whitelist.ToArray());
            _txtPorts.Text = string.Join(", ", c.DevPorts.Select(p => p.ToString()).ToArray());
            if (_cmbTheme != null)
            {
                if (c.Theme == "light") _cmbTheme.SelectedIndex = 1;
                else if (c.Theme == "dark") _cmbTheme.SelectedIndex = 2;
                else _cmbTheme.SelectedIndex = 0;
            }
            if (_chkGlobal != null) _chkGlobal.Checked = c.GlobalScan;
            if (_cmbLang != null) _cmbLang.SelectedIndex = (c.Language == "en") ? 1 : 0;
            if (_miAuto != null) _miAuto.Checked = c.AutoEnabled;
        }

        private string ThemeModeFromCombo()
        {
            if (_cmbTheme == null) return "system";
            if (_cmbTheme.SelectedIndex == 1) return "light";
            if (_cmbTheme.SelectedIndex == 2) return "dark";
            return "system";
        }

        private void PreviewTheme()
        {
            _theme = Theme.Resolve(ThemeModeFromCombo());
            ApplyThemeAll();
        }

        private void SaveSettingsFromUi()
        {
            AppConfig c = _engine.Config;
            c.CpuThresholdPercent = (double)_numCpu.Value;
            c.IdleMinutes = (int)_numIdle.Value;
            c.MinLifetimeMinutes = (int)_numMinLife.Value;
            c.AutoIntervalHours = (int)_numInterval.Value;
            c.GlobalIdleMinutes = (int)_numGlobalIdle.Value;
            c.AutoEnabled = _chkAuto.Checked;
            c.GlobalExcludeInstalled = _chkExcludeInstalled.Checked;
            c.StartMinimized = _chkStartMin.Checked;
            c.Watchlist = ParseLines(_txtWatch.Text);
            c.Whitelist = ParseLines(_txtWhite.Text);
            c.DevPorts = ParsePorts(_txtPorts.Text);
            c.Theme = ThemeModeFromCombo();

            string newLang = (_cmbLang != null && _cmbLang.SelectedIndex == 1) ? "en" : "ru";
            bool langChanged = c.Language != newLang;
            c.Language = newLang;

            bool autostartChanged = c.Autostart != _chkAutostart.Checked;
            c.Autostart = _chkAutostart.Checked;

            _engine.SaveConfig();
            if (autostartChanged || true) _engine.ApplyAutostart(c.Autostart);
            RescheduleAuto();
            if (_miAuto != null) _miAuto.Checked = c.AutoEnabled;

            MessageBox.Show(Tr.S("Настройки сохранены.", "Settings saved."),
                Tr.S("Настройки", "Settings"), MessageBoxButtons.OK, MessageBoxIcon.Information);

            if (langChanged)
                MessageBox.Show(
                    Tr.S("Язык изменится после перезапуска приложения.",
                         "The language will change after you restart the app."),
                    Tr.S("Язык", "Language"), MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private List<string> ParseLines(string text)
        {
            List<string> list = new List<string>();
            foreach (string line in text.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string t = line.Trim();
                if (t.Length > 0) list.Add(t);
            }
            return list;
        }

        private List<int> ParsePorts(string text)
        {
            List<int> list = new List<int>();
            foreach (string part in text.Split(new char[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries))
            {
                int v;
                if (int.TryParse(part.Trim(), out v) && v > 0 && v < 65536) list.Add(v);
            }
            return list;
        }

        // ---------- Автоочистка по расписанию ----------
        private void RescheduleAuto()
        {
            if (_engine.Config.AutoEnabled)
                _nextAuto = DateTime.Now.AddHours(_engine.Config.AutoIntervalHours);
            else
                _nextAuto = DateTime.MaxValue;
        }

        private void CheckAutoSchedule()
        {
            if (!_engine.Config.AutoEnabled) return;
            if (DateTime.Now >= _nextAuto)
            {
                RunAutoClean(false);
                _nextAuto = DateTime.Now.AddHours(_engine.Config.AutoIntervalHours);
            }
        }

        // ---------- Трей: индикация ----------
        private void UpdateTrayState()
        {
            int candidates = 0;
            foreach (ProcInfo p in _lastScan) if (p.IsCandidate) candidates++;
            if (_tray == null) return;
            if (candidates > 0)
            {
                _tray.Icon = _iconActive;
                _tray.Text = Tr.S("Process Cleaner · кандидатов: ", "Process Cleaner · candidates: ") + candidates;
            }
            else
            {
                _tray.Icon = _iconIdle;
                _tray.Text = "Windows Process Cleaner";
            }
        }

        private static string YesNo(bool v) { return v ? Tr.S("да", "yes") : Tr.S("нет", "no"); }

        private static string FormatSpan(TimeSpan t)
        {
            string s = Tr.S("с", "s"), m = Tr.S("м", "m"), h = Tr.S("ч", "h");
            if (t.TotalSeconds < 1) return "-";
            if (t.TotalMinutes < 1) return (int)t.TotalSeconds + s;
            if (t.TotalHours < 1) return (int)t.TotalMinutes + m;
            return (int)t.TotalHours + h + " " + t.Minutes + m;
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            if (_startHidden)
            {
                Hide();
            }
            _ready = true;
            RefreshHistory();
            RefreshPorts();
            BeginInvoke((MethodInvoker)delegate { FillColumns(); });
            // одноразовая до-подгонка после окончательной раскладки окна
            System.Windows.Forms.Timer once = new System.Windows.Forms.Timer();
            once.Interval = 300;
            once.Tick += delegate { once.Stop(); once.Dispose(); FillColumns(); };
            once.Start();
            if (_selfTest)
                BeginInvoke((MethodInvoker)delegate { DoScan(); });
        }

        private bool _startHidden = false;
        public void SetStartHidden(bool v) { _startHidden = v; }
        private bool _selfTest = false;
        public void SetSelfTest(bool v) { _selfTest = v; }
    }

    // ------------------------------------------------------------------ //
    //  Точка входа + single-instance через локальный порт
    // ------------------------------------------------------------------ //
    static class Program
    {
        private const int SingleInstancePort = 49876; // обычно свободный порт
        private static MainForm _form;

        [STAThread]
        static void Main(string[] args)
        {
            bool startTray = args != null && args.Contains("/tray");

            TcpListener listener;
            if (!TryBecomePrimary(out listener))
            {
                // Уже запущено — просим тот экземпляр показать окно и выходим
                NotifyPrimaryShow();
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            Engine engine = new Engine();
            Tr.En = engine.Config.Language == "en";
            _form = new MainForm(engine);

            if (startTray || engine.Config.StartMinimized)
                _form.SetStartHidden(true);
            if (args != null && args.Contains("/selftest"))
                _form.SetSelfTest(true);

            // Слушаем сигналы "покажись" от повторных запусков
            StartActivationListener(listener);

            Application.Run(_form);
        }

        private static bool TryBecomePrimary(out TcpListener listener)
        {
            listener = null;
            try
            {
                TcpListener l = new TcpListener(IPAddress.Loopback, SingleInstancePort);
                l.Start();
                listener = l;
                return true;
            }
            catch (SocketException)
            {
                return false;
            }
        }

        private static void NotifyPrimaryShow()
        {
            try
            {
                using (TcpClient c = new TcpClient())
                {
                    c.Connect(IPAddress.Loopback, SingleInstancePort);
                    byte[] msg = Encoding.ASCII.GetBytes("SHOW");
                    c.GetStream().Write(msg, 0, msg.Length);
                }
            }
            catch { }
        }

        private static void StartActivationListener(TcpListener listener)
        {
            Thread t = new Thread(delegate()
            {
                while (true)
                {
                    try
                    {
                        TcpClient client = listener.AcceptTcpClient();
                        byte[] buf = new byte[16];
                        client.GetStream().Read(buf, 0, buf.Length);
                        client.Close();
                        if (_form != null && !_form.IsDisposed)
                        {
                            _form.BeginInvoke((MethodInvoker)delegate { _form.ShowWindow(); });
                        }
                    }
                    catch { break; }
                }
            });
            t.IsBackground = true;
            t.Start();
        }
    }
}
