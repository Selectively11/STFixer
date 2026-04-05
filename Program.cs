using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace CloudFix
{
    internal class Program
    {
        static readonly string _version;

        static Program()
        {
            var raw = Assembly.GetExecutingAssembly()
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()
                ?.InformationalVersion ?? "0.0.0";
            // strip source link hash (everything after +)
            int plus = raw.IndexOf('+');
            _version = plus > 0 ? raw[..plus] : raw;
        }

        static string _steamPath;

        static void Main(string[] args)
        {
            try { Console.Title = $"STFixer v{_version}"; } catch { }
            ClearScreen();
            PrintHeader();

            _steamPath = DetectSteamPath();
            if (_steamPath != null)
            {
                PrintLine($"Steam: {_steamPath}  (auto-detected)");
                Console.Write("  Use this path? [Y/n] ");
                var confirm = Console.ReadKey(true);
                Console.WriteLine(confirm.KeyChar);
                if (confirm.KeyChar is 'n' or 'N')
                    _steamPath = null;
            }

            if (_steamPath == null)
            {
                Console.WriteLine();
                Console.Write("  Enter Steam path: ");
                var custom = Console.ReadLine()?.Trim().Trim('"');
                if (string.IsNullOrWhiteSpace(custom) || !Directory.Exists(custom))
                {
                    PrintRed("Invalid path.");
                    Console.ReadKey(true);
                    return;
                }
                _steamPath = custom;
            }

            PrintLine($"Steam: {_steamPath}");

            // non-blocking update check, don't stall the menu
            try
            {
                var updateTask = Updater.CheckForUpdate(_version);
                if (updateTask.Wait(TimeSpan.FromSeconds(4)) && updateTask.Result != null)
                {
                    PrintSep();
                    PrintLine($"Update available: {updateTask.Result.TagName}");
                    if (!string.IsNullOrWhiteSpace(updateTask.Result.Body))
                    {
                        Console.WriteLine();
                        foreach (var line in updateTask.Result.Body.Split('\n'))
                            PrintLine(line.TrimEnd('\r'));
                        Console.WriteLine();
                    }
                    Console.Write("  Download and install? [Y/n] ");
                    var key = Console.ReadKey(true);
                    Console.WriteLine(key.KeyChar);
                    if (key.KeyChar is not ('n' or 'N'))
                    {
                        Updater.ApplyUpdate(updateTask.Result).GetAwaiter().GetResult();
                        return;
                    }
                }
            }
            catch (Exception)
            {
                // update check failed silently - network down, rate limited, whatever
            }

            PrintSep();

            var patcher = new Patcher(_steamPath);

            // detect leftover Morrenus fallback and offer to revert
            if (patcher.HasFallbackRemnants())
            {
                Console.WriteLine();
                PrintYellow("Morrenus fallback detected!");
                PrintLine("The Morrenus API has been shut down because SteamTools is back up.");
                PrintLine("The fallback patches are no longer needed and should be removed.");
                Console.WriteLine();
                Console.Write("  Revert fallback patches now? [Y/n] ");
                var revertKey = Console.ReadKey(true);
                Console.WriteLine(revertKey.KeyChar);
                Console.WriteLine();
                if (revertKey.KeyChar is not ('n' or 'N'))
                {
                    var revertResult = patcher.RevertFallback();
                    if (revertResult.Succeeded)
                        PrintGreen("Fallback patches removed successfully.");
                    else
                        PrintRed($"Could not revert fallback: {revertResult.Error}");
                    WaitForKey();
                }
            }

            while (true)
            {
                ClearScreen();
                PrintHeader();
                PrintLine($"Steam: {_steamPath}");
                PrintSep();
                RunDiagnostics(patcher);
                PrintSep();
                Console.WriteLine();
                PrintMenuItem("1. Setup SteamTools Offline", "makes new SteamTools installations work if servers are down");
                PrintMenuItem("2. Capcom Game Save Fix", "fixes games that will not create saves");
                bool anyPatched = patcher.GetOfflinePatchState() == PatchState.Patched
                    || patcher.GetPatchState() == PatchState.Patched;
                int stState = patcher.GetSteamToolsExePatchState();
                if (anyPatched && stState == 1)
                    PrintMenuItem("3. Patch SteamTools App", "prevents SteamTools Desktop from overwriting patches");
                else
                    PrintMenuItem("3. This space intentionally left blank", null);
                PrintMenuItem("4. Repair SteamTools DLLs", "checks for the core SteamTools DLLs and replaces missing DLLs");
                PrintMenuItem("5. Disable Everything", "restore original files");
                PrintMenuItem("6. Exit", null);
                Console.WriteLine();
                Console.Write("  > ");

                var choice = Console.ReadKey(true);
                Console.WriteLine(choice.KeyChar);
                Console.WriteLine();

                switch (choice.KeyChar)
                {
                    case '1':
                        ClearScreen();
                        PrintHeader();
                        PrintLine($"Steam: {_steamPath}");
                        PrintSep();
                        Console.WriteLine();
                        PrintLine("SteamTools requires a connection to their server during first");
                        PrintLine("time setup. This can be a problem if the server is down.");
                        PrintLine("This option patches that so that SteamTools will work, even");
                        PrintLine("if the server is down.");
                        Console.WriteLine();
                        Console.Write("  Continue? [Y/n] ");
                        var offlineConfirm = Console.ReadKey(true);
                        Console.WriteLine(offlineConfirm.KeyChar);
                        Console.WriteLine();
                        if (offlineConfirm.KeyChar is 'n' or 'N')
                            break;
                        var setupResult = patcher.ApplyOfflineSetup();
                        if (!setupResult.Succeeded && IsWrongVersionError(setupResult.Error) && OfferDllReplace(patcher))
                            setupResult = patcher.ApplyOfflineSetup();
                        if (!setupResult.Succeeded && patcher.NeedsDllRepair() && OfferDllRepair(patcher))
                            setupResult = patcher.ApplyOfflineSetup();
                        Console.WriteLine();
                        if (setupResult.Succeeded)
                        {
                            PrintGreen("Offline setup: done");
                            OfferSteamToolsExePatch(patcher);
                            if (!OfferSteamRestart())
                                WaitForKey();
                        }
                        else
                        {
                            PrintRed($"Error: {setupResult.Error}");
                            WaitForKey();
                        }
                        break;

                    case '2':
                        ClearScreen();
                        PrintHeader();
                        PrintLine($"Steam: {_steamPath}");
                        PrintSep();
                        Console.WriteLine();
                        PrintLine("SteamTools messes with Steam Cloud. The purpose of this was to");
                        PrintLine("make Steam Cloud 'work' for non-owned games. Valve has since");
                        PrintLine("patched this, so Steam Cloud doesn't work for non-owned games.");
                        PrintLine("The consequence of SteamTools's messing with Steam Cloud is");
                        PrintLine("that Capcom games will not save at all. They won't be able to");
                        PrintLine("create a save.");
                        Console.WriteLine();
                        PrintLine("This patch fixes that. Capcom games will save.");
                        Console.WriteLine();
                        Console.Write("  Continue? [Y/n] ");
                        var cloudConfirm = Console.ReadKey(true);
                        Console.WriteLine(cloudConfirm.KeyChar);
                        Console.WriteLine();
                        if (cloudConfirm.KeyChar is 'n' or 'N')
                            break;
                        var applyResult = patcher.Apply();
                        if (!applyResult.Succeeded && IsWrongVersionError(applyResult.Error) && OfferDllReplace(patcher))
                            applyResult = patcher.Apply();
                        if (!applyResult.Succeeded && patcher.NeedsDllRepair() && OfferDllRepair(patcher))
                            applyResult = patcher.Apply();
                        Console.WriteLine();
                        if (applyResult.Succeeded)
                        {
                            PrintGreen("Capcom Game Save Fix: enabled");
                            OfferSteamToolsExePatch(patcher);
                            if (!OfferSteamRestart())
                                WaitForKey();
                        }
                        else
                        {
                            PrintRed($"Error: {applyResult.Error}");
                            WaitForKey();
                        }
                        break;

                    case '3':
                        if (anyPatched && stState == 1)
                        {
                            ClearScreen();
                            PrintHeader();
                            PrintLine($"Steam: {_steamPath}");
                            PrintSep();
                            Console.WriteLine();
                            PrintLine("The SteamTools Desktop App overwrites DLL patches every time");
                            PrintLine("it starts. This option patches SteamTools.exe to prevent that.");
                            Console.WriteLine();
                            Console.Write("  Continue? [Y/n] ");
                            var stConfirm = Console.ReadKey(true);
                            Console.WriteLine(stConfirm.KeyChar);
                            Console.WriteLine();
                            if (stConfirm.KeyChar is 'n' or 'N')
                                break;
                            KillSteamToolsIfRunning();
                            patcher.PatchSteamToolsExe();
                            Console.WriteLine();
                            WaitForKey();
                        }
                        break;

                    case '4':
                        ClearScreen();
                        PrintHeader();
                        PrintLine($"Steam: {_steamPath}");
                        PrintSep();
                        Console.WriteLine();
                        RunDllRepair(patcher);
                        break;

                    case '5':
                        ClearScreen();
                        PrintHeader();
                        PrintLine($"Steam: {_steamPath}");
                        PrintSep();
                        Console.WriteLine();
                        PrintYellow("This will undo all the patches/modifications made by this tool.");
                        Console.Write("  Are you sure you want to do this? [y/N] ");
                        var restoreConfirm = Console.ReadKey(true);
                        Console.WriteLine(restoreConfirm.KeyChar);
                        Console.WriteLine();
                        if (restoreConfirm.KeyChar is not ('y' or 'Y'))
                            break;
                        if (patcher.GetSteamToolsExePatchState() == 0)
                            KillSteamToolsIfRunning();
                        var restoreResult = patcher.Restore();
                        Console.WriteLine();
                        if (restoreResult.Succeeded)
                        {
                            PrintRed("All patches removed");
                            if (!OfferSteamRestart())
                                WaitForKey();
                        }
                        else
                        {
                            PrintRed($"Error: {restoreResult.Error}");
                            WaitForKey();
                        }
                        break;

                    case '6':
                        Console.Write("  Are you sure you want to exit? [Y/n] ");
                        var exitConfirm = Console.ReadKey(true);
                        Console.WriteLine(exitConfirm.KeyChar);
                        if (exitConfirm.KeyChar is not ('n' or 'N'))
                            return;
                        break;
                }
            }
        }

        static void RunDiagnostics(Patcher patcher)
        {
            try
            {
                RunDiagnosticsInner(patcher);
            }
            catch (Exception ex)
            {
                PrintRed($"Diagnostics error: {ex.Message}");
                PrintLine("Payload cache may be corrupt. Delete the appcache/httpcache folder and restart Steam.");
            }
        }

        static void RunDiagnosticsInner(Patcher patcher)
        {
            const long ExpectedVersion = 1773426488;
            var steamVersion = GetSteamVersion();
            if (steamVersion != null)
            {
                if (steamVersion == ExpectedVersion.ToString())
                    PrintGreen($"Steam version:         {steamVersion}");
                else
                {
                    PrintRed($"Steam version:         {steamVersion} (unsupported!)");
                    if (long.TryParse(steamVersion, out var ver) && ver > ExpectedVersion)
                    {
                        PrintRed($"Expected version {ExpectedVersion}. You're on a newer version!");
                        PrintRed("Either wait for an update to this tool or run sm0k3r to downgrade!");
                    }
                    else
                        PrintRed($"Expected version {ExpectedVersion}. Patches may not work unless you update Steam!");
                }
            }
            else
                PrintYellow("Steam version:         unknown");

            var offlineState = patcher.GetOfflinePatchState();
            string offlineLabel = offlineState switch
            {
                PatchState.Unpatched => "not patched",
                PatchState.Patched => "patched",
                PatchState.OutOfDate => "out of date",
                PatchState.PartiallyPatched => "partially patched",
                PatchState.PayloadCorrupt => "payload corrupt",
                PatchState.UnknownVersion => "unsupported payload version",
                PatchState.NotInstalled => "payload not found",
                _ => "unknown"
            };

            if (offlineState == PatchState.Patched)
                PrintGreen($"Offline:               {offlineLabel}");
            else if (offlineState == PatchState.OutOfDate)
                PrintYellow($"Offline:               {offlineLabel}");
            else
                PrintRed($"Offline:               {offlineLabel}");

            var cloudState = patcher.GetPatchState();
            string cloudLabel = cloudState switch
            {
                PatchState.NotInstalled => "SteamTools not detected",
                PatchState.Unpatched => "not patched",
                PatchState.Patched => "patched",
                PatchState.OutOfDate => "out of date",
                PatchState.PartiallyPatched => "partially patched",
                PatchState.PayloadCorrupt => "payload corrupt",
                PatchState.UnknownVersion => "unsupported SteamTools version",
                _ => "unknown"
            };

            if (cloudState == PatchState.Patched)
                PrintGreen($"Capcom Game Save Fix:  {cloudLabel}");
            else if (cloudState == PatchState.OutOfDate)
                PrintYellow($"Capcom Game Save Fix:  {cloudLabel}");
            else
                PrintRed($"Capcom Game Save Fix:  {cloudLabel}");

            // show guidance for payload issues
            if (offlineState == PatchState.PayloadCorrupt || cloudState == PatchState.PayloadCorrupt)
            {
                PrintRed("  Payload cache is corrupt. Run option 4 to re-download DLLs and reset the payload.");
                return;
            }
            if (offlineState == PatchState.UnknownVersion || cloudState == PatchState.UnknownVersion)
            {
                PrintRed("  Payload version is not recognized by this version of STFixer.");
                PrintRed("  Run option 4 to re-download DLLs and reset the payload, then restart Steam.");
                return;
            }

            if (cloudState == PatchState.NotInstalled)
            {
                PrintLine("  Use option 4 to download SteamTools DLLs");
                return;
            }

            var stState = patcher.GetSteamToolsExePatchState();
            if (stState >= 0)
            {
                Console.WriteLine();
                if (stState == 0)
                    PrintGreen("SteamTools: silent DLL updating is disabled");
                else
                {
                    PrintYellow("SteamTools: unpatched");
                    bool anyPatched = offlineState == PatchState.Patched
                        || cloudState == PatchState.Patched;
                    if (anyPatched)
                    {
                        PrintYellow("SteamTools patches are enabled but SteamTools Desktop App is unpatched.");
                        PrintYellow("The SteamTools Desktop App will overwrite these patches unless you patch the app!");
                        PrintYellow("Run Option 3 to patch the SteamTools app.");
                    }
                }
            }

            bool allGood = cloudState == PatchState.Patched
                && offlineState == PatchState.Patched
                && stState <= 0;

            if (allGood)
            {
                Console.WriteLine();
                PrintGreen("Everything is configured correctly!");
            }
        }

        static void RunDllRepair(Patcher patcher)
        {
            PrintLine("This will download fresh SteamTools DLLs (xinput1_4.dll / dwmapi.dll)");
            PrintLine("and replace any existing copies.");
            Console.WriteLine();
            Console.Write("  Proceed? [Y/n] ");
            var key = Console.ReadKey(true);
            Console.WriteLine(key.KeyChar);
            Console.WriteLine();

            if (key.KeyChar is 'n' or 'N')
                return;

            DeleteCoreDlls();
            var result = patcher.RepairDlls();
            Console.WriteLine();
            if (result.Succeeded)
            {
                PrintGreen("DLLs repaired successfully.");

                // if the payload is unrecognized, delete it so Steam fetches a fresh one
                var offState = patcher.GetOfflinePatchState();
                var cloudState = patcher.GetPatchState();
                if (offState == PatchState.PayloadCorrupt || offState == PatchState.UnknownVersion
                    || cloudState == PatchState.PayloadCorrupt || cloudState == PatchState.UnknownVersion)
                {
                    Console.WriteLine();
                    if (patcher.DeletePayloadCache())
                    {
                        PrintYellow("Payload cache was unrecognized and has been deleted.");
                        PrintLine("Restart Steam so that SteamTools can download a fresh payload.");
                    }
                    else
                        PrintYellow("Could not delete payload cache. Try deleting the appcache/httpcache folder manually.");
                }
            }
            else
                PrintRed($"Repair failed: {result.Error}");

            WaitForKey();
        }

        static bool OfferDllRepair(Patcher patcher)
        {
            PrintRed("SteamTools Core DLL not found.");
            Console.WriteLine();
            Console.Write("  Download and install SteamTools DLLs? [Y/n] ");
            var key = Console.ReadKey(true);
            Console.WriteLine(key.KeyChar);
            Console.WriteLine();

            if (key.KeyChar is 'n' or 'N')
                return false;

            var result = patcher.RepairDlls();
            Console.WriteLine();
            if (result.Succeeded)
            {
                PrintGreen("DLLs installed. Retrying..");
                Console.WriteLine();
                return true;
            }

            PrintRed($"Repair failed: {result.Error}");
            return false;
        }

        static bool IsWrongVersionError(string error)
        {
            return error != null && error.Contains("wrong version", StringComparison.OrdinalIgnoreCase);
        }

        static bool OfferDllReplace(Patcher patcher)
        {
            PrintRed("The DLL appears to be a different version than expected.");
            Console.WriteLine();
            Console.Write("  Delete and re-download SteamTools DLLs? [Y/n] ");
            var key = Console.ReadKey(true);
            Console.WriteLine(key.KeyChar);
            Console.WriteLine();

            if (key.KeyChar is 'n' or 'N')
                return false;

            DeleteCoreDlls();
            var result = patcher.RepairDlls();
            Console.WriteLine();
            if (result.Succeeded)
            {
                PrintGreen("DLLs replaced. Retrying..");
                Console.WriteLine();
                return true;
            }

            PrintRed($"Repair failed: {result.Error}");
            return false;
        }

        static void DeleteCoreDlls()
        {
            foreach (var name in new[] { "xinput1_4.dll", "dwmapi.dll" })
            {
                var path = Path.Combine(_steamPath, name);
                try { if (File.Exists(path)) File.Delete(path); }
                catch { }
            }
        }

        static string DetectSteamPath()
        {
            var candidates = new List<string>();

            string[] keys =
            {
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Valve\Steam",
                @"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Valve\Steam",
                @"HKEY_CURRENT_USER\SOFTWARE\Valve\Steam",
            };

            foreach (var key in keys)
            {
                try
                {
                    var val = Registry.GetValue(key, "InstallPath", null) as string;
                    if (val != null && Directory.Exists(val) && !candidates.Contains(val))
                        candidates.Add(val);
                }
                catch (Exception) { }
            }

            string[] guesses =
            {
                @"C:\Program Files (x86)\Steam",
                @"C:\Program Files\Steam",
                @"C:\games\steam",
            };

            foreach (var path in guesses)
            {
                if (Directory.Exists(path) && !candidates.Contains(path))
                    candidates.Add(path);
            }

            // prefer the path that actually has SteamTools
            foreach (var path in candidates)
            {
                foreach (var dll in new[] { "xinput1_4.dll", "dwmapi.dll" })
                {
                    if (File.Exists(Path.Combine(path, dll)))
                        return path;
                }
            }

            // fall back to first valid Steam dir
            return candidates.Count > 0 ? candidates[0] : null;
        }

        static void PrintHeader()
        {
            Console.WriteLine();
            Console.WriteLine($"  STFixer v{_version}");
            Console.WriteLine("  SteamTools patcher");
            Console.WriteLine();
        }

        static void ClearScreen()
        {
            try { Console.Clear(); } catch { }
        }

        static void WaitForKey()
        {
            Console.WriteLine();
            Console.Write("  Press any key to continue..");
            Console.ReadKey(true);
        }

        static readonly string[] SteamProcessNames =
        {
            "steam", "steamservice", "steamwebhelper",
            "SteamService", "GameOverlayUI",
        };

        static void OfferSteamToolsExePatch(Patcher patcher)
        {
            var stState = patcher.GetSteamToolsExePatchState();
            if (stState != 1) return; // not found, already patched, or unrecognized

            Console.WriteLine();
            PrintYellow("SteamTools Desktop is installed and will overwrite DLL patches on startup.");
            PrintLine("Would you like to disable its DLL deployment? (y/n)");
            PrintLine("IF YOU DON'T KNOW WHAT TO DO, PRESS Y");
            Console.Write("  > ");
            var answer = Console.ReadLine()?.Trim().ToLowerInvariant();
            if (answer == "" || answer == "y" || answer == "yes")
            {
                Console.WriteLine();
                KillSteamToolsIfRunning();
                patcher.PatchSteamToolsExe();
            }
        }

        static bool OfferSteamRestart()
        {
            if (!AnySteamRunning())
                return false;

            Console.WriteLine();
            Console.Write("  Restart Steam now? [Y/n] ");
            var key = Console.ReadKey(true);
            Console.WriteLine(key.KeyChar);

            if (key.KeyChar is 'n' or 'N')
                return false;

            PrintLine("Shutting down Steam..");
            try
            {
                var steamExe = Path.Combine(_steamPath, "steam.exe");
                Process.Start(new ProcessStartInfo(steamExe, "-shutdown") { UseShellExecute = true });

                // wait for all steam processes to exit
                var deadline = Environment.TickCount64 + 15000;
                while (Environment.TickCount64 < deadline && AnySteamRunning())
                    System.Threading.Thread.Sleep(500);

                // kill anything still hanging around
                KillAllSteam();

                PrintLine("Restarting Steam..");
                Process.Start(new ProcessStartInfo(steamExe) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                PrintLine($"Warning: could not restart Steam - {ex.Message}");
                return false;
            }

            return true;
        }

        static bool AnySteamRunning()
        {
            foreach (var name in SteamProcessNames)
            {
                var procs = Process.GetProcessesByName(name);
                bool found = procs.Length > 0;
                foreach (var p in procs) p.Dispose();
                if (found) return true;
            }
            return false;
        }

        static void KillAllSteam()
        {
            foreach (var name in SteamProcessNames)
            {
                foreach (var p in Process.GetProcessesByName(name))
                {
                    try { p.Kill(); } catch { }
                    p.Dispose();
                }
            }
        }

        static void KillSteamToolsIfRunning()
        {
            foreach (var p in Process.GetProcessesByName("SteamTools"))
            {
                try { p.Kill(); p.WaitForExit(5000); } catch { }
                p.Dispose();
            }
        }

        static string GetSteamVersion()
        {
            try
            {
                var manifest = Path.Combine(_steamPath, "package", "steam_client_win64.manifest");
                if (!File.Exists(manifest))
                    return null;
                foreach (var line in File.ReadLines(manifest))
                {
                    var trimmed = line.Trim();
                    if (!trimmed.StartsWith("\"version\""))
                        continue;
                    // format: "version"		"1773426488"
                    var last = trimmed.LastIndexOf('"');
                    var secondLast = trimmed.LastIndexOf('"', last - 1);
                    if (last > secondLast && secondLast >= 0)
                        return trimmed[(secondLast + 1)..last];
                }
            }
            catch { }
            return null;
        }

        internal static void PrintSep()
        {
            Console.WriteLine("==================================================");
        }

        internal static void PrintLine(string msg)
        {
            Console.WriteLine($"  {msg}");
        }

        internal static void PrintGreen(string msg)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"  {msg}");
            Console.ResetColor();
        }

        internal static void PrintRed(string msg)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"  {msg}");
            Console.ResetColor();
        }

        internal static void PrintYellow(string msg)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"  {msg}");
            Console.ResetColor();
        }

        static void PrintMenuItem(string name, string description, ConsoleColor nameColor = ConsoleColor.White, ConsoleColor descColor = ConsoleColor.Green)
        {
            Console.ForegroundColor = nameColor;
            Console.Write($"  {name}");
            if (description != null)
            {
                Console.ForegroundColor = descColor;
                Console.Write($" - {description}");
            }
            Console.ResetColor();
            Console.WriteLine();
        }
    }
}
