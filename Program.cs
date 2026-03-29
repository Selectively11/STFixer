using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
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
            try { Console.Title = "STFixer"; } catch { }
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

            while (true)
            {
                ClearScreen();
                PrintHeader();
                PrintLine($"Steam: {_steamPath}");
                PrintSep();
                RunDiagnostics(patcher);
                PrintSep();
                Console.WriteLine();
                Console.WriteLine("  1. Setup SteamTools offline");
                Console.WriteLine("  2. Enable  (patch cloud saves)");
                Console.WriteLine("  3. Disable (restore originals)");
                Console.WriteLine("  4. Enable Morrenus fallback");
                Console.WriteLine("  5. Exit");
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
                        var setupResult = patcher.ApplyOfflineSetup();
                        Console.WriteLine();
                        if (setupResult.Succeeded)
                        {
                            PrintGreen("Offline setup: done");
                            OfferSteamRestart();
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
                        var applyResult = patcher.Apply();
                        Console.WriteLine();
                        if (applyResult.Succeeded)
                        {
                            PrintGreen("Cloud Fix: enabled");
                            OfferSteamRestart();
                        }
                        else
                        {
                            PrintRed($"Error: {applyResult.Error}");
                            WaitForKey();
                        }
                        break;

                    case '3':
                        ClearScreen();
                        PrintHeader();
                        PrintLine($"Steam: {_steamPath}");
                        PrintSep();
                        Console.WriteLine();
                        var restoreResult = patcher.Restore();
                        Console.WriteLine();
                        if (restoreResult.Succeeded)
                        {
                            PrintRed("Cloud Fix: disabled");
                            OfferSteamRestart();
                        }
                        else
                        {
                            PrintRed($"Error: {restoreResult.Error}");
                            WaitForKey();
                        }
                        break;

                    case '4':
                        ClearScreen();
                        PrintHeader();
                        PrintLine($"Steam: {_steamPath}");
                        PrintSep();
                        Console.WriteLine();
                        RunFallbackSetup(patcher);
                        break;

                    case '5':
                        return;
                }
            }
        }

        static void RunDiagnostics(Patcher patcher)
        {
            var cloudState = patcher.GetPatchState();
            string cloudLabel = cloudState switch
            {
                PatchState.NotInstalled => "SteamTools not detected",
                PatchState.Unpatched => "not patched",
                PatchState.Patched => "patched",
                PatchState.PartiallyPatched => "partially patched",
                PatchState.UnknownVersion => "unknown SteamTools version",
                _ => "unknown"
            };

            if (cloudState == PatchState.Patched)
                PrintGreen($"Cloud Fix: {cloudLabel}");
            else
                PrintRed($"Cloud Fix: {cloudLabel}");

            if (cloudState == PatchState.NotInstalled)
                return;

            var offlineState = patcher.GetOfflinePatchState();
            string offlineLabel = offlineState switch
            {
                PatchState.Unpatched => "not patched",
                PatchState.Patched => "patched",
                PatchState.PartiallyPatched => "partially patched",
                PatchState.UnknownVersion => "unknown payload version",
                PatchState.NotInstalled => "payload not found",
                _ => "unknown"
            };

            if (offlineState == PatchState.Patched)
                PrintGreen($"Offline:    {offlineLabel}");
            else
                PrintRed($"Offline:    {offlineLabel}");

            var fallbackState = patcher.GetFallbackPatchState();
            string fallbackLabel = fallbackState switch
            {
                PatchState.Unpatched => "not patched",
                PatchState.Patched => "active",
                PatchState.OutOfDate => "out of date",
                PatchState.PartiallyPatched => "partially patched",
                PatchState.UnknownVersion => "unknown payload version",
                PatchState.NotInstalled => "payload not found",
                _ => "unknown"
            };

            if (fallbackState == PatchState.Patched)
                PrintGreen($"Fallback:   {fallbackLabel}");
            else if (fallbackState == PatchState.OutOfDate)
                PrintYellow($"Fallback:   {fallbackLabel}");
            else
                PrintRed($"Fallback:   {fallbackLabel}");
        }

        static void RunFallbackSetup(Patcher patcher)
        {
            string apiKey = null;
            var cfgPath = Path.Combine(_steamPath, "stella.cfg");

            if (File.Exists(cfgPath))
            {
                PrintLine("stella.cfg found, using existing API key.");
            }
            else
            {
                PrintLine("Enter your Morrenus API key:");
                Console.Write("  > ");
                apiKey = Console.ReadLine()?.Trim();
                if (string.IsNullOrWhiteSpace(apiKey))
                {
                    PrintRed("No API key provided.");
                    WaitForKey();
                    return;
                }
            }

            var result = patcher.ApplyFallback(apiKey);
            Console.WriteLine();
            if (result.Succeeded)
            {
                PrintGreen("Morrenus fallback: enabled");
                if (!OfferSteamRestart())
                    WaitForKey();
            }
            else
            {
                PrintRed($"Error: {result.Error}");
                WaitForKey();
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
    }
}
