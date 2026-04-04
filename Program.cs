using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text.Json;
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
        static ApiKeyStatus? _apiKeyStatus;

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
            _apiKeyStatus = CheckApiKeyStatus();

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
                PrintMenuItem("3. This space intentionally left blank", null);
                var fallbackColor = patcher.GetFallbackPatchState() == PatchState.Patched
                    ? ConsoleColor.White : ConsoleColor.Cyan;
                PrintMenuItem("4. Enable Morrenus fallback", "fixes \"No Internet Connection\" error", fallbackColor);
                PrintMenuItem("5. Test Morrenus API", "checks if your ISP is blocking the API/if your API key is bad");
                PrintMenuItem("6. Update Morrenus API key", "update your expired API key here");
                PrintMenuItem("7. Repair SteamTools DLLs", "checks for the core SteamTools DLLs and replaces missing DLLs");
                PrintMenuItem("8. Disable Everything", "restore original files");
                PrintMenuItem("9. Exit", null);
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
                        break;

                    case '4':
                        ClearScreen();
                        PrintHeader();
                        PrintLine($"Steam: {_steamPath}");
                        PrintSep();
                        Console.WriteLine();
                        PrintLine("If a specific SteamTools service is down, manifests cannot be");
                        PrintLine("retrieved for games that are not owned. A user experiences this");
                        PrintLine("as a 'No Internet Connection' error in Steam. This fixes that.");
                        Console.WriteLine();
                        Console.Write("  Continue? [Y/n] ");
                        var fallbackConfirm = Console.ReadKey(true);
                        Console.WriteLine(fallbackConfirm.KeyChar);
                        Console.WriteLine();
                        if (fallbackConfirm.KeyChar is 'n' or 'N')
                            break;
                        RunFallbackSetup(patcher);
                        _apiKeyStatus = CheckApiKeyStatus();
                        break;

                    case '5':
                        ClearScreen();
                        PrintHeader();
                        PrintLine($"Steam: {_steamPath}");
                        PrintSep();
                        Console.WriteLine();
                        RunApiTest();
                        break;

                    case '6':
                        ClearScreen();
                        PrintHeader();
                        PrintLine($"Steam: {_steamPath}");
                        PrintSep();
                        Console.WriteLine();
                        RunUpdateApiKey();
                        _apiKeyStatus = CheckApiKeyStatus();
                        break;

                    case '7':
                        ClearScreen();
                        PrintHeader();
                        PrintLine($"Steam: {_steamPath}");
                        PrintSep();
                        Console.WriteLine();
                        RunDllRepair(patcher);
                        break;

                    case '8':
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

                    case '9':
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
                        PrintRed($"Expected version {ExpectedVersion}. Fallback WILL NOT WORK unless you update Steam!");
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
                PatchState.UnknownVersion => "unknown payload version",
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
                PatchState.UnknownVersion => "unknown SteamTools version",
                _ => "unknown"
            };

            if (cloudState == PatchState.Patched)
                PrintGreen($"Capcom Game Save Fix:  {cloudLabel}");
            else if (cloudState == PatchState.OutOfDate)
                PrintYellow($"Capcom Game Save Fix:  {cloudLabel}");
            else
                PrintRed($"Capcom Game Save Fix:  {cloudLabel}");

            if (cloudState == PatchState.NotInstalled)
            {
                PrintLine("  Use option 7 to download SteamTools DLLs");
                return;
            }

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
            {
                if (!patcher.IsStellaDllCurrent())
                    PrintYellow($"Fallback:              {fallbackLabel} (DLL outdated)");
                else
                    PrintGreen($"Fallback:              {fallbackLabel}");
            }
            else if (fallbackState == PatchState.OutOfDate)
                PrintYellow($"Fallback:              {fallbackLabel}");
            else
                PrintRed($"Fallback:              {fallbackLabel}");

            var stState = patcher.GetSteamToolsExePatchState();
            if (stState >= 0)
            {
                Console.WriteLine();
                if (stState == 0)
                    PrintGreen("SteamTools: silent DLL updating is disabled");
                else
                {
                    PrintYellow("SteamTools: unpatched");
                    if (fallbackState == PatchState.Patched)
                    {
                        PrintYellow("Fallback is enabled but SteamTools Desktop App is unpatched.");
                        PrintYellow("SteamTools Desktop App will overwrite Morrenus fallback every time");
                        PrintYellow("you launch the desktop app unless you run option 4 and patch it!");
                    }
                }
            }

            bool allGood = cloudState == PatchState.Patched
                && offlineState == PatchState.Patched
                && fallbackState == PatchState.Patched
                && patcher.IsStellaDllCurrent()
                && stState <= 0;

            if (allGood)
            {
                Console.WriteLine();
                if (_apiKeyStatus == null || _apiKeyStatus == ApiKeyStatus.Good || _apiKeyStatus == ApiKeyStatus.NoKey)
                {
                    if (_apiKeyStatus == ApiKeyStatus.Good)
                        PrintGreen("API key is valid and the API is responding correctly!");
                    Console.WriteLine();
                    PrintGreen("Everything is configured correctly!");
                }
                else if (_apiKeyStatus == ApiKeyStatus.Expired)
                {
                    PrintRed("API key:               expired or invalid");
                    PrintRed("Use option 6 to update your API key.");
                }
                else if (_apiKeyStatus == ApiKeyStatus.SslBlocked)
                {
                    PrintRed("Your ISP is blocking the API! Turn off Advanced Security in your");
                    PrintRed("ISP's app if they have that feature. Alternatively, use a VPN.");
                }
                else
                {
                    PrintYellow("API key:               could not verify (network error)");
                }
            }
        }

        static void RunFallbackSetup(Patcher patcher)
        {
            if (patcher.NeedsDllRepair())
            {
                if (!OfferDllRepair(patcher))
                {
                    WaitForKey();
                    return;
                }
            }

            string apiKey = null;
            var cfgPath = Path.Combine(_steamPath, "stella.cfg");

            if (File.Exists(cfgPath))
            {
                var existing = File.ReadAllText(cfgPath).Trim();
                if (IsValidApiKey(existing))
                {
                    PrintLine("stella.cfg found, using existing API key.");
                }
                else
                {
                    PrintRed("stella.cfg exists but key is invalid.");
                    File.Delete(cfgPath);
                }
            }

            if (!File.Exists(cfgPath))
            {
                while (true)
                {
                    PrintLine("Enter your Morrenus API key (or leave blank to cancel):");
                    Console.Write("  > ");
                    apiKey = Console.ReadLine()?.Trim();

                    if (string.IsNullOrWhiteSpace(apiKey))
                        return;

                    if (IsValidApiKey(apiKey))
                        break;

                    PrintRed("Invalid key. Make sure you are copying the key correctly.");
                    Console.WriteLine();
                }
            }

            var result = patcher.ApplyFallback(apiKey);
            if (!result.Succeeded && IsWrongVersionError(result.Error) && OfferDllReplace(patcher))
                result = patcher.ApplyFallback(apiKey);
            Console.WriteLine();
            if (result.Succeeded)
            {
                PrintGreen("Morrenus fallback: enabled");

                var stState = patcher.GetSteamToolsExePatchState();
                if (stState == 1)
                {
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

                if (!OfferSteamRestart())
                    WaitForKey();
            }
            else
            {
                PrintRed($"Error: {result.Error}");
                WaitForKey();
            }
        }

        static void RunApiTest()
        {
            var cfgPath = Path.Combine(_steamPath, "stella.cfg");
            if (!File.Exists(cfgPath))
            {
                PrintRed("stella.cfg not found in Steam directory.");
                PrintLine("Run 'Enable Morrenus fallback' first to set up your API key.");
                WaitForKey();
                return;
            }

            string apiKey;
            try { apiKey = File.ReadAllText(cfgPath).Trim(); }
            catch (IOException ex)
            {
                PrintRed($"Could not read stella.cfg: {ex.Message}");
                WaitForKey();
                return;
            }

            if (string.IsNullOrWhiteSpace(apiKey))
            {
                PrintRed("stella.cfg is empty.");
                WaitForKey();
                return;
            }

            PrintLine("API key loaded from stella.cfg");
            Console.WriteLine();

            ulong depotId, manifestId;

            Console.WriteLine("  1. Test with Grind Survivors");
            Console.WriteLine("  2. Specify depot + manifest ID");
            Console.WriteLine("  3. Return to main menu");
            Console.WriteLine();
            Console.Write("  > ");
            var testChoice = Console.ReadKey(true);
            Console.WriteLine(testChoice.KeyChar);
            Console.WriteLine();

            if (testChoice.KeyChar == '3')
                return;

            if (testChoice.KeyChar == '1')
            {
                depotId = 3816931;
                manifestId = 3636809188681531478;
                PrintLine($"Depot: {depotId}  Manifest: {manifestId}");
            }
            else
            {
                Console.Write("  Depot ID: ");
                var depotStr = Console.ReadLine()?.Trim();
                if (!ulong.TryParse(depotStr, out depotId) || depotId == 0)
                {
                    PrintRed("Invalid depot ID.");
                    WaitForKey();
                    return;
                }

                Console.Write("  Manifest ID: ");
                var manifestStr = Console.ReadLine()?.Trim();
                if (!ulong.TryParse(manifestStr, out manifestId) || manifestId == 0)
                {
                    PrintRed("Invalid manifest ID.");
                    WaitForKey();
                    return;
                }
            }

            Console.WriteLine();

            try
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
                http.DefaultRequestHeaders.UserAgent.ParseAdd("Stella/1.0");

                PrintLine("Requesting code from manifest.morrenus.xyz..");

                var apiUrl = $"https://manifest.morrenus.xyz/api/v1/generate/requestcode" +
                             $"?depot_id={depotId}&manifest_id={manifestId}";
                var apiReq = new HttpRequestMessage(HttpMethod.Get, apiUrl);
                apiReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

                var apiResp = http.SendAsync(apiReq).GetAwaiter().GetResult();
                var apiBody = apiResp.Content.ReadAsStringAsync().GetAwaiter().GetResult();

                PrintLine($"API: HTTP {(int)apiResp.StatusCode} {apiResp.ReasonPhrase}");

                if (!string.IsNullOrEmpty(apiBody))
                    PrintLine($"Response: {apiBody}");

                if (!apiResp.IsSuccessStatusCode)
                {
                    Console.WriteLine();
                    PrintRed("API request failed");
                    WaitForKey();
                    return;
                }

                ulong requestCode = 0;
                try
                {
                    using var doc = JsonDocument.Parse(apiBody);
                    if (doc.RootElement.TryGetProperty("request_code", out var rc))
                    {
                        if (rc.ValueKind == JsonValueKind.Number)
                            requestCode = rc.GetUInt64();
                        else if (rc.ValueKind == JsonValueKind.String)
                            ulong.TryParse(rc.GetString(), out requestCode);
                    }
                }
                catch (JsonException)
                {
                    Console.WriteLine();
                    PrintRed("Response is not valid JSON");
                    WaitForKey();
                    return;
                }

                if (requestCode == 0)
                {
                    Console.WriteLine();
                    PrintRed("request_code is 0 or missing (depot/manifest may not exist)");
                    WaitForKey();
                    return;
                }

                PrintGreen($"request_code: {requestCode}");
                Console.WriteLine();
                PrintGreen("API connection is working");
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine();
                PrintRed($"Connection failed: {ex.Message}");
            }
            catch (AggregateException ex) when (ex.InnerException is TaskCanceledException)
            {
                Console.WriteLine();
                PrintRed("Request timed out");
            }
            catch (Exception ex)
            {
                Console.WriteLine();
                PrintRed($"Error: {ex.Message}");
            }

            WaitForKey();
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
                PrintGreen("DLLs repaired successfully.");
            else
                PrintRed($"Repair failed: {result.Error}");

            WaitForKey();
        }

        static void RunUpdateApiKey()
        {
            var cfgPath = Path.Combine(_steamPath, "stella.cfg");

            if (File.Exists(cfgPath))
            {
                try
                {
                    var existing = File.ReadAllText(cfgPath).Trim();
                    if (existing.Length > 8)
                        PrintLine($"Current key: {existing[..4]}...{existing[^4..]}");
                    else if (existing.Length > 0)
                        PrintLine($"Current key: {existing}");
                }
                catch { }
            }
            else
            {
                PrintLine("No API key configured.");
            }

            Console.WriteLine();
            string newKey;
            while (true)
            {
                PrintLine("Enter new Morrenus API key (or leave blank to cancel):");
                Console.Write("  > ");
                newKey = Console.ReadLine()?.Trim();

                if (string.IsNullOrWhiteSpace(newKey))
                    return;

                if (IsValidApiKey(newKey))
                    break;

                PrintRed("Invalid key. Make sure you are copying the key correctly.");
                Console.WriteLine();
            }

            try
            {
                File.WriteAllText(cfgPath, newKey);
                PrintGreen("API key saved to stella.cfg");
            }
            catch (Exception ex)
            {
                PrintRed($"Could not write stella.cfg: {ex.Message}");
            }

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

        static bool IsValidApiKey(string key)
        {
            if (key.Length != 100 || !key.StartsWith("smm_"))
                return false;
            for (int i = 4; i < key.Length; i++)
            {
                char c = key[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
                    return false;
            }
            return true;
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

        static void KillSteamToolsIfRunning()
        {
            foreach (var p in Process.GetProcessesByName("SteamTools"))
            {
                try { p.Kill(); p.WaitForExit(5000); } catch { }
                p.Dispose();
            }
        }

        enum ApiKeyStatus { Good, Expired, SslBlocked, NetworkError, NoKey }

        static ApiKeyStatus CheckApiKeyStatus()
        {
            var cfgPath = Path.Combine(_steamPath, "stella.cfg");
            if (!File.Exists(cfgPath))
                return ApiKeyStatus.NoKey;

            string apiKey;
            try { apiKey = File.ReadAllText(cfgPath).Trim(); }
            catch { return ApiKeyStatus.NoKey; }

            if (string.IsNullOrWhiteSpace(apiKey) || !IsValidApiKey(apiKey))
                return ApiKeyStatus.NoKey;

            try
            {
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                var url = $"https://manifest.morrenus.xyz/api/v1/user/stats?api_key={apiKey}";
                var resp = http.GetAsync(url).GetAwaiter().GetResult();

                if ((int)resp.StatusCode == 401)
                    return ApiKeyStatus.Expired;

                if (!resp.IsSuccessStatusCode)
                    return ApiKeyStatus.NetworkError;

                return ApiKeyStatus.Good;
            }
            catch (HttpRequestException ex) when (ex.InnerException is System.Security.Authentication.AuthenticationException)
            {
                return ApiKeyStatus.SslBlocked;
            }
            catch
            {
                return ApiKeyStatus.NetworkError;
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
