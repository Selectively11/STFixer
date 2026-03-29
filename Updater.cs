using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace CloudFix
{
    internal class ReleaseInfo
    {
        [JsonPropertyName("tag_name")]
        public string TagName { get; set; }

        [JsonPropertyName("body")]
        public string Body { get; set; }

        [JsonPropertyName("assets")]
        public ReleaseAsset[] Assets { get; set; }
    }

    internal class ReleaseAsset
    {
        [JsonPropertyName("name")]
        public string Name { get; set; }

        [JsonPropertyName("browser_download_url")]
        public string DownloadUrl { get; set; }
    }

    [JsonSerializable(typeof(ReleaseInfo))]
    internal partial class UpdaterJsonContext : JsonSerializerContext { }

    internal static class Updater
    {
        const string RepoOwner = "Selectively11";
        const string RepoName = "CloudFix";

        static readonly HttpClient _http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };

        static Updater()
        {
            _http.DefaultRequestHeaders.UserAgent.ParseAdd("CloudFix-Updater");
        }

        public static async Task<ReleaseInfo> CheckForUpdate(string currentVersion)
        {
            var url = $"https://api.github.com/repos/{RepoOwner}/{RepoName}/releases/latest";
            var release = await _http.GetFromJsonAsync(url, UpdaterJsonContext.Default.ReleaseInfo);

            if (release == null || string.IsNullOrEmpty(release.TagName))
                return null;

            // strip leading 'v' for comparison
            var remote = release.TagName.TrimStart('v');
            var local = currentVersion.TrimStart('v');

            if (remote == local)
                return null;

            if (Version.TryParse(remote, out var remoteVer) &&
                Version.TryParse(local, out var localVer))
            {
                if (remoteVer <= localVer)
                    return null;
            }
            else
            {
                // can't compare versions reliably, skip update
                return null;
            }

            return release;
        }

        public static async Task ApplyUpdate(ReleaseInfo release)
        {
            ReleaseAsset exeAsset = null;
            foreach (var asset in release.Assets)
            {
                if (asset.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                {
                    exeAsset = asset;
                    break;
                }
            }

            if (exeAsset == null)
            {
                Program.PrintLine("Error: no .exe asset found in release");
                return;
            }

            Program.PrintLine($"Downloading {exeAsset.Name}..");

            var tempPath = Path.Combine(Path.GetTempPath(), $"CloudFix_{Guid.NewGuid():N}.exe");
            try
            {
                using (var stream = await _http.GetStreamAsync(exeAsset.DownloadUrl))
                using (var fs = File.Create(tempPath))
                {
                    await stream.CopyToAsync(fs);
                }

                var currentExe = Environment.ProcessPath;
                var backupPath = currentExe + ".old";

                Program.PrintLine("Installing update..");
                try
                {
                    if (File.Exists(backupPath))
                        File.Delete(backupPath);
                    File.Move(currentExe, backupPath);
                    File.Move(tempPath, currentExe);
                }
                catch (Exception ex)
                {
                    Program.PrintLine($"Error: could not replace exe - {ex.Message}");
                    if (!File.Exists(currentExe) && File.Exists(backupPath))
                        File.Move(backupPath, currentExe);
                    return;
                }

                Program.PrintLine("Updated. Relaunching..");
                Process.Start(new ProcessStartInfo(currentExe) { UseShellExecute = true });
            }
            finally
            {
                try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
            }
        }
    }
}
