using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace CloudFix
{
    // unified OAuth flow for CloudRedirect — dispatches to Google Drive or OneDrive
    // based on CloudConfig. the DLL handles token refresh; this just gets the initial
    // refresh_token via a one-time browser sign-in.
    internal static class CloudAuth
    {
        // Google Drive (clasp OAuth credentials)
        const string GDriveClientId = "1072944905499-vm2v2i5dvn0a0d2o4ca36i1vge8cvbn0.apps.googleusercontent.com";
        const string GDriveClientSecret = "v6V3fKV_zWU7iw1DrpO1rknX";
        const string GDriveScope = "https://www.googleapis.com/auth/drive.file";
        const string GDriveAuthEndpoint = "https://accounts.google.com/o/oauth2/auth";
        const string GDriveTokenEndpoint = "https://oauth2.googleapis.com/token";

        // OneDrive (Azure AD public client)
        const string OneDriveClientId = "c582f799-5dc5-48a7-a4cd-cd0d8af354a2";
        const string OneDriveScope = "Files.ReadWrite offline_access";
        const string OneDriveAuthEndpoint = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
        const string OneDriveTokenEndpoint = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";

        public static string TokenPath { get; private set; }

        public static void Init()
        {
            var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var dir = Path.Combine(appData, "CloudRedirect");
            Directory.CreateDirectory(dir);
            TokenPath = Path.Combine(dir, "tokens.json");
        }

        public enum Status { Authenticated, NotAuthenticated, Error }

        public static Status GetStatus()
        {
            if (!File.Exists(TokenPath))
                return Status.NotAuthenticated;

            try
            {
                using var json = JsonDocument.Parse(File.ReadAllText(TokenPath));
                var refresh = json.RootElement.GetProperty("refresh_token").GetString();
                return string.IsNullOrEmpty(refresh) ? Status.NotAuthenticated : Status.Authenticated;
            }
            catch
            {
                return Status.Error;
            }
        }

        public static void SignOut()
        {
            if (File.Exists(TokenPath))
                File.Delete(TokenPath);
        }

        // returns null on success, error string on failure
        public static async Task<string> RunSignIn()
        {
            bool isGDrive = CloudConfig.GetBackend() == "gdrive";

            // allocate a random port and start HttpListener on it.
            // retry up to 5 times to avoid TOCTOU race on port allocation.
            HttpListener listener = null;
            string redirectUri = null;
            for (int attempt = 0; attempt < 5; attempt++)
            {
                var tcp = new TcpListener(IPAddress.Loopback, 0);
                tcp.Start();
                int port = ((IPEndPoint)tcp.LocalEndpoint).Port;
                tcp.Stop();

                redirectUri = $"http://localhost:{port}/";
                listener = new HttpListener();
                listener.Prefixes.Add(redirectUri);
                try
                {
                    listener.Start();
                    break;
                }
                catch (HttpListenerException) when (attempt < 4)
                {
                    listener = null;
                }
            }
            if (listener == null)
                return "Failed to allocate a local port for OAuth callback after 5 attempts";

            // PKCE for OneDrive
            string codeVerifier = null;
            string codeChallenge = null;
            if (!isGDrive)
                (codeVerifier, codeChallenge) = GeneratePkce();

            try
            {
                // build auth URL — differs per backend
                string authUrl;
                if (isGDrive)
                {
                    authUrl =
                        GDriveAuthEndpoint +
                        $"?client_id={Uri.EscapeDataString(GDriveClientId)}" +
                        $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                        "&response_type=code" +
                        $"&scope={Uri.EscapeDataString(GDriveScope)}" +
                        "&access_type=offline" +
                        "&prompt=consent";
                }
                else
                {
                    authUrl =
                        OneDriveAuthEndpoint +
                        $"?client_id={Uri.EscapeDataString(OneDriveClientId)}" +
                        $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                        "&response_type=code" +
                        $"&scope={Uri.EscapeDataString(OneDriveScope)}" +
                        $"&code_challenge={Uri.EscapeDataString(codeChallenge)}" +
                        "&code_challenge_method=S256" +
                        "&prompt=consent";
                }

                Process.Start(new ProcessStartInfo(authUrl) { UseShellExecute = true });

                HttpListenerContext ctx;
                try
                {
                    var cts = new CancellationTokenSource(TimeSpan.FromMinutes(2));
                    ctx = await listener.GetContextAsync().WaitAsync(cts.Token);
                }
                catch (OperationCanceledException)
                {
                    return "Authentication timed out (2 minutes)";
                }

                var query = ctx.Request.Url?.Query ?? "";
                string code = ParseQueryParam(query, "code");
                string error = ParseQueryParam(query, "error");

                string html = !string.IsNullOrEmpty(code)
                    ? "<html><body style='font-family:sans-serif;text-align:center;padding:60px'>" +
                      "<h2>Authenticated! You can close this tab.</h2></body></html>"
                    : "<html><body style='font-family:sans-serif;text-align:center;padding:60px'>" +
                      "<h2>Authentication failed.</h2></body></html>";

                byte[] responseBytes = Encoding.UTF8.GetBytes(html);
                ctx.Response.ContentType = "text/html";
                ctx.Response.ContentLength64 = responseBytes.Length;
                await ctx.Response.OutputStream.WriteAsync(responseBytes);
                ctx.Response.Close();

                if (string.IsNullOrEmpty(code))
                    return $"Authentication failed: {error ?? "no authorization code received"}";

                // token exchange — Google uses client_secret, OneDrive uses PKCE code_verifier
                using var http = new HttpClient();
                var tokenParams = new Dictionary<string, string>
                {
                    ["code"] = code,
                    ["redirect_uri"] = redirectUri,
                    ["grant_type"] = "authorization_code"
                };

                string tokenEndpoint;
                if (isGDrive)
                {
                    tokenParams["client_id"] = GDriveClientId;
                    tokenParams["client_secret"] = GDriveClientSecret;
                    tokenEndpoint = GDriveTokenEndpoint;
                }
                else
                {
                    tokenParams["client_id"] = OneDriveClientId;
                    tokenParams["code_verifier"] = codeVerifier;
                    tokenParams["scope"] = OneDriveScope;
                    tokenEndpoint = OneDriveTokenEndpoint;
                }

                var tokenReq = new FormUrlEncodedContent(tokenParams);
                var tokenResp = await http.PostAsync(tokenEndpoint, tokenReq);
                var tokenBody = await tokenResp.Content.ReadAsStringAsync();

                if (!tokenResp.IsSuccessStatusCode)
                    return $"Token exchange failed: HTTP {(int)tokenResp.StatusCode}\n{tokenBody}";

                using var tokenJson = JsonDocument.Parse(tokenBody);
                string accessToken = tokenJson.RootElement.GetProperty("access_token").GetString();
                int expiresIn = tokenJson.RootElement.GetProperty("expires_in").GetInt32();
                string refreshToken = tokenJson.RootElement.GetProperty("refresh_token").GetString();
                long expiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + expiresIn;

                var tokenOut = "{\n" +
                    $"  \"access_token\": \"{EscapeJson(accessToken)}\",\n" +
                    $"  \"refresh_token\": \"{EscapeJson(refreshToken)}\",\n" +
                    $"  \"expires_at\": {expiresAt}\n" +
                    "}";
                File.WriteAllText(TokenPath, tokenOut);

                return null;
            }
            finally
            {
                listener.Stop();
            }
        }

        // PKCE helpers (OneDrive only)
        static (string verifier, string challenge) GeneratePkce()
        {
            var bytes = new byte[32];
            RandomNumberGenerator.Fill(bytes);
            string verifier = Base64UrlEncode(bytes);
            using var sha256 = SHA256.Create();
            string challenge = Base64UrlEncode(sha256.ComputeHash(Encoding.ASCII.GetBytes(verifier)));
            return (verifier, challenge);
        }

        static string Base64UrlEncode(byte[] data)
        {
            return Convert.ToBase64String(data)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        static string ParseQueryParam(string query, string name)
        {
            if (string.IsNullOrEmpty(query))
                return null;

            if (query[0] == '?')
                query = query[1..];

            foreach (var pair in query.Split('&'))
            {
                var eq = pair.IndexOf('=');
                if (eq < 0) continue;
                var key = Uri.UnescapeDataString(pair[..eq]);
                if (key == name)
                    return Uri.UnescapeDataString(pair[(eq + 1)..]);
            }
            return null;
        }

        static string EscapeJson(string s)
        {
            return s.Replace("\\", "\\\\")
                    .Replace("\"", "\\\"")
                    .Replace("\n", "\\n")
                    .Replace("\r", "\\r")
                    .Replace("\t", "\\t");
        }
    }
}
