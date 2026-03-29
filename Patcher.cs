using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;

namespace CloudFix
{
    internal class Patcher
    {
        static readonly string[] HijackCandidates = { "xinput1_4.dll", "dwmapi.dll" };

        static readonly byte[] AesKey =
        {
            0x31, 0x4C, 0x20, 0x86, 0x15, 0x05, 0x74, 0xE1,
            0x5C, 0xF1, 0x1D, 0x1B, 0xC1, 0x71, 0x25, 0x1A,
            0x47, 0x08, 0x6C, 0x00, 0x26, 0x93, 0x55, 0xCD,
            0x51, 0xC9, 0x3A, 0x42, 0x3C, 0x14, 0x02, 0x94,
        };

        // hardcoded offsets for current known version - sig scan fallback if these miss
        static readonly PatchEntry[] CorePatches =
        {
            new PatchEntry(0x272F,
                new byte[] { 0xE8, 0x7C, 0xF5, 0xFF, 0xFF },
                new byte[] { 0xB8, 0x01, 0x00, 0x00, 0x00 }),
            new PatchEntry(0x28B5,
                new byte[] { 0x74 },
                new byte[] { 0xEB }),
        };

        static readonly PatchEntry[] PayloadPatches =
        {
            new PatchEntry(0x0D4CF,
                new byte[] { 0x0F, 0x84, 0x3B, 0x01, 0x00, 0x00 },
                new byte[] { 0x90, 0xE9, 0x3B, 0x01, 0x00, 0x00 }),
            new PatchEntry(0x0D7D9,
                new byte[] { 0x8B, 0x0D, 0x7D, 0xCA, 0x1B, 0x00 },
                new byte[] { 0x31, 0xC9, 0x90, 0x90, 0x90, 0x90 }),
            new PatchEntry(0x1D555A,
                new byte[] { 0x89, 0x3D, 0x28, 0xD5, 0xFE, 0xFF },
                new byte[] { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 }),
            new PatchEntry(0x1E0A15,
                new byte[] { 0xC6, 0x05, 0xC6, 0x20, 0xFE, 0xFF, 0x00 },
                new byte[] { 0xC6, 0x05, 0xC6, 0x20, 0xFE, 0xFF, 0x01 }),
            new PatchEntry(0x3BAE0,
                new byte[] { 0x75 },
                new byte[] { 0xEB }),
        };

        // v4 diagnostic: P10 = prologue capture at sub_18000D3C0 entry,
        // P7 = retry loop redirect to fallback_stub, P8 = .text WRITE flag
        static readonly PatchEntry[] FallbackPatches =
        {
            new PatchEntry(0xC7C0,
                new byte[] { 0x48, 0x89, 0x74, 0x24, 0x18 },
                new byte[] { 0xE9, 0x43, 0x8F, 0x16, 0x00 }),
            new PatchEntry(0xC7EC,
                new byte[] { 0x75, 0x3D },
                new byte[] { 0x90, 0x90 }),
            new PatchEntry(0xC803,
                new byte[] { 0xE8, 0x58, 0x57, 0x03, 0x00 },
                new byte[] { 0xE8, 0x1F, 0x8F, 0x16, 0x00 }),
            new PatchEntry(0x1AC,
                new byte[] { 0x20, 0x00, 0x00, 0x60 },
                new byte[] { 0x20, 0x00, 0x00, 0xE0 }),
        };

        const int CodeCaveFileOffset = 0x1756F0;

        static readonly byte[] CodeCaveContent =
        {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x0D, 0xE1, 0xFF, 0xFF, 0xFF, 0x48,
            0x89, 0x15, 0xE2, 0xFF, 0xFF, 0xFF, 0x4C, 0x89, 0x05, 0xE3, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x74,
            0x24, 0x18, 0xE9, 0x9E, 0x70, 0xE9, 0xFF, 0x53, 0x57, 0x56, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x8B,
            0xF1, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x48, 0x8D, 0x0D, 0x3E, 0x00,
            0x00, 0x00, 0xFF, 0x15, 0x08, 0x0F, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x2F, 0x48, 0x8B, 0xF8,
            0x48, 0x8D, 0x15, 0x3D, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xCF, 0xFF, 0x15, 0x40, 0x12, 0x00, 0x00,
            0x48, 0x85, 0xC0, 0x74, 0x17, 0x48, 0x8B, 0xD8, 0x48, 0x8B, 0x0D, 0x91, 0xFF, 0xFF, 0xFF, 0x48,
            0x8B, 0xD6, 0xFF, 0xD3, 0x48, 0x83, 0xC4, 0x30, 0x5E, 0x5F, 0x5B, 0xC3, 0x31, 0xC0, 0xEB, 0xF4,
            0x73, 0x74, 0x65, 0x6C, 0x6C, 0x61, 0x5F, 0x66, 0x61, 0x6C, 0x6C, 0x62, 0x61, 0x63, 0x6B, 0x2E,
            0x64, 0x6C, 0x6C, 0x00, 0x53, 0x74, 0x65, 0x6C, 0x6C, 0x61, 0x47, 0x65, 0x74, 0x52, 0x65, 0x71,
            0x75, 0x65, 0x73, 0x74, 0x43, 0x6F, 0x64, 0x65, 0x00,
        };

        string _steamPath;
        bool _verbose;

        byte[] _cachedPayload;
        long _cachedPayloadTicks;

        public Patcher(string steamPath)
        {
            _steamPath = steamPath;
        }

        static byte[] ReadFileShared(string path)
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var buf = new byte[fs.Length];
            fs.ReadExactly(buf);
            return buf;
        }

        byte[] GetDecryptedPayload(string cachePath)
        {
            var info = new FileInfo(cachePath);
            if (!info.Exists) return null;

            long ticks = info.LastWriteTimeUtc.Ticks;
            if (_cachedPayload != null && _cachedPayloadTicks == ticks)
                return _cachedPayload;

            byte[] raw;
            try
            {
                using var fs = new FileStream(cachePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                raw = new byte[fs.Length];
                fs.ReadExactly(raw);
            }
            catch (IOException) { return null; }

            if (raw.Length < 32) return null;

            try
            {
                var iv = raw.AsSpan(0, 16).ToArray();
                var ct = raw.AsSpan(16).ToArray();
                var dec = AesCbcDecrypt(ct, AesKey, iv);
                using var zIn = new ZLibStream(
                    new MemoryStream(dec, 4, dec.Length - 4),
                    CompressionMode.Decompress);
                using var ms = new MemoryStream();
                zIn.CopyTo(ms);
                _cachedPayload = ms.ToArray();
                _cachedPayloadTicks = ticks;
                return _cachedPayload;
            }
            catch { return null; }
        }

        (byte[] payload, byte[] iv, string error) ReadAndDecryptPayload(string cachePath)
        {
            byte[] raw;
            try { raw = ReadFileShared(cachePath); }
            catch (IOException) { return (null, null, "Payload cache is in use - close Steam first"); }

            if (raw.Length < 32)
                return (null, null, "Cache file too small");

            var iv = raw.AsSpan(0, 16).ToArray();
            var ct = raw.AsSpan(16).ToArray();

            Log("  Decrypting..");
            byte[] dec;
            try { dec = AesCbcDecrypt(ct, AesKey, iv); }
            catch (Exception ex) { return (null, null, $"Decryption failed: {ex.Message}"); }

            byte[] payload;
            try
            {
                using var zIn = new ZLibStream(
                    new MemoryStream(dec, 4, dec.Length - 4),
                    CompressionMode.Decompress);
                using var ms = new MemoryStream();
                zIn.CopyTo(ms);
                payload = ms.ToArray();
            }
            catch (Exception ex) { return (null, null, $"Decompression failed: {ex.Message}"); }

            Log($"  Payload: {payload.Length} bytes");
            return (payload, iv, null);
        }

        string FindCoreDll()
        {
            foreach (var name in HijackCandidates)
            {
                var path = Path.Combine(_steamPath, name);
                if (!File.Exists(path)) continue;

                try
                {
                    using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    var buf = new byte[fs.Length];
                    fs.ReadExactly(buf);

                    if (Signatures.ScanForBytes(buf, 0, buf.Length, AesKey) >= 0)
                        return name;
                }
                catch (IOException) { }
            }
            return null;
        }

        public PatchState GetPatchState()
        {
            _verbose = false;
            var hijackDll = FindCoreDll();
            if (hijackDll == null)
                return PatchState.NotInstalled;

            var dllPath = Path.Combine(_steamPath, hijackDll);

            byte[] dll;
            try
            {
                using var fs = new FileStream(dllPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                dll = new byte[fs.Length];
                fs.ReadExactly(dll);
            }
            catch (IOException)
            {
                return PatchState.UnknownVersion;
            }

            var resolvedCore = ResolveCorePatchOffsets(dll);
            if (resolvedCore == null)
                return PatchState.UnknownVersion;

            var (_, applied, skipped, errors) = CheckPatches(dll, resolvedCore);

            if (errors.Count > 0)
                return PatchState.UnknownVersion;
            if (applied == 0 && skipped == resolvedCore.Length)
                return PatchState.Patched;
            if (skipped == 0 && applied == resolvedCore.Length)
                return PatchState.Unpatched;

            return PatchState.PartiallyPatched;
        }

        public PatchState GetOfflinePatchState()
        {
            _verbose = false;

            var cachePath = Fingerprint.FindCachePath(_steamPath, verbose: false);
            if (cachePath == null)
                return PatchState.NotInstalled;

            var payload = GetDecryptedPayload(cachePath);
            if (payload == null)
                return PatchState.UnknownVersion;

            var resolved = ResolveSetupPatchOffsets(payload);
            if (resolved == null)
                return PatchState.UnknownVersion;

            var (_, applied, skipped, errors) = CheckPatches(payload, resolved);

            if (errors.Count > 0)
                return PatchState.UnknownVersion;
            if (applied == 0 && skipped == resolved.Length)
                return PatchState.Patched;
            if (skipped == 0 && applied == resolved.Length)
                return PatchState.Unpatched;

            return PatchState.PartiallyPatched;
        }

        public PatchResult ApplyOfflineSetup()
        {
            _verbose = true;
            var result = new PatchResult();

            try
            {
                var hijackDll = FindCoreDll();
                if (hijackDll == null)
                    return result.Fail("SteamTools Core DLL not found. Is SteamTools installed?");

                var dllPath = Path.Combine(_steamPath, hijackDll);
                byte[] dllData;
                try { dllData = ReadFileShared(dllPath); }
                catch (IOException) { return result.Fail($"{hijackDll} is in use - close Steam first"); }

                Log($"Patching {hijackDll}..");
                var resolvedCore = ResolveCorePatchOffsets(dllData);
                if (resolvedCore == null)
                    return result.Fail($"Could not identify patch locations in {hijackDll} - unsupported version?");

                var (patchedDll, dllApplied, dllSkipped, dllErrors) = ApplyPatches(dllData, resolvedCore);
                if (dllErrors.Count > 0)
                {
                    foreach (var err in dllErrors) Log(err);
                    return result.Fail("Byte mismatch in " + hijackDll + " - wrong version?");
                }

                var cachePath = Fingerprint.FindCachePath(_steamPath);
                if (cachePath == null)
                {
                    Log("Payload cache not found. Deploying embedded payload..");
                    cachePath = DeployEmbeddedPayload();
                    if (cachePath == null)
                        return result.Fail("Could not deploy payload cache.");
                }

                Log("Patching payload (offline setup)..");

                var (payload, iv, plErr) = ReadAndDecryptPayload(cachePath);
                if (payload == null)
                    return result.Fail(plErr);

                var resolvedSetup = ResolveSetupPatchOffsets(payload);
                if (resolvedSetup == null)
                    return result.Fail("Could not identify activation patch locations in payload - unsupported version?");

                var (patchedPayload, plApplied, plSkipped, plErrors) = ApplyPatches(payload, resolvedSetup);
                if (plErrors.Count > 0)
                {
                    foreach (var err in plErrors) Log(err);
                    return result.Fail("Byte mismatch in payload - wrong version?");
                }

                // all patches verified - now write both files
                Backup(dllPath);
                if (dllApplied > 0)
                {
                    File.WriteAllBytes(dllPath, patchedDll);
                    Log($"  {dllApplied} patch(es) applied to {hijackDll}" + (dllSkipped > 0 ? $", {dllSkipped} already done" : ""));
                }
                else
                {
                    Log($"  {hijackDll}: already patched");
                }
                result.DllPatched = true;

                Backup(cachePath);
                if (plApplied > 0)
                {
                    ReEncryptAndWrite(cachePath, patchedPayload, iv);
                    Log($"  {plApplied} patch(es) applied to payload" + (plSkipped > 0 ? $", {plSkipped} already done" : ""));
                }
                else
                {
                    Log("  Payload: already patched");
                }
                result.CachePatched = true;

                result.Succeeded = true;
                Log("Done.");
            }
            catch (Exception ex)
            {
                result.Fail($"Unexpected error: {ex.Message}");
                Log($"Error: {ex.Message}");
            }

            return result;
        }

        public PatchResult Apply()
        {
            _verbose = true;
            var result = new PatchResult();

            try
            {
                var hijackDll = FindCoreDll();
                if (hijackDll == null)
                    return result.Fail("SteamTools Core DLL not found. Is SteamTools installed?");

                var dllPath = Path.Combine(_steamPath, hijackDll);
                byte[] dllData;
                try { dllData = ReadFileShared(dllPath); }
                catch (IOException) { return result.Fail($"{hijackDll} is in use - close Steam first"); }

                Log($"Patching {hijackDll}..");
                var resolvedCore = ResolveCorePatchOffsets(dllData);
                if (resolvedCore == null)
                    return result.Fail($"Could not identify patch locations in {hijackDll} - unsupported version?");

                var (patchedDll, dllApplied, dllSkipped, dllErrors) = ApplyPatches(dllData, resolvedCore);
                if (dllErrors.Count > 0)
                {
                    foreach (var err in dllErrors) Log(err);
                    return result.Fail("Byte mismatch in " + hijackDll + " - wrong version?");
                }

                var cachePath = Fingerprint.FindCachePath(_steamPath);
                byte[] patchedPayload = null;
                byte[] iv = null;
                int plApplied = 0, plSkipped = 0;

                if (cachePath != null)
                {
                    Log("Patching payload in cache..");

                    byte[] payload;
                    (payload, iv, var plErr) = ReadAndDecryptPayload(cachePath);
                    if (payload == null)
                        return result.Fail(plErr);

                    var resolvedPayload = ResolvePayloadPatchOffsets(payload);
                    if (resolvedPayload == null)
                        return result.Fail("Could not identify patch locations in payload - unsupported version?");

                    List<string> plErrors;
                    (patchedPayload, plApplied, plSkipped, plErrors) = ApplyPatches(payload, resolvedPayload);
                    if (plErrors.Count > 0)
                    {
                        foreach (var err in plErrors) Log(err);
                        return result.Fail("Byte mismatch in payload - wrong version?");
                    }
                }

                // all patches verified - now write
                Backup(dllPath);
                if (dllApplied > 0)
                {
                    File.WriteAllBytes(dllPath, patchedDll);
                    Log($"  {dllApplied} patch(es) applied to {hijackDll}" + (dllSkipped > 0 ? $", {dllSkipped} already done" : ""));
                }
                else
                {
                    Log($"  {hijackDll}: already patched");
                }
                result.DllPatched = true;

                if (cachePath == null)
                {
                    Log("Payload cache not found. Run offline setup first, or wait for SteamTools to download it.");
                }
                else
                {
                    Backup(cachePath);
                    if (plApplied > 0)
                    {
                        ReEncryptAndWrite(cachePath, patchedPayload, iv);
                        Log($"  {plApplied} patch(es) applied to payload" + (plSkipped > 0 ? $", {plSkipped} already done" : ""));
                    }
                    else
                    {
                        Log("  Payload: already patched");
                    }
                    result.CachePatched = true;
                }

                result.Succeeded = true;
                Log("Done.");
            }
            catch (Exception ex)
            {
                result.Fail($"Unexpected error: {ex.Message}");
                Log($"Error: {ex.Message}");
            }

            return result;
        }

        public PatchResult Restore()
        {
            _verbose = true;
            var result = new PatchResult();
            int restored = 0;

            try
            {
                foreach (var name in HijackCandidates)
                {
                    var dllPath = Path.Combine(_steamPath, name);
                    if (RestoreBackup(dllPath, name))
                    {
                        restored++;
                        break;
                    }
                }

                var cachePath = Fingerprint.FindCachePath(_steamPath);
                if (cachePath != null && RestoreBackup(cachePath, "payload cache"))
                    restored++;
                else
                {
                    var cacheDir = Path.Combine(_steamPath, "appcache", "httpcache", "3b");
                    if (Directory.Exists(cacheDir))
                    {
                        foreach (var f in Directory.GetFiles(cacheDir, "*.bak").Concat(
                                          Directory.GetFiles(cacheDir, "*.orig")))
                        {
                            var ext = Path.GetExtension(f);
                            var basePath = f[..^ext.Length];
                            var fname = Path.GetFileName(basePath);
                            if (fname.Length == 16)
                            {
                                RestoreBackup(basePath, "payload cache");
                                restored++;
                                break;
                            }
                        }
                    }
                }

                if (restored > 0)
                {
                    CleanupStellaFiles();
                    Log($"Restored {restored} file(s).");
                    result.Succeeded = true;
                }
                else
                {
                    Log("Nothing to restore (no backups found).");
                    result.Succeeded = true;
                }
            }
            catch (Exception ex)
            {
                result.Fail($"Restore failed: {ex.Message}");
                Log($"Error: {ex.Message}");
            }

            return result;
        }

        public PatchState GetFallbackPatchState()
        {
            _verbose = false;

            var cachePath = Fingerprint.FindCachePath(_steamPath, verbose: false);
            if (cachePath == null)
                return PatchState.NotInstalled;

            var payload = GetDecryptedPayload(cachePath);
            if (payload == null)
                return PatchState.UnknownVersion;

            var resolved = ResolveFallbackPatchOffsets(payload);
            if (resolved == null)
                return PatchState.UnknownVersion;

            var (_, applied, skipped, errors) = CheckPatches(payload, resolved);

            if (errors.Count > 0)
                return PatchState.UnknownVersion;

            bool caveWritten = CodeCaveFileOffset + CodeCaveContent.Length <= payload.Length
                && BytesMatch(payload, CodeCaveFileOffset, CodeCaveContent, 0, CodeCaveContent.Length);

            if (applied == 0 && skipped == resolved.Length)
                return caveWritten ? PatchState.Patched : PatchState.OutOfDate;
            if (skipped == 0 && applied == resolved.Length)
                return PatchState.Unpatched;

            return PatchState.PartiallyPatched;
        }

        public PatchResult ApplyFallback(string apiKey)
        {
            _verbose = true;
            var result = new PatchResult();

            try
            {
                var cachePath = Fingerprint.FindCachePath(_steamPath);
                if (cachePath == null)
                {
                    Log("Payload cache not found. Deploying embedded payload..");
                    cachePath = DeployEmbeddedPayload();
                    if (cachePath == null)
                        return result.Fail("Could not deploy payload cache.");
                }

                Log("Patching payload (Morrenus fallback)..");
                Backup(cachePath);

                var (payload, iv, plErr) = ReadAndDecryptPayload(cachePath);
                if (payload == null)
                    return result.Fail(plErr);

                var resolved = ResolveFallbackPatchOffsets(payload);
                if (resolved == null)
                    return result.Fail("Could not locate fallback patch sites in payload");

                var (patchedPayload, plApplied, plSkipped, plErrors) = ApplyPatches(payload, resolved);
                if (plErrors.Count > 0)
                {
                    foreach (var err in plErrors) Log(err);
                    return result.Fail("Byte mismatch at fallback patch sites");
                }

                if (CodeCaveFileOffset + CodeCaveContent.Length > patchedPayload.Length)
                    return result.Fail("Payload too small for code cave injection");

                bool caveAlready = BytesMatch(patchedPayload, CodeCaveFileOffset,
                    CodeCaveContent, 0, CodeCaveContent.Length);

                var stellaErr = DeployStella(apiKey);
                if (stellaErr != null)
                    return result.Fail(stellaErr);

                if (plApplied > 0 || !caveAlready)
                {
                    Buffer.BlockCopy(CodeCaveContent, 0, patchedPayload, CodeCaveFileOffset, CodeCaveContent.Length);
                    ReEncryptAndWrite(cachePath, patchedPayload, iv);
                    int total = plApplied + (caveAlready ? 0 : 1);
                    Log($"  {total} change(s) applied" + (plSkipped > 0 ? $", {plSkipped} already done" : ""));
                }
                else
                {
                    Log("  Already patched");
                }
                result.CachePatched = true;

                result.Succeeded = true;
                Log("Done.");
            }
            catch (Exception ex)
            {
                result.Fail($"Unexpected error: {ex.Message}");
                Log($"Error: {ex.Message}");
            }

            return result;
        }

        string DeployStella(string apiKey)
        {
            var dllDest = Path.Combine(_steamPath, "stella_fallback.dll");
            var cfgDest = Path.Combine(_steamPath, "stella.cfg");

            using var stream = typeof(Patcher).Assembly
                .GetManifestResourceStream("stella_fallback.dll");
            if (stream != null)
            {
                try
                {
                    using var fs = new FileStream(dllDest, FileMode.Create, FileAccess.Write);
                    stream.CopyTo(fs);
                    Log($"  Deployed stella_fallback.dll to {_steamPath}");
                }
                catch (IOException)
                {
                    return "stella_fallback.dll is in use (close Steam first)";
                }
            }
            else
            {
                return "stella_fallback.dll not embedded in build";
            }

            if (!string.IsNullOrWhiteSpace(apiKey))
            {
                File.WriteAllText(cfgDest, apiKey.Trim());
                Log($"  Wrote API key to stella.cfg");
            }
            else if (!File.Exists(cfgDest))
            {
                return "no API key provided and stella.cfg not found";
            }

            return null;
        }

        void Log(string msg)
        {
            if (_verbose) Program.PrintLine(msg);
        }

        string DeployEmbeddedPayload()
        {
            try
            {
                var cachePath = Fingerprint.GetExpectedCachePath(_steamPath);
                var dir = Path.GetDirectoryName(cachePath);
                if (!Directory.Exists(dir))
                    Directory.CreateDirectory(dir);

                using var stream = typeof(Patcher).Assembly
                    .GetManifestResourceStream("payload.cache");
                if (stream == null)
                {
                    Log("  Embedded payload not found in assembly");
                    return null;
                }

                using var fs = new FileStream(cachePath, FileMode.Create, FileAccess.Write);
                stream.CopyTo(fs);

                Log($"  Deployed to {cachePath}");
                return cachePath;
            }
            catch (Exception ex)
            {
                Log($"  Deploy failed: {ex.Message}");
                return null;
            }
        }

        void Backup(string path)
        {
            var orig = path + ".orig";
            if (!File.Exists(orig))
            {
                File.Copy(path, orig);
                Log($"  Original saved to {orig}");
            }

            var bak = path + ".bak";
            File.Copy(path, bak, overwrite: true);
            Log($"  Backed up to {bak}");
        }

        bool RestoreBackup(string path, string label)
        {
            var orig = path + ".orig";
            var bak = path + ".bak";

            string source = File.Exists(orig) ? orig : File.Exists(bak) ? bak : null;
            if (source == null)
            {
                Log($"  {label}: no backup found");
                return false;
            }

            File.Copy(source, path, overwrite: true);

            // clean up both backup files
            try { if (File.Exists(orig)) File.Delete(orig); } catch { }
            try { if (File.Exists(bak)) File.Delete(bak); } catch { }

            Log($"  {label}: restored from {(source == orig ? "original" : "backup")}");
            return true;
        }

        void CleanupStellaFiles()
        {
            string[] names = { "stella_fallback.dll", "stella.cfg", "stella_debug.log" };
            foreach (var name in names)
            {
                var path = Path.Combine(_steamPath, name);
                try
                {
                    if (File.Exists(path))
                    {
                        File.Delete(path);
                        Log($"  Removed {name}");
                    }
                }
                catch (IOException) { }
            }
        }

        static byte[] AesCbcDecrypt(byte[] ct, byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.Key = key; aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            using var dec = aes.CreateDecryptor();
            return dec.TransformFinalBlock(ct, 0, ct.Length);
        }

        static byte[] AesCbcEncrypt(byte[] pt, byte[] key, byte[] iv)
        {
            using var aes = Aes.Create();
            aes.Key = key; aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            using var enc = aes.CreateEncryptor();
            return enc.TransformFinalBlock(pt, 0, pt.Length);
        }

        void ReEncryptAndWrite(string cachePath, byte[] patchedPayload, byte[] iv)
        {
            Log("  Re-encrypting..");
            using var compMs = new MemoryStream();
            using (var zOut = new ZLibStream(compMs, CompressionLevel.Optimal, leaveOpen: true))
                zOut.Write(patchedPayload, 0, patchedPayload.Length);

            var blob = new byte[4 + compMs.Length];
            BitConverter.TryWriteBytes(blob.AsSpan(0, 4), patchedPayload.Length);
            compMs.ToArray().CopyTo(blob, 4);

            var newCt = AesCbcEncrypt(blob, AesKey, iv);
            var output = new byte[16 + newCt.Length];
            iv.CopyTo(output, 0);
            newCt.CopyTo(output, 16);
            File.WriteAllBytes(cachePath, output);
        }

        static bool BytesMatch(byte[] data, int dataOffset, byte[] pattern, int patOffset, int length)
        {
            if (dataOffset + length > data.Length) return false;
            for (int i = 0; i < length; i++)
                if (data[dataOffset + i] != pattern[patOffset + i]) return false;
            return true;
        }

        static PatchEntry SnapshotPatch(byte[] data, int offset, PatchEntry template,
            int wildcardStart = 0, int wildcardLen = 0)
        {
            int len = template.Original.Length;
            var orig = (byte[])template.Original.Clone();
            var repl = (byte[])template.Replacement.Clone();

            if (wildcardLen > 0 && wildcardStart + wildcardLen <= len)
            {
                Buffer.BlockCopy(data, offset + wildcardStart, orig, wildcardStart, wildcardLen);
                Buffer.BlockCopy(data, offset + wildcardStart, repl, wildcardStart, wildcardLen);
            }

            return new PatchEntry(offset, orig, repl);
        }

        static (byte[] data, int applied, int skipped, List<string> errors) CheckPatches(byte[] data, PatchEntry[] patches)
        {
            int applied = 0, skipped = 0;
            var errors = new List<string>();

            foreach (var p in patches)
            {
                if (BytesMatch(data, p.Offset, p.Replacement, 0, p.Replacement.Length))
                    skipped++;
                else if (BytesMatch(data, p.Offset, p.Original, 0, p.Original.Length))
                    applied++;
                else
                    errors.Add($"  Mismatch at 0x{p.Offset:X}: expected {BitConverter.ToString(p.Original)}, got {BitConverter.ToString(data, p.Offset, p.Original.Length)}");
            }

            return (data, applied, skipped, errors);
        }

        static (byte[] data, int applied, int skipped, List<string> errors) ApplyPatches(byte[] data, PatchEntry[] patches)
        {
            var buf = (byte[])data.Clone();
            int applied = 0, skipped = 0;
            var errors = new List<string>();

            foreach (var p in patches)
            {
                if (BytesMatch(buf, p.Offset, p.Replacement, 0, p.Replacement.Length))
                {
                    skipped++;
                }
                else if (BytesMatch(buf, p.Offset, p.Original, 0, p.Original.Length))
                {
                    Buffer.BlockCopy(p.Replacement, 0, buf, p.Offset, p.Replacement.Length);
                    applied++;
                }
                else
                {
                    errors.Add($"  Mismatch at 0x{p.Offset:X}: expected {BitConverter.ToString(p.Original)}, got {BitConverter.ToString(buf, p.Offset, p.Original.Length)}");
                }
            }

            return (buf, applied, skipped, errors);
        }

        int TryHardcodedOrScan(byte[] data, int hardcoded,
            byte[] original, byte[] replacement, Func<int> scanFunc)
        {
            if (hardcoded >= 0 && hardcoded + original.Length <= data.Length)
            {
                if (BytesMatch(data, hardcoded, original, 0, original.Length) ||
                    BytesMatch(data, hardcoded, replacement, 0, replacement.Length))
                    return hardcoded;
            }

            Log("    Hardcoded offset miss, scanning..");
            return scanFunc();
        }

        PatchEntry[] ResolveCorePatchOffsets(byte[] dll)
        {
            var sections = PeSection.Parse(dll);
            var rdataSec = PeSection.Find(sections, ".rdata");
            if (rdataSec == null)
            {
                Log("  Core.dll: no .rdata section found");
                return null;
            }

            int keyOffset = Signatures.ScanForBytes(dll, rdataSec.Value.RawOffset,
                rdataSec.Value.RawOffset + rdataSec.Value.RawSize, AesKey);
            if (keyOffset < 0)
                keyOffset = Signatures.ScanForBytes(dll, 0, dll.Length, AesKey);
            if (keyOffset < 0)
            {
                Log("  Core.dll: AES key not found - not a recognized SteamTools version");
                return null;
            }
            Log($"  AES key found at 0x{keyOffset:X}");

            var textSec = PeSection.Find(sections, ".text");
            if (textSec == null)
            {
                Log("  Core.dll: no .text section found");
                return null;
            }
            int tStart = textSec.Value.RawOffset;
            int tEnd = tStart + textSec.Value.RawSize;

            int p1 = TryHardcodedOrScan(dll, CorePatches[0].Offset,
                CorePatches[0].Original, CorePatches[0].Replacement,
                () => Signatures.FindCorePatch1(dll, tStart, tEnd));

            if (p1 < 0)
            {
                Log("  Core.dll: could not locate patch 1 (download call)");
                return null;
            }

            int p2 = TryHardcodedOrScan(dll, CorePatches[1].Offset,
                CorePatches[1].Original, CorePatches[1].Replacement,
                () => Signatures.FindCorePatch2(dll, p1, Math.Min(p1 + 0x300, tEnd)));

            if (p2 < 0)
            {
                Log("  Core.dll: could not locate patch 2 (hash check jump)");
                return null;
            }

            Log($"  Core patches at 0x{p1:X}, 0x{p2:X}");
            return new PatchEntry[]
            {
                SnapshotPatch(dll, p1, CorePatches[0]),
                SnapshotPatch(dll, p2, CorePatches[1]),
            };
        }

        bool ResolvePayloadSections(byte[] payload, out int tStart, out int tEnd, out int gStart, out int gEnd)
        {
            tStart = tEnd = gStart = gEnd = 0;
            var sections = PeSection.Parse(payload);
            var textSec = PeSection.Find(sections, ".text");

            // obfuscated section has a random name each build - find by excluding standard ones
            var knownNames = new HashSet<string> { ".text", ".rdata", ".data", ".pdata", ".fptable", ".rsrc", ".reloc" };
            PeSection? obfSec = null;
            foreach (var sec in sections)
            {
                if (!knownNames.Contains(sec.Name))
                {
                    obfSec = sec;
                    break;
                }
            }

            if (textSec == null || obfSec == null)
            {
                Log("  Payload: missing expected sections");
                return false;
            }

            tStart = textSec.Value.RawOffset;
            tEnd = tStart + textSec.Value.RawSize;
            gStart = obfSec.Value.RawOffset;
            gEnd = gStart + obfSec.Value.RawSize;
            return true;
        }

        PatchEntry[] ResolvePayloadPatchOffsets(byte[] payload)
        {
            if (!ResolvePayloadSections(payload, out int tStart, out int tEnd, out int gStart, out int gEnd))
                return null;

            int p1 = TryHardcodedOrScan(payload, PayloadPatches[0].Offset,
                PayloadPatches[0].Original, PayloadPatches[0].Replacement,
                () => Signatures.FindPayloadPatch1(payload, tStart, tEnd));
            if (p1 < 0)
            {
                Log("  Payload: could not locate patch 1 (cloud rewrite skip)");
                return null;
            }

            int p2 = TryHardcodedOrScan(payload, PayloadPatches[1].Offset,
                PayloadPatches[1].Original, PayloadPatches[1].Replacement,
                () => Signatures.FindPayloadPatch2(payload, p1, Math.Min(p1 + 0x500, tEnd)));
            if (p2 < 0)
            {
                Log("  Payload: could not locate patch 2 (proxy appid zero)");
                return null;
            }

            int p3 = TryHardcodedOrScan(payload, PayloadPatches[2].Offset,
                PayloadPatches[2].Original, PayloadPatches[2].Replacement,
                () => Signatures.FindPayloadPatch3(payload, gStart, gEnd));
            if (p3 < 0)
            {
                Log("  Payload: could not locate patch 3 (IPC appid preserve)");
                return null;
            }

            Log($"  Payload patches at 0x{p1:X}, 0x{p2:X}, 0x{p3:X}");
            return new PatchEntry[]
            {
                SnapshotPatch(payload, p1, PayloadPatches[0], wildcardStart: 2, wildcardLen: 4),
                SnapshotPatch(payload, p2, PayloadPatches[1]),
                SnapshotPatch(payload, p3, PayloadPatches[2]),
            };
        }

        PatchEntry[] ResolveSetupPatchOffsets(byte[] payload)
        {
            if (!ResolvePayloadSections(payload, out int tStart, out int tEnd, out int gStart, out int gEnd))
                return null;

            int p4 = TryHardcodedOrScan(payload, PayloadPatches[3].Offset,
                PayloadPatches[3].Original, PayloadPatches[3].Replacement,
                () => Signatures.FindPayloadPatch4(payload, gStart, gEnd));
            if (p4 < 0)
            {
                Log("  Payload: could not locate activation flag patch");
                return null;
            }

            int p5 = TryHardcodedOrScan(payload, PayloadPatches[4].Offset,
                PayloadPatches[4].Original, PayloadPatches[4].Replacement,
                () => Signatures.FindPayloadPatch5(payload, tStart, tEnd));
            if (p5 < 0)
            {
                Log("  Payload: could not locate GetCookie retry patch");
                return null;
            }

            Log($"  Setup patches at 0x{p4:X}, 0x{p5:X}");
            return new PatchEntry[]
            {
                SnapshotPatch(payload, p4, PayloadPatches[3], wildcardStart: 2, wildcardLen: 4),
                SnapshotPatch(payload, p5, PayloadPatches[4]),
            };
        }

        PatchEntry[] ResolveFallbackPatchOffsets(byte[] payload)
        {
            if (!ResolvePayloadSections(payload, out int tStart, out int tEnd, out _, out _))
                return null;

            int p10 = TryHardcodedOrScan(payload, FallbackPatches[0].Offset,
                FallbackPatches[0].Original, FallbackPatches[0].Replacement,
                () => Signatures.FindPayloadPatch10(payload, tStart, tEnd));
            if (p10 < 0)
            {
                Log("  Payload: could not locate Flow #3 prologue (sub_18000D3C0)");
                return null;
            }

            // jnz is always 0x2C bytes after function start
            int pJnz = p10 + 0x2C;
            if (pJnz + 2 > payload.Length ||
                (!BytesMatch(payload, pJnz, FallbackPatches[1].Original, 0, 2) &&
                 !BytesMatch(payload, pJnz, FallbackPatches[1].Replacement, 0, 2)))
            {
                Log("  Payload: could not locate jnz (result==15 check)");
                return null;
            }

            int p7 = TryHardcodedOrScan(payload, FallbackPatches[2].Offset,
                FallbackPatches[2].Original, FallbackPatches[2].Replacement,
                () => Signatures.FindPayloadPatch7(payload, tStart, tEnd));
            if (p7 < 0)
            {
                Log("  Payload: could not locate hook call site");
                return null;
            }

            int p8 = TryHardcodedOrScan(payload, FallbackPatches[3].Offset,
                FallbackPatches[3].Original, FallbackPatches[3].Replacement,
                () => Signatures.FindPayloadPatch8(payload));
            if (p8 < 0)
            {
                Log("  Payload: could not locate .text section header");
                return null;
            }

            Log($"  Fallback patches at 0x{p10:X}, 0x{pJnz:X}, 0x{p7:X}, 0x{p8:X}");
            return new PatchEntry[]
            {
                SnapshotPatch(payload, p10, FallbackPatches[0]),
                SnapshotPatch(payload, pJnz, FallbackPatches[1]),
                SnapshotPatch(payload, p7, FallbackPatches[2]),
                SnapshotPatch(payload, p8, FallbackPatches[3]),
            };
        }
    }
}
