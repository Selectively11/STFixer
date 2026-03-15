using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
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
        };

        string _steamPath;
        bool _verbose;

        public Patcher(string steamPath)
        {
            _steamPath = steamPath;
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
                Log($"Warning: could not read {hijackDll} (file may be in use by Steam)");
                return PatchState.Unpatched;
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
                var dllData = File.ReadAllBytes(dllPath);

                Log($"Patching {hijackDll}..");
                var resolvedCore = ResolveCorePatchOffsets(dllData);
                if (resolvedCore == null)
                    return result.Fail($"Could not identify patch locations in {hijackDll} - unsupported version?");

                Backup(dllPath);

                var (patchedDll, dllApplied, dllSkipped, dllErrors) = ApplyPatches(dllData, resolvedCore);
                if (dllErrors.Count > 0)
                {
                    foreach (var err in dllErrors) Log(err);
                    return result.Fail("Byte mismatch in " + hijackDll + " - wrong version?");
                }

                if (dllApplied > 0)
                {
                    File.WriteAllBytes(dllPath, patchedDll);
                    Log($"  {dllApplied} patch(es) applied" + (dllSkipped > 0 ? $", {dllSkipped} already done" : ""));
                }
                else
                {
                    Log("  Already patched");
                }
                result.DllPatched = true;

                var cachePath = Fingerprint.FindCachePath(_steamPath);
                if (cachePath == null)
                {
                    Log("Payload cache not found. Will only patch DLL.");
                    Log("Run again after SteamTools downloads it.");
                    result.Succeeded = true;
                    return result;
                }

                Log("Patching payload in cache..");
                Backup(cachePath);

                var raw = File.ReadAllBytes(cachePath);
                if (raw.Length < 32)
                    return result.Fail("Cache file too small");

                var iv = raw.AsSpan(0, 16).ToArray();
                var ct = raw.AsSpan(16).ToArray();

                Log("  Decrypting..");
                byte[] dec;
                try { dec = AesCbcDecrypt(ct, AesKey, iv); }
                catch (Exception ex) { return result.Fail($"Decryption failed: {ex.Message}"); }

                int expectedSize = BitConverter.ToInt32(dec, 0);
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
                catch (Exception ex) { return result.Fail($"Decompression failed: {ex.Message}"); }

                Log($"  Payload: {payload.Length} bytes");
                if (payload.Length != expectedSize)
                    Log($"  Warning: size mismatch ({payload.Length} vs header {expectedSize})");

                var resolvedPayload = ResolvePayloadPatchOffsets(payload);
                if (resolvedPayload == null)
                    return result.Fail("Could not identify patch locations in payload - unsupported version?");

                var (patchedPayload, plApplied, plSkipped, plErrors) = ApplyPatches(payload, resolvedPayload);
                if (plErrors.Count > 0)
                {
                    foreach (var err in plErrors) Log(err);
                    return result.Fail("Byte mismatch in payload - wrong version?");
                }

                if (plApplied > 0)
                {
                    ReEncryptAndWrite(cachePath, patchedPayload, iv);
                    Log($"  {plApplied} patch(es) applied" + (plSkipped > 0 ? $", {plSkipped} already done" : ""));
                }
                else
                {
                    Log("  Already patched");
                }
                result.CachePatched = true;

                result.Succeeded = true;
                Log("Done. Restart Steam if it's running.");
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
                        foreach (var f in Directory.GetFiles(cacheDir, "*.bak"))
                        {
                            var orig = f[..^4];
                            var fname = Path.GetFileName(orig);
                            if (fname.Length == 16)
                            {
                                RestoreBackup(orig, "payload cache");
                                restored++;
                                break;
                            }
                        }
                    }
                }

                if (restored > 0)
                {
                    Log($"Restored {restored} file(s). Restart Steam if it's running.");
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

        void Log(string msg)
        {
            if (_verbose) Program.PrintLine(msg);
        }

        void Backup(string path)
        {
            var bak = path + ".bak";
            if (File.Exists(bak)) return;
            File.Copy(path, bak);
            Log($"  Backed up to {bak}");
        }

        bool RestoreBackup(string path, string label)
        {
            var bak = path + ".bak";
            if (!File.Exists(bak))
            {
                Log($"  {label}: no backup found");
                return false;
            }
            File.Copy(bak, path, overwrite: true);
            File.Delete(bak);
            Log($"  {label}: restored from backup");
            return true;
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

        static PatchEntry SnapshotPatch(byte[] data, int offset, PatchEntry template, int fixedPrefixLen)
        {
            int len = template.Original.Length;
            var actual = new byte[len];
            Buffer.BlockCopy(data, offset, actual, 0, len);

            var repl = (byte[])template.Replacement.Clone();
            if (fixedPrefixLen > 0 && fixedPrefixLen < len)
                Buffer.BlockCopy(actual, fixedPrefixLen, repl, fixedPrefixLen, len - fixedPrefixLen);

            return new PatchEntry(offset, actual, repl);
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
                SnapshotPatch(dll, p1, CorePatches[0], 0),
                SnapshotPatch(dll, p2, CorePatches[1], 0),
            };
        }

        PatchEntry[] ResolvePayloadPatchOffsets(byte[] payload)
        {
            var sections = PeSection.Parse(payload);
            var textSec = PeSection.Find(sections, ".text");

            // obfuscated section has a random name each build - find by excluding standard ones
            var knownNames = new HashSet<string> { ".text", ".rdata", ".data", ".pdata", ".fptable", ".rsrc", ".reloc" };
            PeSection? gcjSec = null;
            foreach (var sec in sections)
            {
                if (!knownNames.Contains(sec.Name))
                {
                    gcjSec = sec;
                    break;
                }
            }

            if (textSec == null || gcjSec == null)
            {
                Log("  Payload: missing expected sections");
                return null;
            }

            int tStart = textSec.Value.RawOffset;
            int tEnd = tStart + textSec.Value.RawSize;
            int gStart = gcjSec.Value.RawOffset;
            int gEnd = gStart + gcjSec.Value.RawSize;

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
                SnapshotPatch(payload, p1, PayloadPatches[0], 2),
                SnapshotPatch(payload, p2, PayloadPatches[1], 0),
                SnapshotPatch(payload, p3, PayloadPatches[2], 0),
            };
        }
    }
}
