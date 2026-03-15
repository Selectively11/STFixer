using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace CloudFix
{
    internal static class Fingerprint
    {
        public static string FindCachePath(string steamPath)
        {
            var cacheDir = Path.Combine(steamPath, "appcache", "httpcache", "3b");
            if (!Directory.Exists(cacheDir))
                return null;

            try
            {
                var fp = Compute();
                var path = Path.Combine(cacheDir, fp);
                if (File.Exists(path))
                {
                    Program.PrintLine($"Cache: {path}");
                    return path;
                }
                Program.PrintLine($"Fingerprint {fp} computed but no cache file there");
            }
            catch (Exception ex)
            {
                Program.PrintLine($"Fingerprint computation failed ({ex.Message}), scanning..");
            }

            foreach (var f in Directory.GetFiles(cacheDir))
            {
                var name = Path.GetFileName(f);
                var info = new FileInfo(f);
                if (name.Length == 16 && info.Length > 500000 && info.Length < 5000000)
                {
                    Program.PrintLine($"Cache (found by scan): {f}");
                    return f;
                }
            }

            return null;
        }

        static unsafe string Compute()
        {
            // CPUID leaf 0 -> vendor string
            CpuId(0, out uint _, out uint ebx0, out uint ecx0, out uint edx0);
            var vendorBytes = new byte[12];
            BitConverter.TryWriteBytes(vendorBytes.AsSpan(0, 4), ebx0);
            BitConverter.TryWriteBytes(vendorBytes.AsSpan(4, 4), edx0);
            BitConverter.TryWriteBytes(vendorBytes.AsSpan(8, 4), ecx0);
            var vendor = System.Text.Encoding.ASCII.GetString(vendorBytes);

            // CPUID leaf 1 -> family/model
            CpuId(1, out uint eax1, out _, out _, out _);
            int family = ((int)eax1 >> 8) & 0xF;
            int model = ((int)eax1 >> 4) & 0xF;
            int nproc = Environment.ProcessorCount & 0xFF;

            var tag = System.Text.Encoding.ASCII.GetBytes(
                $"V{vendor}_F{family:X}_M{model:X}_C{nproc:X}");

            // XOR with "version" (same as Core.dll)
            var xorKey = System.Text.Encoding.ASCII.GetBytes("version");
            var xored = new byte[tag.Length];
            for (int i = 0; i < tag.Length; i++)
                xored[i] = (byte)(tag[i] ^ xorKey[i % 7]);

            var md5Hex = System.Text.Encoding.ASCII.GetBytes(
                Convert.ToHexString(MD5.HashData(xored)).ToLowerInvariant());

            // CRC-64
            ulong crc = 0xFFFFFFFFFFFFFFFF;
            foreach (byte b in md5Hex)
            {
                crc ^= b;
                for (int j = 0; j < 8; j++)
                {
                    if ((crc & 1) != 0) crc ^= 0x85E1C3D753D46D27;
                    crc >>= 1;
                }
            }
            return (crc ^ 0xFFFFFFFFFFFFFFFF).ToString("X16");
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(IntPtr addr, UIntPtr size, uint type, uint protect);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool VirtualFree(IntPtr addr, UIntPtr size, uint type);

        static unsafe void CpuId(uint leaf, out uint eax, out uint ebx, out uint ecx, out uint edx)
        {
            // x64 shellcode for cpuid instruction
            ReadOnlySpan<byte> code = new byte[]
            {
                0x53, 0x49, 0x89, 0xD0, 0x89, 0xC8, 0x31, 0xC9, 0x0F, 0xA2,
                0x41, 0x89, 0x00, 0x41, 0x89, 0x58, 0x04, 0x41, 0x89, 0x48,
                0x08, 0x41, 0x89, 0x50, 0x0C, 0x5B, 0xC3
            };

            var mem = VirtualAlloc(IntPtr.Zero, (UIntPtr)code.Length, 0x3000, 0x40);
            if (mem == IntPtr.Zero) throw new InvalidOperationException("VirtualAlloc failed");

            try
            {
                Marshal.Copy(code.ToArray(), 0, mem, code.Length);
                var regs = stackalloc uint[4];

                var fn = (delegate* unmanaged[Cdecl]<uint, uint*, void>)mem;
                fn(leaf, regs);

                eax = regs[0]; ebx = regs[1]; ecx = regs[2]; edx = regs[3];
            }
            finally
            {
                VirtualFree(mem, UIntPtr.Zero, 0x8000);
            }
        }
    }
}
