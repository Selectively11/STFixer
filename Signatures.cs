using System;

namespace CloudFix
{
    internal static class Signatures
    {
        public static int ScanForPattern(byte[] data, int start, int end, byte[] pattern, byte[] mask)
        {
            int limit = Math.Min(end, data.Length) - pattern.Length;
            for (int i = start; i <= limit; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (mask[j] != 0 && data[i + j] != pattern[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return i;
            }
            return -1;
        }

        public static int ScanForBytes(byte[] data, int start, int end, byte[] needle)
        {
            int limit = Math.Min(end, data.Length) - needle.Length;
            for (int i = start; i <= limit; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (data[i + j] != needle[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return i;
            }
            return -1;
        }

        // Pattern: E8 ?? ?? ?? ?? 85 C0 0F 84 with negative call target
        public static int FindCorePatch1(byte[] data, int start, int end)
        {
            byte[] pattern = { 0xE8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x0F, 0x84 };
            byte[] mask =    { 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF };

            int pos = start;
            while (pos < end)
            {
                int hit = ScanForPattern(data, pos, end, pattern, mask);
                if (hit < 0) break;

                // call target should be negative (download func is earlier in code)
                int rel = BitConverter.ToInt32(data, hit + 1);
                if (rel < 0)
                    return hit;

                pos = hit + 1;
            }
            return -1;
        }

        // Pattern: 85 C0 74 xx 33 FF E9 (hash compare fall-through)
        public static int FindCorePatch2(byte[] data, int start, int end)
        {
            for (int i = start; i < end - 6; i++)
            {
                if (data[i] == 0x85 && data[i + 1] == 0xC0 &&
                    (data[i + 2] == 0x74 || data[i + 2] == 0xEB) &&
                    data[i + 4] == 0x33 && data[i + 5] == 0xFF)
                {
                    return i + 2;
                }
            }

            // looser match without leading test eax,eax
            for (int i = start; i < end - 5; i++)
            {
                if ((data[i] == 0x74 || data[i] == 0xEB) &&
                    data[i + 2] == 0x33 && data[i + 3] == 0xFF &&
                    data[i + 4] == 0xE9)
                {
                    return i;
                }
            }

            return -1;
        }

        // Cloud rewrite jz: 85 C0 0F 85 ?? ?? 00 00 45 85 FF [0F 84 | 90 E9]
        public static int FindPayloadPatch1(byte[] data, int tStart, int tEnd)
        {
            for (int i = tStart; i < tEnd - 17; i++)
            {
                if (data[i] == 0x85 && data[i + 1] == 0xC0 &&
                    data[i + 2] == 0x0F && data[i + 3] == 0x85 &&
                    data[i + 6] == 0x00 && data[i + 7] == 0x00 &&
                    data[i + 8] == 0x45 && data[i + 9] == 0x85 && data[i + 10] == 0xFF &&
                    data[i + 15] == 0x00 && data[i + 16] == 0x00)
                {
                    if ((data[i + 11] == 0x0F && data[i + 12] == 0x84) ||
                        (data[i + 11] == 0x90 && data[i + 12] == 0xE9))
                    {
                        return i + 11;
                    }
                }
            }
            return -1;
        }

        // Proxy appid load: [8B 0D | 31 C9] ?? ?? ?? ?? 48 8D 14 3E
        public static int FindPayloadPatch2(byte[] data, int start, int end)
        {
            byte[] tail = { 0x48, 0x8D, 0x14, 0x3E };

            for (int i = start; i < end - 10; i++)
            {
                if (data[i + 6] == tail[0] && data[i + 7] == tail[1] &&
                    data[i + 8] == tail[2] && data[i + 9] == tail[3])
                {
                    if ((data[i] == 0x8B && data[i + 1] == 0x0D) ||
                        (data[i] == 0x31 && data[i + 1] == 0xC9))
                    {
                        return i;
                    }
                }
            }
            return -1;
        }

        // Anchor: Spacewar 480 constant (C7 40 09 E0 01 00 00), then next 89 3D or 6x NOP
        public static int FindPayloadPatch3(byte[] data, int gStart, int gEnd)
        {
            byte[] spacewar = { 0xC7, 0x40, 0x09, 0xE0, 0x01, 0x00, 0x00 };
            int anchor = ScanForBytes(data, gStart, gEnd, spacewar);
            if (anchor < 0)
                return -1;

            int searchStart = anchor + spacewar.Length;
            int searchEnd = Math.Min(searchStart + 30, gEnd);
            for (int i = searchStart; i < searchEnd - 5; i++)
            {
                if (data[i] == 0x89 && data[i + 1] == 0x3D)
                    return i;
                if (data[i] == 0x90 && data[i + 1] == 0x90 &&
                    data[i + 2] == 0x90 && data[i + 3] == 0x90 &&
                    data[i + 4] == 0x90 && data[i + 5] == 0x90)
                    return i;
            }

            return -1;
        }

        // Activation flag: two mov cs:byte_xxx, imm8 instructions (C6 05 xx xx FE FF 01/00)
        // separated by E9 00 00 00 00 E9 ?? ?? 00 00 bridge, both targeting same global.
        // Returns offset of the second instruction (the fail path that sets 0).
        public static int FindPayloadPatch4(byte[] data, int gStart, int gEnd)
        {
            for (int i = gStart; i < gEnd - 24; i++)
            {
                if (data[i] != 0xC6 || data[i + 1] != 0x05) continue;
                if (data[i + 4] != 0xFE || data[i + 5] != 0xFF) continue;
                if (data[i + 6] != 0x01) continue;

                int b = i + 7;
                if (b + 10 + 7 > gEnd) continue;
                if (data[b] != 0xE9 || data[b + 1] != 0x00 || data[b + 2] != 0x00 ||
                    data[b + 3] != 0x00 || data[b + 4] != 0x00) continue;
                if (data[b + 5] != 0xE9) continue;
                if (data[b + 8] != 0x00 || data[b + 9] != 0x00) continue;

                int failOff = b + 10;
                if (data[failOff] != 0xC6 || data[failOff + 1] != 0x05) continue;
                if (data[failOff + 4] != 0xFE || data[failOff + 5] != 0xFF) continue;
                if (data[failOff + 6] != 0x00 && data[failOff + 6] != 0x01) continue;

                return failOff;
            }
            return -1;
        }

        // GetCookie retry skip: 48 85 F6 (test rsi,rsi) followed by 75/EB xx (jnz/jmp short)
        // preceded by a call (E8 xx xx xx xx) to the cookie cleanup func.
        // Returns offset of the 75/EB byte.
        public static int FindPayloadPatch5(byte[] data, int tStart, int tEnd)
        {
            for (int i = tStart; i < tEnd - 12; i++)
            {
                if (data[i] != 0xE8) continue;
                if (data[i + 5] != 0x48 || data[i + 6] != 0x85 || data[i + 7] != 0xF6) continue;
                if (data[i + 8] != 0x75 && data[i + 8] != 0xEB) continue;

                int skipDist = data[i + 9];
                int afterSkip = i + 10 + skipDist;
                if (afterSkip > tEnd) continue;

                bool hasLoop = false;
                for (int j = i + 10; j < afterSkip && j < tEnd - 5; j++)
                {
                    if (data[j] == 0xE9)
                    {
                        int rel = BitConverter.ToInt32(data, j + 1);
                        if (rel < 0) { hasLoop = true; break; }
                    }
                }
                if (!hasLoop) continue;

                return i + 8;
            }
            return -1;
        }

        // P10: prologue of sub_18000D3C0
        // 48 89 74 24 xx | E9 xx xx xx xx, followed by 41 56 48 83 EC 30
        public static int FindPayloadPatch10(byte[] data, int tStart, int tEnd)
        {
            for (int i = tStart; i < tEnd - 15; i++)
            {
                bool isOriginal = data[i] == 0x48 && data[i + 1] == 0x89 &&
                                  data[i + 2] == 0x74 && data[i + 3] == 0x24;
                bool isPatched = data[i] == 0xE9;

                if (!isOriginal && !isPatched) continue;

                if (data[i + 5] == 0x41 && data[i + 6] == 0x56 &&
                    data[i + 7] == 0x48 && data[i + 8] == 0x83 &&
                    data[i + 9] == 0xEC && data[i + 10] == 0x30)
                {
                    return i;
                }
            }
            return -1;
        }

        // P7: call to sub_180042B60 (or redirected to code cave)
        public static int FindPayloadPatch7(byte[] data, int tStart, int tEnd)
        {
            for (int i = tStart; i < tEnd - 10; i++)
            {
                if (data[i] != 0xE8) continue;

                int rel = BitConverter.ToInt32(data, i + 1);
                int target = i + 5 + rel;

                if ((target >= 0x41000 && target <= 0x44000) ||
                    (target >= 0x175000 && target <= 0x176000))
                {
                    if (i + 8 < tEnd && data[i + 5] == 0x48 && data[i + 6] == 0x85 && data[i + 7] == 0xC0)
                        return i;
                }
            }
            return -1;
        }

        // P8: .text section characteristics in PE header
        public static int FindPayloadPatch8(byte[] data)
        {
            if (data.Length < 64) return -1;

            int peOff = BitConverter.ToInt32(data, 0x3C);
            if (peOff < 0 || peOff + 24 > data.Length) return -1;
            if (data[peOff] != 'P' || data[peOff + 1] != 'E') return -1;

            int numSections = BitConverter.ToUInt16(data, peOff + 6);
            int optSize = BitConverter.ToUInt16(data, peOff + 20);
            int firstSection = peOff + 24 + optSize;

            for (int i = 0; i < numSections; i++)
            {
                int off = firstSection + i * 40;
                if (off + 40 > data.Length) break;

                if (data[off] == '.' && data[off + 1] == 't' &&
                    data[off + 2] == 'e' && data[off + 3] == 'x' && data[off + 4] == 't')
                    return off + 36;
            }
            return -1;
        }
    }
}
