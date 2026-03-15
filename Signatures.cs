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
    }
}
