using System;

namespace CloudFix
{
    internal record PatchEntry(int Offset, byte[] Original, byte[] Replacement);

    internal enum PatchState
    {
        NotInstalled,
        Unpatched,
        Patched,
        PartiallyPatched,
        UnknownVersion,
        OutOfDate,
    }

    internal class PatchResult
    {
        public bool Succeeded { get; set; }
        public bool DllPatched { get; set; }
        public bool CachePatched { get; set; }
        public string Error { get; set; }

        public PatchResult Fail(string error)
        {
            Succeeded = false;
            Error = error;
            return this;
        }
    }

    internal readonly struct PeSection
    {
        public readonly string Name;
        public readonly int VirtualAddress;
        public readonly int VirtualSize;
        public readonly int RawOffset;
        public readonly int RawSize;

        public PeSection(string name, int va, int vsize, int raw, int rawSize)
        {
            Name = name;
            VirtualAddress = va;
            VirtualSize = vsize;
            RawOffset = raw;
            RawSize = rawSize;
        }

        public static PeSection[] Parse(byte[] pe)
        {
            if (pe.Length < 64) return Array.Empty<PeSection>();

            int peOff = BitConverter.ToInt32(pe, 0x3C);
            if (peOff < 0 || peOff + 24 > pe.Length) return Array.Empty<PeSection>();
            if (pe[peOff] != 'P' || pe[peOff + 1] != 'E') return Array.Empty<PeSection>();

            int numSections = BitConverter.ToUInt16(pe, peOff + 6);
            int optSize = BitConverter.ToUInt16(pe, peOff + 20);
            int firstSection = peOff + 24 + optSize;

            var result = new PeSection[numSections];
            for (int i = 0; i < numSections; i++)
            {
                int off = firstSection + i * 40;
                if (off + 40 > pe.Length) break;

                int nameEnd = 0;
                for (int j = 0; j < 8 && pe[off + j] != 0; j++) nameEnd = j + 1;
                string name = System.Text.Encoding.ASCII.GetString(pe, off, nameEnd);

                int vsize = BitConverter.ToInt32(pe, off + 8);
                int va = BitConverter.ToInt32(pe, off + 12);
                int rawSize = BitConverter.ToInt32(pe, off + 16);
                int rawPtr = BitConverter.ToInt32(pe, off + 20);

                result[i] = new PeSection(name, va, vsize, rawPtr, rawSize);
            }
            return result;
        }

        public static PeSection? Find(PeSection[] sections, string name)
        {
            for (int i = 0; i < sections.Length; i++)
                if (sections[i].Name == name) return sections[i];
            return null;
        }
    }
}
