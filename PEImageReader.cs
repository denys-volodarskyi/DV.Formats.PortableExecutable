using System.Diagnostics;
using System.Text;

namespace DV.Formats.PortableExecutable;
public class PEImageReader
{
    public bool IsMapped { get; }

    private Stream Stream { get; }
    private readonly BinaryReader Reader;

    private void Seek(long position) => Stream.Position = position;

    public bool SeekRva(uint rva)
    {
        if (Image.RvaToSection(rva, out var sec))
        {
            var pos = sec.RawAddress + (rva - sec.VirtualAddress);
            Seek(pos);
            return true;
        }
        return false;
    }

    public bool SeekVa(ulong va) => Image.VaToRva(va, out var rva) && SeekRva(rva);

    private ulong ReadPEUint()
    {
        if (Image.Is32BitPE)
            return Reader.ReadUInt32();
        if (Image.Is64BitPE)
            return Reader.ReadUInt64();
        throw new NotSupportedException();
    }

    public PEImage Image { get; } = new PEImage();

    private static DateTime DecodeTimeStampUtc(uint datetimestamp) => DateTimeOffset.FromUnixTimeSeconds(datetimestamp).UtcDateTime;

    private void Log(string message)
    {
        Debug.WriteLine(message);
    }

    private void ErrorLog(string message)
    {
        Debug.WriteLine(message);
    }

    public PEImageReader(Stream stream, bool is_mapped)
    {
        IsMapped = is_mapped;
        Stream = stream;
        Reader = new BinaryReader(stream, Encoding.ASCII, leaveOpen: true);
    }

    /// <summary>
    /// Checks if there is MZ/PE signatures and reads headers and sections
    /// needed for further parsing.
    /// </summary>
    public bool Open()
    {
        // MZ
        Seek(0);
        if (Reader.ReadByte() != 'M' || Reader.ReadByte() != 'Z')
        {
            ErrorLog("MZ signature not found.");
            return false;
        }

        Seek(0x3c);
        var e_lfa_new = Reader.ReadInt32();
        if (e_lfa_new >= Stream.Length)
        {
            ErrorLog("Bad PE header offset");
            return false;
        }

        // PE
        Seek(e_lfa_new);
        if (Reader.ReadByte() != 'P' ||
            Reader.ReadByte() != 'E' ||
            Reader.ReadByte() != 0 ||
            Reader.ReadByte() != 0)
        {
            ErrorLog("PE signature not found.");
            return false;
        }

        #region File Header
        Image.Machine = (IMAGE_FILE_MACHINE)Reader.ReadUInt16();
        var NumberOfSections = Reader.ReadUInt16();
        Image.TimeDateStamp = DecodeTimeStampUtc(Reader.ReadUInt32());

        var PointerToSymbolTable = Reader.ReadUInt32();
        if (PointerToSymbolTable != 0)
            Log("PointerToSymbolTable should be zero for an image because COFF debugging information is deprecated.");

        var NumberOfSymbols = Reader.ReadUInt32();
        if (NumberOfSymbols != 0)
            Log("NumberOfSymbols should be zero for an image because COFF debugging information is deprecated.");

        var SizeOfOptionalHeader = Reader.ReadUInt16();

        Image.Characteristics = (IMAGE_FILE_CHARACTERISTICS)Reader.ReadUInt16();
        #endregion

        var opt_hdr_begin = Stream.Position;
        var opt_hdr_end = opt_hdr_begin + SizeOfOptionalHeader;

        ReadOptionalHeader(out var data_dir_cnt_declared);

        var data_dir_begin = Stream.Position;
        var data_dir_max_possible = (opt_hdr_end - data_dir_begin) / 8;
        if (data_dir_cnt_declared > data_dir_max_possible)
            Log($"Declared number of data directories ({data_dir_cnt_declared}) is more than max possible ({data_dir_max_possible}).");
        var data_dir_cnt = Math.Min(data_dir_cnt_declared, data_dir_max_possible);
        ReadDataDirectories((int)data_dir_cnt);

        ReadSectionHeaders(NumberOfSections);

        return true;
    }

    private void ReadOptionalHeader(out uint NumberOfRvaAndSizes)
    {
        Image.Magic = Reader.ReadUInt16();

        Image.MajorLinkerVersion = Reader.ReadByte();
        Image.MinorLinkerVersion = Reader.ReadByte();

        Image.SizeOfCode = Reader.ReadUInt32();
        Image.SizeOfInitializedData = Reader.ReadUInt32();
        Image.SizeOfUninitializedData = Reader.ReadUInt32();

        Image.AddressOfEntryPoint = Reader.ReadUInt32();

        Image.BaseOfCode = Reader.ReadUInt32();

        if (Image.Is32BitPE)
            Image.BaseOfData = Reader.ReadUInt32();

        Image.ImageBase = ReadPEUint();

        Image.SectionAlignment = Reader.ReadUInt32();
        Image.FileAlignment = Reader.ReadUInt32();

        Image.MajorOperatingSystemVersion = Reader.ReadUInt16();
        Image.MinorOperatingSystemVersion = Reader.ReadUInt16();

        Image.MajorImageVersion = Reader.ReadUInt16();
        Image.MinorImageVersion = Reader.ReadUInt16();

        Image.MajorSubsystemVersion = Reader.ReadUInt16();
        Image.MinorSubsystemVersion = Reader.ReadUInt16();

        var _Win32VersionValue = Reader.ReadUInt32(); // 

        Image.SizeOfImage = Reader.ReadUInt32();
        Image.SizeOfHeaders = Reader.ReadUInt32();

        Image.CheckSum = Reader.ReadUInt32();

        Image.Subsystem = (IMAGE_SUBSYSTEM)Reader.ReadUInt16();

        Image.DllCharacteristics = (IMAGE_DLLCHARACTERISTICS)Reader.ReadUInt16();

        Image.SizeOfStackReserve = ReadPEUint();
        Image.SizeOfStackCommit = ReadPEUint();

        Image.SizeOfHeapReserve = ReadPEUint();
        Image.SizeOfHeapCommit = ReadPEUint();

        Image.LoaderFlags = Reader.ReadUInt32();

        NumberOfRvaAndSizes = Reader.ReadUInt32();
    }

    private void ReadDataDirectories(int count)
    {
        Image.DataDirectories.Clear();
        for (var i = 0; i < count; i++)
            Image.DataDirectories.Add(new AddressRange(Reader.ReadUInt32(), Reader.ReadUInt32()));
    }

    private void ReadSectionHeaders(int count)
    {
        Image.Sections.Clear();

        Span<byte> name_span = stackalloc byte[8];

        for (var i = 0; i < count; i++)
        {
            Stream.Read(name_span);

            var name = ProcessSectionName(name_span);

            var virtual_size = Reader.ReadUInt32();
            var virtual_addr = Reader.ReadUInt32();

            var raw_size = Reader.ReadUInt32();
            var raw_offset = Reader.ReadUInt32();

            var _PointerToRelocations = Reader.ReadUInt32();
            var _PointerToLinenumbers = Reader.ReadUInt32();
            var _NumberOfRelocations = Reader.ReadUInt16();
            var _NumberOfLinenumbers = Reader.ReadUInt16();

            var Characteristics = (IMAGE_SCN)Reader.ReadUInt32();

            Image.Sections.Add(new()
            {
                Name = name,

                VirtualAddress = virtual_addr,
                VirtualSize = virtual_size,

                RawAddress = raw_offset,
                RawSize = raw_size,

                Flags = (IMAGE_SCN)Characteristics
            });
        }
    }

    private static string ProcessSectionName(Span<byte> span)
    {
        int len = span.Length;
        while (len > 0 && span[len - 1] == 0)
            len--;

        for (var i = 0; i < len; i++)
            if (!IsGoodSectionNameChar(span[i]))
                span[i] = (byte)'_';

        return Encoding.ASCII.GetString(span[..len]);
    }

    private static bool IsGoodSectionNameChar(byte b) => b >= 33 && b <= 126;

    public bool ReadTLS(out TLS tls)
    {
        tls = default;

        if (!Image.GetDataDirectory(DataDirectoryType.TLS, out var dir) || dir.Empty)
            return false;

        if (!SeekRva((uint)dir.Address))
        {
            Log($"TLS directory not found at 0x{dir.Address:X}");
            return false;
        }

        // TLS header.
        var hdr = new TLSDirectoryHeader
        {
            RawDataStartVA = ReadPEUint(),
            RawDataEndVA = ReadPEUint(),
            AddressOfIndex = ReadPEUint(),
            AddressOfCallbacks = ReadPEUint(),
            SizeOfZeroFill = Reader.ReadUInt32(),
            Characteristics = Reader.ReadUInt32()
        };

        // TSL callbacks.
        if (hdr.AddressOfCallbacks == 0)
            return false;

        if (!Image.VaToRva(hdr.AddressOfCallbacks, out var callbacks_rva))
        {
            Log($"Address of TLS callbacks not found: 0x{hdr.AddressOfCallbacks:X}");
            return false;
        }

        ReadNullTerminatedList(callbacks_rva, ReadPEUint, out var callbacks);

        // Callbacks are VAs.
        // Convert to RVAs.
        for (var i = 0; i < callbacks.Count; i++)
        {
            var va = callbacks[i];

            if (!Image.VaToRva(va, out var rva))
            {
                Log($"Failed to convert TLS callback VA to RVA: 0x{va:X}");
                return false;
            }

            callbacks[i] = rva;
        }


        tls = new TLS
        {
            CAllbacksArrayRVA = callbacks_rva,
            ListOfCallbackRVAs = callbacks
        };

        return true;
    }

    private bool ReadNullTerminatedList<T>(uint rva, Func<T> read_func, out List<T> list) where T : struct
    {
        if (SeekRva(rva))
        {
            list = new List<T>();
            while (true)
            {
                var value = read_func();
                if (value.Equals(default(T)))
                    break;
                list.Add(value);
            }
            return true;
        }
        list = default;
        return false;
    }
}
