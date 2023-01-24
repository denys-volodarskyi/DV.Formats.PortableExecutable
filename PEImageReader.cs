using System.Diagnostics;
using System.Text;

namespace DV.Formats.PortableExecutable;
public class PEImageReader
{
    public bool IsMapped { get; }

    private Stream Stream { get; }
    private readonly BinaryReader Reader;

    private void Seek(long position) => Stream.Position = position;

    public bool SeekRva(ulong rva) => SeekRva((uint)rva);
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

    private bool ReadList<T>(uint rva, int count, Func<T> read_func, out List<T> list)
    {
        if (SeekRva(rva))
        {
            list = new List<T>();
            while (count-- > 0)
                list.Add(read_func());
            return true;
        }
        list = default;
        return false;
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

    private string ReadNullTerminatedString(Encoding encoding)
    {
        var bytes = new List<byte>(16);
        while (true)
        {
            var b = Stream.ReadByte();
            if (b <= 0)
                break;
            bytes.Add((byte)b);
        }
        return encoding.GetString(bytes.ToArray());
    }

    public string ReadNullTerminatedString() => ReadNullTerminatedString(Encoding.ASCII);

    private bool ReadStringA(uint rva, out string str)
    {
        if (SeekRva(rva))
        {
            str = ReadNullTerminatedString();
            return true;
        }

        str = null;
        return false;
    }

    public PEImage Image { get; } = new PEImage();

    private static DateTime? DecodeTimeStampUtc(uint datetimestamp)
    {
        return datetimestamp == 0 || datetimestamp == uint.MaxValue
            ? null
            : DateTimeOffset.FromUnixTimeSeconds(datetimestamp).UtcDateTime;
    }

    private static void LogDbg(string message) => Debug.Write(message);

    public Action<string> LogFunc { get; set; } = LogDbg;

    private void Log(string message) => LogFunc?.Invoke(message + "\n");

    private void ErrorLog(string message) => Log("[Error] " + message);

    public PEImageReader(Stream stream, bool is_mapped)
    {
        IsMapped = is_mapped;
        Stream = stream;
        Reader = new BinaryReader(stream, Encoding.ASCII, leaveOpen: true);
    }

    /// <summary>
    /// Check if stream has MZ+PE signatures.
    /// </summary>
    public static bool IsMzPe(Stream src)
    {
        src.Position = 0;
        if (src.ReadByte() == 'M' && src.ReadByte() == 'Z')
        {
            src.Position = 0x3C;
            if (src.ReadByte() == 'P' && src.ReadByte() == 'E' && src.ReadByte() == 0 && src.ReadByte() == 0)
                return true;
        }
        return false;
    }

    public bool Open(out PEImage img)
    {
        img = Image;
        return Open();
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
        var data_dir_cnt = Math.Min(data_dir_cnt_declared, data_dir_max_possible);
        if (data_dir_cnt_declared > data_dir_max_possible)
        {
            Log($"Declared number of data directories ({data_dir_cnt_declared}) is more than max possible ({data_dir_max_possible}).\n" +
                $"Will load {data_dir_cnt} directories.");
        }
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

    public bool ReadExports(out ExportTable table)
    {
        // Required:
        // 
        //   Export directory table
        //   Export address table
        // 
        // Optional to export names:
        // 
        //   Name pointer table
        //   Ordinal table
        //   Export name table

        table = null;

        if (!Image.GetDataDirectory(DataDirectoryType.Exports, out var dir))
        {
            return false;
        }

        if (dir.Address == 0)
            return false;

        if (!SeekRva((uint)dir.Address))
        {
            Log($"Export directory not found at 0x{dir.Address:X}");
            return false;
        }

        var Export_Flags = Reader.ReadUInt32();                // Reserved, must be 0.
        var Time_Date_Stamp = Reader.ReadUInt32();             // The time and date that the export data was created.
        var Major_Version = Reader.ReadUInt16();               // The major version number.The major and minor version numbers can be set by the user.
        var Minor_Version = Reader.ReadUInt16();               // The minor version number.
        var Name_RVA = Reader.ReadUInt32();                    // The address of the ASCII string that contains the name of the DLL.
                                                               // This address is relative to the image base.
        var Ordinal_Base = Reader.ReadUInt32();                // The starting ordinal number for exports in this image.
                                                               // This field specifies the starting ordinal number for the export address table.
                                                               // It is usually set to 1.
        var Address_Table_Entries_Count = Reader.ReadUInt32(); // The number of entries in the export address table.
        var Number_of_Name_Pointers = Reader.ReadUInt32();     // The number of entries in the name pointer table.
                                                               // This is also the number of entries in the ordinal table.
        var Export_Address_Table_RVA = Reader.ReadUInt32();    // The address of the export address table, relative to the image base.
        var Name_Pointer_RVA = Reader.ReadUInt32();            // The address of the export name pointer table, relative to the image base.
                                                               // The table size is given by the Number of Name Pointers field.
        var Ordinal_Table_RVA = Reader.ReadUInt32();           // The address of the ordinal table, relative to the image base.

        string name = "";
        if (Name_RVA != 0 && !ReadStringA(Name_RVA, out name))
        {
            Log("Error reading export module name.");
            return false;
        }

        table = new ExportTable
        {
            Major = Major_Version,
            Minor = Minor_Version,
            Name = name,
            DateTimeUtc = DecodeTimeStampUtc(Time_Date_Stamp)
        };

        if (Address_Table_Entries_Count == 0)
            return true;

        if (Export_Address_Table_RVA == 0)
        {
            Log($"Exported address count is {Address_Table_Entries_Count}, but address array not specified");
            return false;
        }

        if (!ReadList(Export_Address_Table_RVA, (int)Address_Table_Entries_Count, Reader.ReadUInt32, out var rvas))
        {
            Log("Failed to read export address RVAs");
            return false;
        }

        // Allocate symbols.
        for (var j = 0; j < Address_Table_Entries_Count; j++)
            table.Symbols.Add(new ExportSymbol());

        // Fill with RVAs or forwarders.
        for (var i = 0; i < Address_Table_Entries_Count; i++)
        {
            if (dir.Has(rvas[i]))
            {
                // Forwarded.
                if (!ReadStringA(rvas[i], out var fwdname))
                {
                    Log("Error reading export forwarder name");
                    return false;
                }
                table.Symbols[i].Forwarder = fwdname;
            }
            else
            {
                table.Symbols[i].RVA = rvas[i];
            }
        }

        if (Number_of_Name_Pointers > 0)
        {
            if (ReadList(Ordinal_Table_RVA, (int)Number_of_Name_Pointers, Reader.ReadUInt16, out var ordinals))
            {
                if (ReadList(Name_Pointer_RVA, (int)Number_of_Name_Pointers, Reader.ReadUInt32, out var namervas))
                {
                    for (var i = 0; i < Number_of_Name_Pointers; i++)
                    {
                        if (!ReadStringA(namervas[i], out var symname))
                        {
                            Log("Error reading exported symbol name");
                            return false;
                        }

                        var ordinal = ordinals[i];
                        table.Symbols[ordinal].Ordinal = ordinal + Ordinal_Base;
                        table.Symbols[ordinal].Name = symname;
                    }
                }
                else
                    Log("Failed to read export names RVAs");
            }
            else
                Log("Failed to read export ordinals");
        }

        return true;
    }

    public bool ReadImports(out List<ImportedModule> modules)
    {
        if (!Image.GetDataDirectory(DataDirectoryType.Imports, out var dir) || dir.Address == 0)
        {
            modules = null;
            return false;
        }

        // Ignore directory size.
        // Stop on empty import directory.
        modules = new();
        var rva = (uint)dir.Address;
        while (ReadImportDirectory(rva, out var module))
        {
            if (module != null)
                modules.Add(module);
            rva += 20;
        }

        return true;
    }

    private bool ReadImportDirectory(uint rva, out ImportedModule module)
    {
        module = null;

        if (!SeekRva(rva))
        {
            Log($"Import directory not found at RVA 0x{rva:X}.");
            return false;
        }

        var import_lookup_table_rva = Reader.ReadUInt32();
        var time_date_stamp = Reader.ReadUInt32();
        var forwarder_chain = Reader.ReadUInt32();
        var name_rva = Reader.ReadUInt32();
        var import_address_table_rva = Reader.ReadUInt32();

        if (import_address_table_rva == 0 &&
            time_date_stamp == 0 &&
            forwarder_chain == 0 &&
            name_rva == 0 &&
            import_address_table_rva == 0)
        {
            // Empty.
            return false;
        }

        if (name_rva == 0)
        {
            Log("Import directory has bad module name.");
            return false;
        }
        if (!ReadStringA(name_rva, out var name))
        {
            Log("Error reading imported module name.");
            return false;
        }

        var is_bound = time_date_stamp != 0;

        List<ImportedSymbol> symbols;

        // Import address table.
        if (is_bound)
        {
            throw new Exception("Reading bound import is not implemented yet");
        }
        else
        {
            // Read from lookup table if it is present.
            // Otherwise read from address table.
            var ilt_rva = import_lookup_table_rva != 0 ? import_lookup_table_rva : import_address_table_rva;

            if (!ReadNullTerminatedList(ilt_rva, ReadPEUint, out var items))
            {
                Log("Error reading import lookup table.");
                return false;
            }

            var bitness = Image.Bitness;
            symbols = CreateImportSymbolsFromDesc(items, bitness);
            FillSymbolRVAS(symbols, import_address_table_rva, bitness);
        }

        module = new ImportedModule
        {
            Name = name,
            Symbols = symbols,
        };

        return true;
    }

    private List<ImportedSymbol> CreateImportSymbolsFromDesc(IEnumerable<ulong> items, int bitness)
    {
        var symbols = new List<ImportedSymbol>();

        foreach (var value in items)
        {
            var sym = new ImportedSymbol();

            bool by_ordinal = ((value >> (bitness - 1)) & 1) != 0;

            if (by_ordinal)
            {
                var ordinal = (ushort)value;

                sym.ByOrdinal = true;
                sym.Ordinal = ordinal;
            }
            else
            {
                var hint_name_table_rva = (uint)(value & 0x7FFFFFFF);

                if (!SeekRva(hint_name_table_rva))
                {
                    throw new Exception("Error reading import hint.");
                }

                sym.ByOrdinal = false;
                sym.Hint = Reader.ReadUInt16();
                sym.Name = ReadNullTerminatedString();
            }

            symbols.Add(sym);
        }

        return symbols;
    }

    private static void FillSymbolRVAS(IEnumerable<ImportedSymbol> symbols, uint begin_rva, int bitness)
    {
        var ptrsize = (uint)bitness / 8;
        var rva = begin_rva;
        foreach (var symbol in symbols)
        {
            symbol.RVA = rva;
            rva += ptrsize;
        }
    }
}
