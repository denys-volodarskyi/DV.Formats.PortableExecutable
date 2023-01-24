namespace DV.Formats.PortableExecutable;

public class ImportedSymbol
{
    public uint RVA { get; internal set; }

    public bool ByOrdinal { get; internal set; }
    public bool ByName => !ByOrdinal;

    public ushort Ordinal { get; internal set; }

    public string Name { get; internal set; } = "";
    public ushort Hint { get; internal set; }

    public override string ToString()
    {
        if (ByOrdinal)
            return $"{RVA:X8} #{Ordinal}";
        else
            return $"{RVA:X8} {Name}";
    }
}

public class ImportedModule
{
    public string Name { get; internal set; } = "";

    public List<ImportedSymbol> Symbols { get; internal set; } = new();

    /// <summary>
    /// Bound import means there are predefined addresses set at symbols in memory
    /// to avoid resolving these addresses by names/ordinals.
    /// <see cref="BoundImportInfo"/>
    /// <see cref="PEImageReader.ReadBoundImport(out BoundImportInfo)"/>
    /// </summary>
    /// <remarks>
    /// This property is just for more information here.
    /// You can ignore it.
    /// </remarks>
    public bool IsBound { get; internal set; }

    public override string ToString() => $"{Name} ({Symbols.Count} import(s))";
}

public class BoundImportInfo
{
    public string ModuleName { get; internal set; }
    public DateTime? TimeDateStamp { get; internal set; }
}

public class DelayLoadImportedModule
{
    /// <summary>
    /// Name of the DLL to be loaded. 
    /// </summary>
    public string Name { get; internal set; }

    /// <summary>
    /// The timestamp of the DLL to which this image has been bound.
    /// </summary>
    public DateTime? TimeStamp { get; internal set; }

    /// <summary>
    /// The RVA of the module handle (in the data section of the image) of the DLL to be delay-loaded. 
    /// It is used for storage by the routine that is supplied to manage delay-loading.
    /// </summary>
    public uint ModuleHandleRVA { get; internal set; }
    
    public List<ImportedSymbol> Symbols { get; internal set; }

    public override string ToString() => $"{Name} ({Symbols.Count} import(s))";
}