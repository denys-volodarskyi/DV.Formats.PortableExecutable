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