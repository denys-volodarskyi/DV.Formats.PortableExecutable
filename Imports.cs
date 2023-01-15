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

    public bool Delay { get; internal set; }

    public override string ToString() => $"{Name} ({Symbols.Count} import(s))";
}
