namespace DV.Formats.PortableExecutable;

public class ExportTable
{
    public DateTime DateTimeUtc { get; internal set; }

    public ushort Major { get; internal set; }

    public ushort Minor { get; internal set; }

    public string Name { get; internal set; } = "";

    public List<ExportSymbol> Symbols { get; internal set; } = new();
}

public class ExportSymbol
{
    public string Name { get; internal set; }

    public string Forwarder { get; internal set; }

    public uint Ordinal { get; internal set; }

    public uint RVA { get; internal set; }
}