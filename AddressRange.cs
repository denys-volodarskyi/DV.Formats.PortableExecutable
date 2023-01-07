namespace DV.Formats.PortableExecutable;

public struct AddressRange
{
    public AddressRange(ulong address, ulong size)
    {
        Address = address;
        Size = size;
    }

    public ulong Address { get; set; }
    public ulong Size { get; set; }

    public ulong End => Address + Size;
    public bool Empty => Size == 0;
    public bool Has(ulong address) => address >= Address && address < End;

    public override string ToString() => $"0x{Address:X}-0x{End:X} (0x{Size:X})";
}