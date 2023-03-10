# Portable Executable File Format

According to documentation at https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

- [x] Read base headers, section headers, data directory headers.
- [x] Read TLS callbacks.
- [x] Read Export Table.
- [x] Read Import Table.

Usage example:

```cs
using DV.Formats.PortableExecutable;

// Create source stream.
using (var stream = File.OpenRead(@"c:\my.exe"))
{
    // Create reader.
    var reader = new PEImageReader(stream, is_mapped: false)
    {
        // Optionally set log function to see errors and warnings.
        LogFunc = Console.WriteLine
    };

    // Open method will read PE headers, section headers, data directory headers.
    if (reader.Open())
    {
        // Read Thread Local Storage structures.
        if (reader.ReadTLS(out var tls))
        {
            // ...
        }

        // Read Export Table.
        if (reader.ReadExports(out var exports))
        {
            // ...
        }

        // Read Import Table.
        if (reader.ReadImports(out var imports))
        {
            // ...
        }
    }
}
```
