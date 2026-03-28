# VirusScanner

A .NET library for virus scanning with a **provider-agnostic** design. `VirusScanner.Core` defines the interfaces and models; any backend can implement them. `VirusScanner.ClamAV` ships the first-party [ClamAV](https://www.clamav.net/) provider. Licensed under the [MIT License](LICENSE).

## Packages

Two NuGet packages are published from this repository:

| Package | Role | Target Frameworks |
|---|---|---|
| [`VirusScanner.Core`](https://www.nuget.org/packages/VirusScanner.Core) | Abstractions only – `IVirusScanner`, `IBatchProcessor`, shared models. No external dependencies. | `netstandard2.0`, `netstandard2.1`, `net10.0` |
| [`VirusScanner.ClamAV`](https://www.nuget.org/packages/VirusScanner.ClamAV) | ClamAV provider – implements `IVirusScanner` against a `clamd` server. Depends on `VirusScanner.Core`. | `netstandard2.0`, `netstandard2.1`, `net10.0` |

**Which package do I need?**

- **Libraries / shared code** that should stay backend-independent → install only `VirusScanner.Core` and code against `IVirusScanner`.
- **Applications** that use ClamAV → install only `VirusScanner.ClamAV`. `VirusScanner.Core` is pulled in automatically as a transitive dependency.

```
# Application – one package is enough, Core comes along automatically
Install-Package VirusScanner.ClamAV

# Library / shared project – abstractions only, no backend coupling
Install-Package VirusScanner.Core
```

## ClamAV Dependency

A running ClamAV (`clamd`) server is required. ClamAV is a free, open-source virus scanner.

Current stable release lines (as of 2026-03):
- 1.5.x (latest: 1.5.2)
- 1.4.x (latest: 1.4.4)
- 1.0.x LTS (latest: 1.0.9)

- Docs: https://docs.clamav.net/
- Releases: https://github.com/Cisco-Talos/clamav/releases

Communication uses the standard clamd protocol commands `PING`, `VERSION`, and `INSTREAM`, so VirusScanner is compatible with any current ClamAV release that supports the clamd protocol.

## Docker Compose

This repository includes a ready-to-use `docker-compose.yml` to run ClamAV locally.

```bash
# Start ClamAV
docker compose up -d

# Follow logs until clamd is ready
docker compose logs -f clamav

# Stop
docker compose down
```

**Connection settings:**
- .NET app running on the host machine → `localhost:3310`
- .NET app running as a Compose service in the same network → `clamav:3310`

## Quick Start

```csharp
using VirusScanner.ClamAV;
using VirusScanner.Core;

var scanner = new ClamAvScanner("localhost", 3310);

// Check connectivity
bool isReady = await scanner.TryPingAsync();

// Scan a file
ScanResult result = await scanner.ScanAsync(@"C:\test.txt");

switch (result.Status)
{
	case ScanStatus.Clean:
		Console.WriteLine("The file is clean!");
		break;
	case ScanStatus.VirusDetected:
		Console.WriteLine($"Virus found: {result.InfectedFiles![0].VirusName}");
		break;
	case ScanStatus.Error:
		Console.WriteLine("Scan error.");
		break;
}
```

You can also construct `ClamAvScanner` with an `IPAddress`:

```csharp
var scanner = new ClamAvScanner(IPAddress.Parse("127.0.0.1"), 3310);
```

## Scanning Overloads

`ClamAvScanner` implements `IVirusScanner` and supports scanning from multiple sources:

```csharp
// From a file path
ScanResult result = await scanner.ScanAsync(@"C:\test.txt");

// From a stream
await using var stream = File.OpenRead(@"C:\test.txt");
ScanResult result = await scanner.ScanAsync(stream);

// From a byte array
byte[] data = await File.ReadAllBytesAsync(@"C:\test.txt");
ScanResult result = await scanner.ScanAsync(data);
```

## ClamAV-specific Operations

```csharp
// PING – throws if the server does not respond with PONG
await scanner.PingAsync();

// TryPing – returns false instead of throwing
bool available = await scanner.TryPingAsync();

// Server version string
string version = await scanner.GetVersionAsync();

// Server stats
string stats = await scanner.GetStatsAsync();
```

## Batch Processing

`VirusScanner.ClamAV` includes batch processing for scanning multiple files efficiently.

### Extension Methods (simplest)

```csharp
// Scan a list of files
IEnumerable<BatchScanResult> results = await scanner.BatchScanFilesAsync(filePaths);

// Scan a directory
IEnumerable<BatchScanResult> results = await scanner.BatchScanDirectoryAsync(
	@"C:\MyFolder", recursive: true);

// Scan by file extensions
IEnumerable<BatchScanResult> results = await scanner.BatchScanByExtensionsAsync(
	@"C:\MyFolder", new[] { ".exe", ".dll" });

// Scan executable files only
IEnumerable<BatchScanResult> results = await scanner.BatchScanExecutableFilesAsync(
	@"C:\MyFolder", recursive: true);
```

### ClamAvBatchProcessor (more control)

```csharp
var processor = new ClamAvBatchProcessor(scanner, maxConcurrency: 4, connectionTimeoutSeconds: 10);

IEnumerable<BatchScanResult> results = await processor.ScanDirectoryAsync(
	@"C:\MyFolder", recursive: true);
```

### Progress Reporting

```csharp
var progress = new Progress<BatchProgress>(p =>
{
	Console.WriteLine($"Progress: {p.CompletedFiles}/{p.TotalFiles} ({p.PercentageComplete:F1}%)");
	Console.WriteLine($"Current:  {p.CurrentFile}");
});

var results = await scanner.BatchScanDirectoryAsync(
	@"C:\MyFolder",
	recursive: true,
	progressCallback: progress);
```

### Result Analysis

```csharp
// Generate a detailed text report
string report = ClamAvBatchUtilities.GenerateReport(results, DateTime.Now);

// Filter results
var infected = results.Where(r => r.IsInfected);
var errors   = results.Where(r => r.HasError);
var clean    = results.Where(r => r.IsClean);
```

### Batch Processing Features

- **Concurrent scanning** – configurable degree of parallelism
- **Progress tracking** – real-time `IProgress<BatchProgress>` callbacks
- **Directory scanning** – recursive and non-recursive
- **File filtering** – by extension or predefined categories
- **Connection resilience** – graceful handling of daemon disconnections
- **Configurable timeouts** – prevent hanging operations
- **Report generation** – built-in text report via `ClamAvBatchUtilities`

## Project Structure

| Project | Description |
|---|---|
| `VirusScanner.Core` | Abstractions: `IVirusScanner`, `IBatchProcessor`, `ScanResult`, `ScanStatus`, `BatchScanResult`, `BatchProgress`, `InfectedFile`, `ScanException` |
| `VirusScanner.ClamAV` | ClamAV implementation: `ClamAvScanner`, `IClamAvScanner`, `ClamAvBatchProcessor`, `ClamAvBatchExtensions`, `ClamAvBatchUtilities` |
| `VirusScanner.ConsoleTest` | Interactive console test application |
| `VirusScanner.Tests` | Unit and integration tests |

## Custom Providers

Because all consuming code depends only on `IVirusScanner` from `VirusScanner.Core`, you can swap or add any backend without touching the rest of your application.

```csharp
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using VirusScanner.Core;

// Example: a provider that delegates to a proprietary REST API
public class MyRestScanner : IVirusScanner
{
	public Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
		=> /* call health endpoint */ Task.FromResult(true);

	public Task<ScanResult> ScanAsync(byte[] data, CancellationToken cancellationToken = default)
		=> ScanAsync(new MemoryStream(data), cancellationToken);

	public async Task<ScanResult> ScanAsync(Stream data, CancellationToken cancellationToken = default)
	{
		// send stream to your API, parse response
		return new ScanResult(ScanStatus.Clean);
	}

	public async Task<ScanResult> ScanAsync(string filePath, CancellationToken cancellationToken = default)
	{
		await using var stream = File.OpenRead(filePath);
		return await ScanAsync(stream, cancellationToken);
	}
}
```

Register it exactly like the built-in ClamAV provider:

```csharp
// ASP.NET Core – swap the implementation without changing any other code
builder.Services.AddScoped<IVirusScanner, MyRestScanner>();
// or
builder.Services.AddScoped<IVirusScanner, ClamAvScanner>(_ => new ClamAvScanner("localhost", 3310));
```

The same principle applies to `IBatchProcessor` – implement it to add batch support to any provider.

## Contributing

PRs are welcome! See [VirusScanner.ConsoleTest/Program.cs](https://github.com/KevinKrueger/VirusScanner/blob/master/VirusScanner.ConsoleTest/Program.cs) for a full usage example.
