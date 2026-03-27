# nClam  #
nClam is a tiny library which helps you scan files or directories using a ClamAV server.  It contains a simple API which encapsulates the communication with the ClamAV server as well as the parsing of its results.  The library is licensed under the Apache License 2.0.

## Dependencies
ClamAV Server, also known as clamd. It is a free, open-source virus scanner.

Current stable release lines (as of 2026-03):
- 1.5.x (latest: 1.5.2)
- 1.4.x (latest: 1.4.4)
- 1.0.x LTS (latest: 1.0.9)

For installation and platform-specific setup, use the official ClamAV docs and release pages:
- https://docs.clamav.net/
- https://github.com/Cisco-Talos/clamav/releases

## Compatibility Notes
nClam communicates with clamd via the standard protocol commands `PING`, `VERSION`, and `INSTREAM`.
Because of this, it is generally compatible with current ClamAV releases that support the clamd protocol.

## Docker Compose
If you want to run ClamAV locally with Docker Compose, this repository includes a ready-to-use `docker-compose.yml`.

Start ClamAV:

```bash
docker compose up -d
```

Follow logs until clamd is ready:

```bash
docker compose logs -f clamav
```

Stop it again:

```bash
docker compose down
```

### C# connection settings
- If your .NET app runs on your host machine: use `localhost:3310`.
- If your .NET app runs as another Compose service in the same Compose network: use `clamav:3310` (service name as host).

Minimal connectivity check:

```csharp
var clam = new ClamClient("localhost", 3310);
var isReady = await clam.TryPingAsync();
```

## NuGet Package

	Install-Package nClam

## Directions
1. Add the nuget package to your project.
2. Create a nClam.ClamClient object, passing it the hostname (or IP address) and port of the ClamAV server.
3. Scan!

# Code Example
```csharp
using System;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using nClam;

class Program
{
	static async Task Main(string[] args)
	{
		var clam = new ClamClient("localhost", 3310);
		// or var clam = new ClamClient(IPAddress.Parse("127.0.0.1"), 3310);
		var scanResult = await clam.ScanFileOnServerAsync("C:\\test.txt");  //any file you would like!

		switch (scanResult.Result)
		{
			case ClamScanResults.Clean:
				Console.WriteLine("The file is clean!");
				break;
			case ClamScanResults.VirusDetected:
				Console.WriteLine("Virus Found!");
				Console.WriteLine("Virus name: {0}", scanResult.InfectedFiles.First().VirusName);
				break;
			case ClamScanResults.Error:
				Console.WriteLine("Woah an error occured! Error: {0}", scanResult.RawResult);
				break;
		}

	}
}
```

## Batch Processing (Built-in)

nClam includes comprehensive batch processing capabilities for scanning multiple files efficiently:

### Quick Start - Batch Scanning
```csharp
using nClam;

var clam = new ClamClient("localhost", 3310);

// Method 1: Using extension methods (simplest)
var results = await clam.BatchScanDirectoryAsync(@"C:\MyFolder", recursive: true);

// Method 2: Using ClamBatchProcessor (more control)
var processor = new ClamBatchProcessor(clam, maxConcurrency: 4);
var results = await processor.ScanDirectoryAsync(@"C:\MyFolder", recursive: true);

// Method 3: Scan specific file types only
var results = await clam.BatchScanExecutableFilesAsync(@"C:\MyFolder", recursive: true);
```

### Batch Processing Features
- ✅ **Concurrent Scanning**: Process multiple files simultaneously (configurable concurrency)
- ✅ **Progress Tracking**: Real-time progress updates with callbacks
- ✅ **Directory Scanning**: Recursive and non-recursive directory scanning
- ✅ **File Filtering**: Scan by extensions or predefined categories (executables, documents, etc.)
- ✅ **Connection Resilience**: Graceful handling of ClamAV daemon disconnections
- ✅ **Timeout Management**: Configurable timeouts to prevent hanging operations
- ✅ **Error Resilience**: Comprehensive error handling and reporting
- ✅ **Result Analysis**: Built-in statistics, filtering, and export capabilities
- ✅ **Memory Efficient**: Optimized for large file sets

### Available Extension Methods
```csharp
// Scan multiple files
await clam.BatchScanFilesAsync(filePaths);

// Scan directory
await clam.BatchScanDirectoryAsync(@"C:\MyFolder", recursive: true);

// Scan by file extensions
await clam.BatchScanByExtensionsAsync(@"C:\MyFolder", new[] {".exe", ".dll"});

// Scan executable files only
await clam.BatchScanExecutableFilesAsync(@"C:\MyFolder", recursive: true);

// Scan high-risk files only
await clam.BatchScanHighRiskFilesAsync(@"C:\MyFolder", recursive: true);
```

### Connection Resilience Example
```csharp
// Create processor with timeout to prevent hanging
var processor = new ClamBatchProcessor(clam, 
	maxConcurrency: 4, 
	connectionTimeoutSeconds: 10);

// Always check connection before batch operations
if (!await clam.TryPingAsync())
{
	Console.WriteLine("ClamAV daemon is not available");
	return;
}

// Batch processing will gracefully handle connection failures
var results = await processor.ScanDirectoryAsync(@"C:\MyFolder");

// Check for connection-related failures
var connectionErrors = results.Where(r => 
	r.ErrorMessage?.Contains("Connection") == true);

if (connectionErrors.Any())
{
	Console.WriteLine($"{connectionErrors.Count()} files failed due to connection issues");
}
```
```csharp
var progress = new Progress<ClamBatchProgress>(p =>
{
	Console.WriteLine($"Progress: {p.CompletedFiles}/{p.TotalFiles} ({p.PercentageComplete:F1}%)");
	Console.WriteLine($"Current: {Path.GetFileName(p.CurrentFile)}");
});

var results = await clam.BatchScanDirectoryAsync(@"C:\MyFolder", 
	recursive: true, 
	progressCallback: progress);
```

### Result Analysis and Export
```csharp
// Get detailed statistics
var stats = ClamBatchUtilities.GetStatistics(results);
Console.WriteLine($"Clean: {stats.CleanFiles}, Infected: {stats.InfectedFiles}");
Console.WriteLine($"Infection Rate: {stats.InfectionRate:F2}%");

// Filter results
var infectedFiles = ClamBatchUtilities.GetInfectedFiles(results);
var cleanFiles = ClamBatchUtilities.GetCleanFiles(results);

// Export to CSV for analysis
await ClamBatchUtilities.SaveToCsvAsync(results, "scan_results.csv");

// Generate detailed report
var report = ClamBatchUtilities.GenerateReport(results, DateTime.Now);
```

### Predefined File Categories
```csharp
// Use built-in file extension categories
ClamBatchUtilities.CommonExtensions.Executable  // .exe, .dll, .bat, etc.
ClamBatchUtilities.CommonExtensions.Document    // .pdf, .docx, .xlsx, etc.
ClamBatchUtilities.CommonExtensions.Archive     // .zip, .rar, .7z, etc.
ClamBatchUtilities.CommonExtensions.HighRisk    // High-priority security scan targets
```

# ClamAV Setup for Windows
For directions on setting up ClamAV as a Windows Service, check out [this blog post](http://architectryan.com/2011/05/19/nclam-a-dotnet-library-to-virus-scan/).

# Test Application
For more information about how to use nClam, you can look at the nClam.ConsoleTest project's [Program.cs](https://github.com/KevinKrueger/nClam/blob/master/nClam.ConsoleTest/Program.cs).

# Contributing
I accept PRs!  We have had several contributors help maintain this library by fixing bugs, introducing async support, and moving to .NET Core.  Thank you to all the contributors!
