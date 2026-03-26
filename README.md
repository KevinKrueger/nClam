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

# ClamAV Setup for Windows
For directions on setting up ClamAV as a Windows Service, check out [this blog post](http://architectryan.com/2011/05/19/nclam-a-dotnet-library-to-virus-scan/).

# Test Application
For more information about how to use nClam, you can look at the nClam.ConsoleTest project's [Program.cs](https://github.com/KevinKrueger/nClam/blob/master/nClam.ConsoleTest/Program.cs).

# Contributing
I accept PRs!  We have had several contributors help maintain this library by fixing bugs, introducing async support, and moving to .NET Core.  Thank you to all the contributors!
