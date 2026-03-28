using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using VirusScanner.ClamAV;
using VirusScanner.Core;
using VirusScanner.ConsoleTest;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("VirusScanner.ClamAV â€“ Test Application");
        Console.WriteLine();

        Console.Write("\t* Testing connectivity: ");

        var scanner = new ClamAvScanner("localhost", 3310, 1_000_000_000);
        if (!await ClamDiagnostics.DisplayClamInfoAsync(scanner))
        {
            Console.WriteLine("\nâŒ Cannot proceed without ClamAV connection");
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
            return;
        }

        Console.WriteLine("connected.");

        Console.WriteLine("\nSelect scanning option:");
        Console.WriteLine("1. Single file scan");
        Console.WriteLine("2. Batch scan directory");
        Console.WriteLine("3. Batch scan by file extensions");
        Console.WriteLine("4. Batch scan specific files");
        Console.Write("Enter choice (1-4): ");

        var choice = Console.ReadLine();

        switch (choice)
        {
            case "1":
                await ScanSingleFile(scanner);
                break;
            case "2":
                await BatchScanDirectory(scanner);
                break;
            case "3":
                await BatchScanByExtensions(scanner);
                break;
            case "4":
                await BatchScanSpecificFiles(scanner);
                break;
            default:
                Console.WriteLine("Invalid choice. Defaulting to single file scan.");
                await ScanSingleFile(scanner);
                break;
        }
    }

    static async Task ScanSingleFile(ClamAvScanner scanner)
    {
        Console.WriteLine("\n--- Single File Scan ---");
        Console.Write("Enter file path: ");
        var filePath = Console.ReadLine();

        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
        {
            Console.WriteLine("File not found.");
            return;
        }

        try
        {
            Console.Write($"\t* Scanning file: {Path.GetFileName(filePath)}...");
            var scanResult = await scanner.ScanAsync(filePath);

            switch (scanResult.Status)
            {
                case ScanStatus.Clean:
                    Console.WriteLine(" The file is clean!");
                    break;
                case ScanStatus.VirusDetected:
                    Console.WriteLine(" Virus Found!");
                    Console.WriteLine($"Virus name: {scanResult.InfectedFiles?.First().VirusName}");
                    break;
                case ScanStatus.Error:
                    var raw = (scanResult as ClamAvScanResult)?.RawResult ?? "Scan error";
                    Console.WriteLine($" Error occurred! {raw}");
                    break;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($" Error: {ex.Message}");
        }
    }

    static async Task BatchScanDirectory(ClamAvScanner scanner)
    {
        Console.WriteLine("\n--- Batch Directory Scan ---");
        Console.Write("Enter directory path: ");
        var directoryPath = Console.ReadLine();

        if (string.IsNullOrEmpty(directoryPath) || !Directory.Exists(directoryPath))
        {
            Console.WriteLine("Directory not found. Using current directory.");
            directoryPath = Directory.GetCurrentDirectory();
        }

        Console.Write("Include subdirectories? (y/n): ");
        var recursive = Console.ReadLine()?.ToLower().StartsWith("y") == true;

        var processor = new ClamAvBatchProcessor(scanner, maxConcurrency: 3);
        var progress = new Progress<BatchProgress>(p =>
            Console.Write($"\rProgress: {p.CompletedFiles}/{p.TotalFiles} ({p.PercentageComplete:F1}%) - {p.CurrentFile}"));

        try
        {
            Console.WriteLine($"\nScanning directory: {directoryPath}");
            var results = await processor.ScanDirectoryAsync(directoryPath, "*", recursive, progressCallback: progress);

            Console.WriteLine("\n\nScan Results:");
            DisplayBatchResults(results);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\nError during batch scan: {ex.Message}");
        }
    }

    static async Task BatchScanByExtensions(ClamAvScanner scanner)
    {
        Console.WriteLine("\n--- Batch Scan by Extensions ---");
        Console.Write("Enter directory path: ");
        var directoryPath = Console.ReadLine();

        if (string.IsNullOrEmpty(directoryPath) || !Directory.Exists(directoryPath))
        {
            Console.WriteLine("Directory not found. Using current directory.");
            directoryPath = Directory.GetCurrentDirectory();
        }

        Console.Write("Enter file extensions (comma-separated, e.g., .exe,.dll,.pdf): ");
        var extensionsInput = Console.ReadLine();
        var extensions = extensionsInput?.Split(',', StringSplitOptions.RemoveEmptyEntries)
                                        .Select(ext => ext.Trim())
                                        .ToArray() ?? new[] { ".exe", ".dll" };

        Console.Write("Include subdirectories? (y/n): ");
        var recursive = Console.ReadLine()?.ToLower().StartsWith("y") == true;

        var processor = new ClamAvBatchProcessor(scanner, maxConcurrency: 3);
        var progress = new Progress<BatchProgress>(p =>
            Console.Write($"\rProgress: {p.CompletedFiles}/{p.TotalFiles} ({p.PercentageComplete:F1}%) - {p.CurrentFile}"));

        try
        {
            Console.WriteLine($"\nScanning files with extensions: {string.Join(", ", extensions)}");
            var results = await processor.ScanByExtensionsAsync(directoryPath, extensions, recursive, progressCallback: progress);

            Console.WriteLine("\n\nScan Results:");
            DisplayBatchResults(results);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\nError during batch scan: {ex.Message}");
        }
    }

    static async Task BatchScanSpecificFiles(ClamAvScanner scanner)
    {
        Console.WriteLine("\n--- Batch Scan Specific Files ---");
        Console.WriteLine("Enter file paths (one per line, empty line to finish):");

        var filePaths = new List<string>();
        string? input;
        while (!string.IsNullOrEmpty(input = Console.ReadLine()))
            filePaths.Add(input);

        if (!filePaths.Any())
        {
            Console.WriteLine("No files specified. Adding files from current directory.");
            filePaths.AddRange(Directory.GetFiles(Directory.GetCurrentDirectory(), "*.*").Take(5));
        }

        var processor = new ClamAvBatchProcessor(scanner, maxConcurrency: 3);
        var progress = new Progress<BatchProgress>(p =>
            Console.Write($"\rProgress: {p.CompletedFiles}/{p.TotalFiles} ({p.PercentageComplete:F1}%) - {Path.GetFileName(p.CurrentFile)}"));

        try
        {
            Console.WriteLine($"\nScanning {filePaths.Count} files...");
            var results = await processor.ScanFilesAsync(filePaths, progressCallback: progress);

            Console.WriteLine("\n\nScan Results:");
            DisplayBatchResults(results);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\nError during batch scan: {ex.Message}");
        }
    }

    static void DisplayBatchResults(IEnumerable<BatchScanResult> results)
    {
        var resultList = results.ToList();
        var cleanCount = resultList.Count(r => r.IsClean);
        var infectedCount = resultList.Count(r => r.IsInfected);
        var errorCount = resultList.Count(r => r.HasError);

        Console.WriteLine($"\nðŸ“Š Summary: {cleanCount} Clean | {infectedCount} Infected | {errorCount} Errors");
        Console.WriteLine(new string('-', 80));

        foreach (var result in resultList)
        {
            var status = result.IsClean ? "âœ… CLEAN" : result.IsInfected ? "ðŸ¦  INFECTED" : "âŒ ERROR";
            var fileSize = result.FileSize > 0 ? $"({result.FileSize:N0} bytes)" : "";
            var duration = result.ScanDuration.TotalMilliseconds > 0 ? $"({result.ScanDuration.TotalMilliseconds:F0}ms)" : "";

            Console.WriteLine($"{status,-12} {result.FileName,-30} {fileSize,-15} {duration}");

            if (result.IsInfected && result.ScanResult?.InfectedFiles?.Any() == true)
            {
                foreach (var infection in result.ScanResult.InfectedFiles)
                    Console.WriteLine($"             â””â”€ Virus: {infection.VirusName}");
            }
            else if (result.HasError && !string.IsNullOrEmpty(result.ErrorMessage))
            {
                Console.WriteLine($"             â””â”€ Error: {result.ErrorMessage}");
            }
        }

        var totalDuration = resultList.Where(r => r.Success).Sum(r => r.ScanDuration.TotalMilliseconds);
        Console.WriteLine(new string('-', 80));
        Console.WriteLine($"Total scan time: {totalDuration:F0}ms");
    }
}

