using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using nClam;

namespace nClam.ConsoleTest
{
    /// <summary>
    /// Example demonstrating resilient batch processing that handles ClamAV daemon failures gracefully
    /// </summary>
    public class ResilientBatchProcessingExample
    {
        public static async Task RunExample()
        {
            Console.WriteLine("🛡️ Resilient Batch Processing Example");
            Console.WriteLine("This example shows how to handle ClamAV daemon disconnections gracefully.\n");

            var clam = new ClamClient("localhost", 3310);

            // Example 1: Connection Check Before Batch Processing
            await Example1_PreConnectionCheck(clam);

            Console.WriteLine("\n" + new string('=', 50));

            // Example 2: Timeout and Retry Handling
            await Example2_TimeoutHandling(clam);

            Console.WriteLine("\n" + new string('=', 50));

            // Example 3: Progress Monitoring with Error Tracking
            await Example3_ErrorTracking(clam);
        }

        private static async Task Example1_PreConnectionCheck(ClamClient clam)
        {
            Console.WriteLine("📋 Example 1: Pre-Connection Check");
            Console.WriteLine("Always check ClamAV availability before starting batch operations.\n");

            try
            {
                Console.Write("🔍 Testing connection to ClamAV daemon...");
                
                var isAvailable = await clam.TryPingAsync();
                
                if (!isAvailable)
                {
                    Console.WriteLine(" ❌ FAILED");
                    Console.WriteLine("ClamAV daemon is not available. Possible causes:");
                    Console.WriteLine("  • Container is not running: docker ps | grep clamav");
                    Console.WriteLine("  • Port not accessible: telnet localhost 3310");
                    Console.WriteLine("  • Network issues or firewall blocking connection");
                    Console.WriteLine("\nSkipping batch processing to avoid hanging.");
                    return;
                }
                
                Console.WriteLine(" ✅ SUCCESS");
                Console.WriteLine("ClamAV daemon is available and responding.");
                
                // If available, proceed with a small test batch
                var testFiles = Directory.GetFiles(Directory.GetCurrentDirectory())
                    .Take(3) // Just a few files for demo
                    .ToArray();

                if (testFiles.Any())
                {
                    Console.WriteLine($"\n📁 Testing batch scan with {testFiles.Length} files...");
                    var processor = new ClamBatchProcessor(clam, maxConcurrency: 2, connectionTimeoutSeconds: 5);
                    var results = await processor.ScanFilesAsync(testFiles);
                    
                    var successful = results.Count(r => r.Success);
                    var failed = results.Count(r => !r.Success);
                    
                    Console.WriteLine($"Results: {successful} successful, {failed} failed");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($" ❌ ERROR: {ex.Message}");
            }
        }

        private static async Task Example2_TimeoutHandling(ClamClient clam)
        {
            Console.WriteLine("📋 Example 2: Timeout and Connection Error Handling");
            Console.WriteLine("Demonstrates graceful handling when ClamAV becomes unavailable during scanning.\n");

            var processor = new ClamBatchProcessor(clam, maxConcurrency: 2, connectionTimeoutSeconds: 3);

            // Create a list of files to scan (even if they don't exist, for demo)
            var testFiles = new[]
            {
                "file1.txt",
                "file2.exe", 
                "file3.pdf",
                "nonexistent.dll"
            };

            try
            {
                Console.WriteLine("🔄 Starting scan with short timeout (3 seconds)...");
                Console.WriteLine("If ClamAV container stops during this, you'll see graceful error handling.\n");

                var progress = new Progress<ClamBatchProgress>(p =>
                {
                    Console.Write($"\r📊 Progress: {p.CompletedFiles}/{p.TotalFiles} " +
                                 $"({p.PercentageComplete:F0}%) - {p.CurrentFile}");
                });

                var results = await processor.ScanFilesAsync(testFiles, progressCallback: progress);
                
                Console.WriteLine("\n\n📈 Scan completed. Results breakdown:");

                foreach (var result in results)
                {
                    var status = result.Success ? "✅" : "❌";
                    var duration = result.ScanDuration.TotalMilliseconds;
                    
                    Console.WriteLine($"{status} {result.FileName} ({duration:F0}ms)");
                    
                    if (!result.Success)
                    {
                        Console.WriteLine($"   └─ Error: {result.ErrorMessage}");
                    }
                }

                // Count connection-related errors
                var connectionErrors = results.Where(r => 
                    !r.Success && (
                        r.ErrorMessage?.Contains("Connection") == true ||
                        r.ErrorMessage?.Contains("ClamAV daemon") == true ||
                        r.ErrorMessage?.Contains("timeout", StringComparison.OrdinalIgnoreCase) == true
                    )).ToList();

                if (connectionErrors.Any())
                {
                    Console.WriteLine($"\n⚠️ {connectionErrors.Count} files failed due to connection issues.");
                    Console.WriteLine("This is normal if the ClamAV container was stopped during scanning.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n❌ Batch processing error: {ex.Message}");
            }
        }

        private static async Task Example3_ErrorTracking(ClamClient clam)
        {
            Console.WriteLine("📋 Example 3: Advanced Error Tracking and Recovery");
            Console.WriteLine("Shows how to monitor and report on different types of scanning failures.\n");

            try
            {
                // Get some real files to scan
                var currentDir = Directory.GetCurrentDirectory();
                var realFiles = Directory.GetFiles(currentDir)
                    .Take(5)
                    .ToList();

                if (!realFiles.Any())
                {
                    Console.WriteLine("No files found in current directory for demo.");
                    return;
                }

                Console.WriteLine($"📂 Scanning {realFiles.Count} files from: {currentDir}");

                var processor = new ClamBatchProcessor(clam, maxConcurrency: 3, connectionTimeoutSeconds: 8);
                
                var errorTracker = new Dictionary<string, int>();
                var startTime = DateTime.Now;

                var progress = new Progress<ClamBatchProgress>(p =>
                {
                    var elapsed = DateTime.Now - startTime;
                    Console.Write($"\r⏱️ {elapsed:mm\\:ss} | Progress: {p.CompletedFiles}/{p.TotalFiles} " +
                                 $"({p.PercentageComplete:F0}%) - {Path.GetFileName(p.CurrentFile)}".PadRight(80));
                });

                var results = await processor.ScanFilesAsync(realFiles, progressCallback: progress);
                
                Console.WriteLine("\n\n📊 Final Results Analysis:");

                // Categorize results
                var clean = results.Where(r => r.IsClean).ToList();
                var infected = results.Where(r => r.IsInfected).ToList();
                var errors = results.Where(r => r.HasError).ToList();

                Console.WriteLine($"✅ Clean files: {clean.Count}");
                Console.WriteLine($"🦠 Infected files: {infected.Count}");
                Console.WriteLine($"❌ Error files: {errors.Count}");

                if (errors.Any())
                {
                    Console.WriteLine("\n🔍 Error Analysis:");
                    
                    var errorGroups = errors.GroupBy(e => GetErrorCategory(e.ErrorMessage ?? "Unknown"));
                    
                    foreach (var group in errorGroups)
                    {
                        Console.WriteLine($"   {group.Key}: {group.Count()} files");
                        
                        // Show first few examples
                        foreach (var example in group.Take(2))
                        {
                            Console.WriteLine($"      • {Path.GetFileName(example.FilePath)}");
                        }
                    }
                }

                var totalTime = results.Sum(r => r.ScanDuration.TotalMilliseconds);
                var avgTime = results.Where(r => r.Success).Average(r => r.ScanDuration.TotalMilliseconds);
                
                Console.WriteLine($"\n⚡ Performance: Total {totalTime:F0}ms, Average {avgTime:F0}ms per file");

            }
            catch (Exception ex)
            {
                Console.WriteLine($"\n💥 Unexpected error: {ex.Message}");
                Console.WriteLine("This suggests a more fundamental issue with the batch processor setup.");
            }
        }

        private static string GetErrorCategory(string errorMessage)
        {
            if (errorMessage.Contains("Connection") || errorMessage.Contains("ClamAV daemon"))
                return "🔌 Connection Issues";
            
            if (errorMessage.Contains("timeout", StringComparison.OrdinalIgnoreCase))
                return "⏰ Timeout Issues";
                
            if (errorMessage.Contains("File not found"))
                return "📁 File Access Issues";
                
            if (errorMessage.Contains("cancelled", StringComparison.OrdinalIgnoreCase))
                return "🛑 Operation Cancelled";
                
            return "❓ Other Issues";
        }

        // Quick utility method to simulate ClamAV container stopping
        public static void SimulateContainerStop()
        {
            Console.WriteLine("\n🔴 To simulate the issue you experienced:");
            Console.WriteLine("1. Start a batch scan in another terminal:");
            Console.WriteLine("   dotnet run");
            Console.WriteLine("2. While it's running, stop the ClamAV container:");
            Console.WriteLine("   docker stop <clamav-container>");
            Console.WriteLine("3. Watch how the improved error handling prevents hanging");
            Console.WriteLine("4. Restart the container to resume:");
            Console.WriteLine("   docker start <clamav-container>");
        }
    }
}