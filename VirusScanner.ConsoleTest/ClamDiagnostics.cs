using System;
using System.Linq;
using System.Threading.Tasks;
using VirusScanner.ClamAV;
using VirusScanner.Core;

namespace VirusScanner.ConsoleTest
{
    /// <summary>
    /// Utility methods for displaying ClamAV information and diagnostics.
    /// </summary>
    public static class ClamDiagnostics
    {
        /// <summary>
        /// Displays comprehensive ClamAV connection and version information.
        /// </summary>
        public static async Task<bool> DisplayClamInfoAsync(IClamAvScanner scanner)
        {
            Console.WriteLine("ClamAV Connection Diagnostics");
            Console.WriteLine(new string('=', 40));

            Console.Write("Testing connectivity: ");
            try
            {
                var pingResult = await scanner.TryPingAsync();
                if (!pingResult)
                {
                    Console.WriteLine("FAILED");
                    Console.WriteLine("   ClamAV daemon is not responding");
                    await DisplayTroubleshootingTips();
                    return false;
                }
                Console.WriteLine("SUCCESS");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: {ex.Message}");
                await DisplayTroubleshootingTips();
                return false;
            }

            Console.Write("Getting ClamAV version: ");
            try
            {
                var version = await scanner.GetVersionAsync();
                Console.WriteLine($"SUCCESS - {version.Trim()}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"FAILED: {ex.Message}");
            }

            Console.Write("Getting daemon statistics: ");
            try
            {
                var stats = await scanner.GetStatsAsync();
                Console.WriteLine("SUCCESS");
                DisplayParsedStats(stats);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"FAILED: {ex.Message}");
            }

            await TestScanCapability(scanner);

            Console.WriteLine(new string('=', 40));
            return true;
        }

        private static async Task TestScanCapability(IVirusScanner scanner)
        {
            Console.Write("Testing scan capability: ");
            try
            {
                var eicarBytes = System.Text.Encoding.ASCII.GetBytes(
                    @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

                var scanResult = await scanner.ScanAsync(eicarBytes);

                if (scanResult.Status == ScanStatus.VirusDetected)
                {
                    Console.WriteLine("SUCCESS - EICAR test virus detected");
                    if (scanResult.InfectedFiles?.Count > 0)
                        Console.WriteLine($"   Detected as: {scanResult.InfectedFiles.First().VirusName}");
                }
                else
                {
                    Console.WriteLine($"WARNING: Unexpected result: {scanResult.Status}");
                    Console.WriteLine("   EICAR test should be detected as virus");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"FAILED: {ex.Message}");
            }
        }

        private static void DisplayParsedStats(string rawStats)
        {
            if (string.IsNullOrEmpty(rawStats))
            {
                Console.WriteLine("   No statistics available");
                return;
            }

            Console.WriteLine("   Daemon Statistics:");
            var lines = rawStats.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines)
            {
                var trimmedLine = line.Trim();
                if (string.IsNullOrEmpty(trimmedLine)) continue;

                if (trimmedLine.StartsWith("POOLS:"))
                    Console.WriteLine($"      * Memory Pools: {trimmedLine.Substring(6).Trim()}");
                else if (trimmedLine.StartsWith("STATE:"))
                {
                    var state = trimmedLine.Substring(6).Trim();
                    Console.WriteLine($"      * Daemon State: {(state.Contains("VALID") ? "[OK]" : "[WARN]")} {state}");
                }
                else if (trimmedLine.StartsWith("THREADS:"))
                    Console.WriteLine($"      * Active Threads: {trimmedLine.Substring(8).Trim()}");
                else if (trimmedLine.StartsWith("QUEUE:"))
                    Console.WriteLine($"      * Queue Length: {trimmedLine.Substring(6).Trim()}");
                else if (trimmedLine.StartsWith("MEMSTATS:"))
                    Console.WriteLine($"      * Memory Usage: {trimmedLine.Substring(9).Trim()}");
                else if (trimmedLine.Length < 100)
                    Console.WriteLine($"      * {trimmedLine}");
            }
        }

        private static async Task DisplayTroubleshootingTips()
        {
            Console.WriteLine("\nTroubleshooting Tips:");
            Console.WriteLine("   [Docker] Check if ClamAV container is running:");
            Console.WriteLine("      docker ps | grep clam");
            Console.WriteLine("   [Network] Test port connectivity:");
            Console.WriteLine("      telnet localhost 3310");
            Console.WriteLine("   [Start] Start ClamAV container:");
            Console.WriteLine("      docker run -d -p 3310:3310 clamav/clamav:stable");
            Console.WriteLine("   [Logs] Check container logs:");
            Console.WriteLine("      docker logs <container-id>");
            await Task.Delay(100);
        }

        /// <summary>
        /// Quick connection test without detailed output.
        /// </summary>
        public static async Task<(bool IsConnected, string Version)> QuickConnectionTestAsync(IClamAvScanner scanner)
        {
            try
            {
                if (!await scanner.TryPingAsync())
                    return (false, "");

                var version = await scanner.GetVersionAsync();
                return (true, version.Trim());
            }
            catch
            {
                return (false, "");
            }
        }

        /// <summary>
        /// Displays a compact connection status line.
        /// </summary>
        public static async Task DisplayCompactStatusAsync(IClamAvScanner scanner)
        {
            var (isConnected, version) = await QuickConnectionTestAsync(scanner);
            Console.WriteLine(isConnected
                ? $"[OK] ClamAV Connected: {version}"
                : "[ERROR] ClamAV Not Available");
        }
    }
}

