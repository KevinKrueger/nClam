using System;
using System.Threading.Tasks;
using nClam;

namespace nClam.ConsoleTest
{
    /// <summary>
    /// Utility methods for displaying ClamAV information and diagnostics
    /// </summary>
    public static class ClamDiagnostics
    {
        /// <summary>
        /// Displays comprehensive ClamAV connection and version information
        /// </summary>
        /// <param name="clamClient">The ClamClient to test</param>
        /// <returns>True if connection is successful, false otherwise</returns>
        public static async Task<bool> DisplayClamInfoAsync(IClamClient clamClient)
        {
            Console.WriteLine("ClamAV Connection Diagnostics");
            Console.WriteLine(new string('=', 40));

            // Test basic connectivity
            Console.Write("Testing connectivity: ");
            try
            {
                var pingResult = await clamClient.TryPingAsync();
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

            // Get version information
            Console.Write("Getting ClamAV version: ");
            try
            {
                var version = await clamClient.GetVersionAsync();
                Console.WriteLine($"SUCCESS - {version.Trim()}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"FAILED: {ex.Message}");
            }

            // Get daemon stats
            Console.Write("Getting daemon statistics: ");
            try
            {
                var stats = await clamClient.GetStatsAsync();
                Console.WriteLine("SUCCESS");

                // Parse and display key stats
                DisplayParsedStats(stats);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"FAILED: {ex.Message}");
            }

            // Test scan capability with EICAR test string
            await TestScanCapability(clamClient);

            Console.WriteLine(new string('=', 40));
            return true;
        }

        /// <summary>
        /// Tests the scanning capability using the EICAR test string
        /// </summary>
        private static async Task TestScanCapability(IClamClient clamClient)
        {
            Console.Write("Testing scan capability: ");
            try
            {
                // EICAR test string - standard antivirus test file
                var eicarString = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
                var eicarBytes = System.Text.Encoding.ASCII.GetBytes(eicarString);

                var scanResult = await clamClient.SendAndScanFileAsync(eicarBytes);

                if (scanResult.Result == ClamScanResults.VirusDetected)
                {
                    Console.WriteLine("SUCCESS - EICAR test virus detected");
                    if (scanResult.InfectedFiles?.Count > 0)
                    {
                        Console.WriteLine($"   Detected as: {scanResult.InfectedFiles[0].VirusName}");
                    }
                }
                else
                {
                    Console.WriteLine($"WARNING: Unexpected result: {scanResult.Result}");
                    Console.WriteLine("   EICAR test should be detected as virus");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"FAILED: {ex.Message}");
            }
        }

        /// <summary>
        /// Parses and displays daemon statistics in a readable format
        /// </summary>
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
                if (!string.IsNullOrEmpty(trimmedLine))
                {
                    // Parse common statistics
                    if (trimmedLine.StartsWith("POOLS:"))
                    {
                        Console.WriteLine($"      * Memory Pools: {trimmedLine.Substring(6).Trim()}");
                    }
                    else if (trimmedLine.StartsWith("STATE:"))
                    {
                        var state = trimmedLine.Substring(6).Trim();
                        var statePrefix = state.Contains("VALID") ? "[OK]" : "[WARN]";
                        Console.WriteLine($"      * Daemon State: {statePrefix} {state}");
                    }
                    else if (trimmedLine.StartsWith("THREADS:"))
                    {
                        Console.WriteLine($"      * Active Threads: {trimmedLine.Substring(8).Trim()}");
                    }
                    else if (trimmedLine.StartsWith("QUEUE:"))
                    {
                        Console.WriteLine($"      * Queue Length: {trimmedLine.Substring(6).Trim()}");
                    }
                    else if (trimmedLine.StartsWith("MEMSTATS:"))
                    {
                        Console.WriteLine($"      * Memory Usage: {trimmedLine.Substring(9).Trim()}");
                    }
                    else if (trimmedLine.Length < 100) // Avoid very long lines
                    {
                        Console.WriteLine($"      * {trimmedLine}");
                    }
                }
            }
        }

        /// <summary>
        /// Displays troubleshooting tips when connection fails
        /// </summary>
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

            await Task.Delay(100); // Small delay for better UX
        }

        /// <summary>
        /// Quick connection test without detailed output
        /// </summary>
        public static async Task<(bool IsConnected, string Version)> QuickConnectionTestAsync(IClamClient clamClient)
        {
            try
            {
                var pingResult = await clamClient.TryPingAsync();
                if (!pingResult)
                {
                    return (false, "");
                }

                var version = await clamClient.GetVersionAsync();
                return (true, version.Trim());
            }
            catch
            {
                return (false, "");
            }
        }

        /// <summary>
        /// Displays a compact connection status line
        /// </summary>
        public static async Task DisplayCompactStatusAsync(IClamClient clamClient)
        {
            var (isConnected, version) = await QuickConnectionTestAsync(clamClient);

            if (isConnected)
            {
                Console.WriteLine($"[OK] ClamAV Connected: {version}");
            }
            else
            {
                Console.WriteLine("[ERROR] ClamAV Not Available");
            }
        }
    }
}