using System;
using System.Threading.Tasks;
using nClam;

namespace nClam.ConsoleTest
{
    /// <summary>
    /// Example program showing ClamAV diagnostics and version information
    /// </summary>
    class DiagnosticsExample
    {
        static async Task ExampleMain(string[] args)
        {
            Console.WriteLine("🛡️ nClam Diagnostics Example");
            Console.WriteLine();

            var clam = new ClamClient("localhost", 3310);

            // Option 1: Quick status check
            Console.WriteLine("📋 Quick Status Check:");
            await ClamDiagnostics.DisplayCompactStatusAsync(clam);

            Console.WriteLine("\n" + new string('-', 50));

            // Option 2: Comprehensive diagnostics
            Console.WriteLine("📋 Comprehensive Diagnostics:");
            var isConnected = await ClamDiagnostics.DisplayClamInfoAsync(clam);

            if (!isConnected)
            {
                Console.WriteLine("\n❌ Cannot proceed without ClamAV connection");
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
                return;
            }

            // Option 3: Integration with existing functionality
            Console.WriteLine("\n📋 Ready for batch processing!");
            Console.WriteLine("ClamAV is available and ready to scan files.");

            // Example: Quick connection validation before batch operations
            var (connected, version) = await ClamDiagnostics.QuickConnectionTestAsync(clam);
            if (connected)
            {
                Console.WriteLine($"\n🎯 Proceeding with {version}");
                // Your batch processing code here...
            }

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }
    }
}