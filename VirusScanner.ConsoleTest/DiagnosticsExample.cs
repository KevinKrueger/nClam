using System;
using System.Threading.Tasks;
using VirusScanner.ClamAV;

namespace VirusScanner.ConsoleTest
{
    /// <summary>
    /// Example showing ClamAV diagnostics and version information.
    /// </summary>
    class DiagnosticsExample
    {
        static async Task ExampleMain(string[] args)
        {
            Console.WriteLine("ðŸ›¡ï¸ VirusScanner.ClamAV Diagnostics Example");
            Console.WriteLine();

            var scanner = new ClamAvScanner("localhost", 3310);

            Console.WriteLine("ðŸ“‹ Quick Status Check:");
            await ClamDiagnostics.DisplayCompactStatusAsync(scanner);

            Console.WriteLine("\n" + new string('-', 50));

            Console.WriteLine("ðŸ“‹ Comprehensive Diagnostics:");
            var isConnected = await ClamDiagnostics.DisplayClamInfoAsync(scanner);

            if (!isConnected)
            {
                Console.WriteLine("\nâŒ Cannot proceed without ClamAV connection");
                Console.WriteLine("Press any key to exit...");
                Console.ReadKey();
                return;
            }

            Console.WriteLine("\nðŸ“‹ Ready for batch processing!");

            var (connected, version) = await ClamDiagnostics.QuickConnectionTestAsync(scanner);
            if (connected)
                Console.WriteLine($"\nðŸŽ¯ Proceeding with {version}");

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }
    }
}
