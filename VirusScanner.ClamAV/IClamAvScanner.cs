using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using VirusScanner.Core;

namespace VirusScanner.ClamAV
{
    /// <summary>
    /// Defines the interface for a ClamAV scanner, extending <see cref="IVirusScanner"/> with
    /// ClamAV-specific operations.
    /// </summary>
    public interface IClamAvScanner : IVirusScanner
    {
        /// <summary>
        /// Maximum chunk size in bytes when streaming data to ClamAV. Default is 128 KB.
        /// </summary>
        int MaxChunkSize { get; set; }

        /// <summary>
        /// Maximum stream size in bytes before ClamAV terminates the connection. Default is 25 MB.
        /// </summary>
        long MaxStreamSize { get; set; }

        /// <summary>
        /// Hostname of the ClamAV server.
        /// </summary>
        string? Server { get; set; }

        /// <summary>
        /// IP address of the ClamAV server.
        /// </summary>
        IPAddress? ServerIP { get; set; }

        /// <summary>
        /// Port the ClamAV server is listening on.
        /// </summary>
        int Port { get; set; }

        /// <summary>
        /// Returns the ClamAV server version string.
        /// </summary>
        Task<string> GetVersionAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Returns the ClamAV server stats.
        /// </summary>
        Task<string> GetStatsAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Sends a PING to the ClamAV server. Throws if the server does not respond with PONG.
        /// </summary>
        Task<bool> PingAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Sends a PING to the ClamAV server. Returns false instead of throwing on failure.
        /// </summary>
        Task<bool> TryPingAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Instructs the ClamAV server to scan a file or directory on its own filesystem.
        /// </summary>
        Task<ClamAvScanResult> ScanFileOnServerAsync(string filePath, CancellationToken cancellationToken = default);

        /// <summary>
        /// Instructs the ClamAV server to scan a path using multiple threads on its own filesystem.
        /// </summary>
        Task<ClamAvScanResult> ScanFileOnServerMultithreadedAsync(string filePath, CancellationToken cancellationToken = default);

        /// <summary>
        /// Instructs the ClamAV server to scan continuously, reporting all infected files even after the first match.
        /// </summary>
        Task<ClamAvScanResult> ContScanFileOnServerAsync(string filePath, CancellationToken cancellationToken = default);

        /// <summary>
        /// Instructs the ClamAV server to scan and report all matching signatures per file.
        /// </summary>
        Task<ClamAvScanResult> AllMatchScanFileOnServerAsync(string filePath, CancellationToken cancellationToken = default);

        /// <summary>
        /// Shuts down the ClamAV server in an orderly fashion.
        /// </summary>
        Task Shutdown(CancellationToken cancellationToken);

        /// <summary>
        /// Instructs the ClamAV server to reload its virus signature databases.
        /// </summary>
        Task ReloadVirusDatabaseAsync(CancellationToken cancellationToken = default);
    }
}
