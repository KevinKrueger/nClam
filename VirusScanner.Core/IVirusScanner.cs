using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace VirusScanner.Core
{
    /// <summary>
    /// Defines a provider-agnostic interface for virus scanning.
    /// </summary>
    public interface IVirusScanner
    {
        /// <summary>
        /// Checks whether the scanner backend is available and ready.
        /// </summary>
        Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default);

        /// <summary>
        /// Scans the provided byte array for viruses.
        /// </summary>
        Task<ScanResult> ScanAsync(byte[] data, CancellationToken cancellationToken = default);

        /// <summary>
        /// Scans the provided stream for viruses.
        /// </summary>
        Task<ScanResult> ScanAsync(Stream data, CancellationToken cancellationToken = default);

        /// <summary>
        /// Reads the file at <paramref name="filePath"/> and scans it for viruses.
        /// </summary>
        Task<ScanResult> ScanAsync(string filePath, CancellationToken cancellationToken = default);
    }
}
