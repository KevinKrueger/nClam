using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace VirusScanner.Core
{
    /// <summary>
    /// Defines a provider-agnostic interface for batch virus scanning.
    /// </summary>
    public interface IBatchProcessor
    {
        /// <summary>
        /// Scans multiple files concurrently.
        /// </summary>
        Task<IEnumerable<BatchScanResult>> ScanFilesAsync(
            IEnumerable<string> filePaths,
            CancellationToken cancellationToken = default,
            IProgress<BatchProgress>? progressCallback = null);

        /// <summary>
        /// Scans all files in a directory.
        /// </summary>
        Task<IEnumerable<BatchScanResult>> ScanDirectoryAsync(
            string directoryPath,
            string searchPattern = "*",
            bool recursive = false,
            CancellationToken cancellationToken = default,
            IProgress<BatchProgress>? progressCallback = null);
    }
}
