using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using VirusScanner.Core;

namespace VirusScanner.ClamAV
{
    /// <summary>
    /// Extension methods for <see cref="IVirusScanner"/> to provide convenient batch processing.
    /// </summary>
    public static class ClamAvBatchExtensions
    {
        /// <summary>
        /// Creates a new <see cref="ClamAvBatchProcessor"/> for this scanner.
        /// </summary>
        public static ClamAvBatchProcessor CreateBatchProcessor(
            this IVirusScanner scanner,
            int maxConcurrency = 4,
            int connectionTimeoutSeconds = 10)
            => new ClamAvBatchProcessor(scanner, maxConcurrency, connectionTimeoutSeconds);

        /// <summary>
        /// Scans multiple files concurrently.
        /// </summary>
        public static async Task<IEnumerable<BatchScanResult>> BatchScanFilesAsync(
            this IVirusScanner scanner,
            IEnumerable<string> filePaths,
            int maxConcurrency = 4,
            int connectionTimeoutSeconds = 10,
            CancellationToken cancellationToken = default,
            IProgress<BatchProgress>? progressCallback = null)
        {
            var processor = new ClamAvBatchProcessor(scanner, maxConcurrency, connectionTimeoutSeconds);
            return await processor.ScanFilesAsync(filePaths, cancellationToken, progressCallback);
        }

        /// <summary>
        /// Scans all files in a directory.
        /// </summary>
        public static async Task<IEnumerable<BatchScanResult>> BatchScanDirectoryAsync(
            this IVirusScanner scanner,
            string directoryPath,
            string searchPattern = "*",
            bool recursive = false,
            int maxConcurrency = 4,
            CancellationToken cancellationToken = default,
            IProgress<BatchProgress>? progressCallback = null)
        {
            var processor = new ClamAvBatchProcessor(scanner, maxConcurrency);
            return await processor.ScanDirectoryAsync(directoryPath, searchPattern, recursive, cancellationToken, progressCallback);
        }

        /// <summary>
        /// Scans files matching specific extensions.
        /// </summary>
        public static async Task<IEnumerable<BatchScanResult>> BatchScanByExtensionsAsync(
            this IVirusScanner scanner,
            string directoryPath,
            IEnumerable<string> extensions,
            bool recursive = false,
            int maxConcurrency = 4,
            CancellationToken cancellationToken = default,
            IProgress<BatchProgress>? progressCallback = null)
        {
            var processor = new ClamAvBatchProcessor(scanner, maxConcurrency);
            return await processor.ScanByExtensionsAsync(directoryPath, extensions, recursive, cancellationToken, progressCallback);
        }

        /// <summary>
        /// Scans executable files in a directory.
        /// </summary>
        public static Task<IEnumerable<BatchScanResult>> BatchScanExecutableFilesAsync(
            this IVirusScanner scanner,
            string directoryPath,
            bool recursive = false,
            int maxConcurrency = 4,
            CancellationToken cancellationToken = default,
            IProgress<BatchProgress>? progressCallback = null)
            => scanner.BatchScanByExtensionsAsync(
                directoryPath,
                ClamAvBatchUtilities.CommonExtensions.Executable,
                recursive, maxConcurrency, cancellationToken, progressCallback);

        /// <summary>
        /// Scans high-risk files in a directory.
        /// </summary>
        public static Task<IEnumerable<BatchScanResult>> BatchScanHighRiskFilesAsync(
            this IVirusScanner scanner,
            string directoryPath,
            bool recursive = false,
            int maxConcurrency = 4,
            CancellationToken cancellationToken = default,
            IProgress<BatchProgress>? progressCallback = null)
            => scanner.BatchScanByExtensionsAsync(
                directoryPath,
                ClamAvBatchUtilities.CommonExtensions.HighRisk,
                recursive, maxConcurrency, cancellationToken, progressCallback);
    }
}
