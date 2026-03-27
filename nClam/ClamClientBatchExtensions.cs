using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace nClam
{
    /// <summary>
    /// Extension methods for IClamClient to provide convenient batch processing functionality
    /// </summary>
    public static class ClamClientBatchExtensions
    {
        /// <summary>
        /// Creates a new batch processor for this ClamClient
        /// </summary>
        /// <param name="clamClient">The ClamClient instance</param>
        /// <param name="maxConcurrency">Maximum number of concurrent scans (default: 4)</param>
        /// <param name="connectionTimeoutSeconds">Connection timeout in seconds (default: 10)</param>
        /// <returns>A new ClamBatchProcessor instance</returns>
        public static ClamBatchProcessor CreateBatchProcessor(this IClamClient clamClient, int maxConcurrency = 4, int connectionTimeoutSeconds = 10)
        {
            return new ClamBatchProcessor(clamClient, maxConcurrency, connectionTimeoutSeconds);
        }

        /// <summary>
        /// Scans multiple files concurrently using this ClamClient
        /// </summary>
        /// <param name="clamClient">The ClamClient instance</param>
        /// <param name="filePaths">Collection of file paths to scan</param>
        /// <param name="maxConcurrency">Maximum number of concurrent scans (default: 4)</param>
        /// <param name="connectionTimeoutSeconds">Connection timeout in seconds (default: 10)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <param name="progressCallback">Optional callback to report progress</param>
        /// <returns>Collection of batch scan results</returns>
        public static async Task<IEnumerable<ClamBatchScanResult>> BatchScanFilesAsync(
            this IClamClient clamClient,
            IEnumerable<string> filePaths,
            int maxConcurrency = 4,
            int connectionTimeoutSeconds = 10,
            CancellationToken cancellationToken = default,
            IProgress<ClamBatchProgress>? progressCallback = null)
        {
            var processor = new ClamBatchProcessor(clamClient, maxConcurrency, connectionTimeoutSeconds);
            return await processor.ScanFilesAsync(filePaths, cancellationToken, progressCallback);
        }

        /// <summary>
        /// Scans all files in a directory using this ClamClient
        /// </summary>
        /// <param name="clamClient">The ClamClient instance</param>
        /// <param name="directoryPath">Directory to scan</param>
        /// <param name="searchPattern">File search pattern (default: "*")</param>
        /// <param name="recursive">Whether to scan subdirectories (default: false)</param>
        /// <param name="maxConcurrency">Maximum number of concurrent scans (default: 4)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <param name="progressCallback">Optional callback to report progress</param>
        /// <returns>Collection of batch scan results</returns>
        public static async Task<IEnumerable<ClamBatchScanResult>> BatchScanDirectoryAsync(
            this IClamClient clamClient,
            string directoryPath,
            string searchPattern = "*",
            bool recursive = false,
            int maxConcurrency = 4,
            CancellationToken cancellationToken = default,
            IProgress<ClamBatchProgress>? progressCallback = null)
        {
            var processor = new ClamBatchProcessor(clamClient, maxConcurrency);
            return await processor.ScanDirectoryAsync(directoryPath, searchPattern, recursive, cancellationToken, progressCallback);
        }

        /// <summary>
        /// Scans files matching specific extensions using this ClamClient
        /// </summary>
        /// <param name="clamClient">The ClamClient instance</param>
        /// <param name="directoryPath">Directory to scan</param>
        /// <param name="extensions">File extensions to include (e.g., ".exe", ".pdf")</param>
        /// <param name="recursive">Whether to scan subdirectories (default: false)</param>
        /// <param name="maxConcurrency">Maximum number of concurrent scans (default: 4)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <param name="progressCallback">Optional callback to report progress</param>
        /// <returns>Collection of batch scan results</returns>
        public static async Task<IEnumerable<ClamBatchScanResult>> BatchScanByExtensionsAsync(
            this IClamClient clamClient,
            string directoryPath,
            IEnumerable<string> extensions,
            bool recursive = false,
            int maxConcurrency = 4,
            CancellationToken cancellationToken = default,
            IProgress<ClamBatchProgress>? progressCallback = null)
        {
            var processor = new ClamBatchProcessor(clamClient, maxConcurrency);
            return await processor.ScanByExtensionsAsync(directoryPath, extensions, recursive, cancellationToken, progressCallback);
        }

        /// <summary>
        /// Scans executable files in a directory using this ClamClient
        /// </summary>
        /// <param name="clamClient">The ClamClient instance</param>
        /// <param name="directoryPath">Directory to scan</param>
        /// <param name="recursive">Whether to scan subdirectories (default: false)</param>
        /// <param name="maxConcurrency">Maximum number of concurrent scans (default: 4)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <param name="progressCallback">Optional callback to report progress</param>
        /// <returns>Collection of batch scan results</returns>
        public static async Task<IEnumerable<ClamBatchScanResult>> BatchScanExecutableFilesAsync(
            this IClamClient clamClient,
            string directoryPath,
            bool recursive = false,
            int maxConcurrency = 4,
            CancellationToken cancellationToken = default,
            IProgress<ClamBatchProgress>? progressCallback = null)
        {
            return await clamClient.BatchScanByExtensionsAsync(
                directoryPath, 
                ClamBatchUtilities.CommonExtensions.Executable, 
                recursive, 
                maxConcurrency, 
                cancellationToken, 
                progressCallback);
        }

        /// <summary>
        /// Scans high-risk files in a directory using this ClamClient
        /// </summary>
        /// <param name="clamClient">The ClamClient instance</param>
        /// <param name="directoryPath">Directory to scan</param>
        /// <param name="recursive">Whether to scan subdirectories (default: false)</param>
        /// <param name="maxConcurrency">Maximum number of concurrent scans (default: 4)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <param name="progressCallback">Optional callback to report progress</param>
        /// <returns>Collection of batch scan results</returns>
        public static async Task<IEnumerable<ClamBatchScanResult>> BatchScanHighRiskFilesAsync(
            this IClamClient clamClient,
            string directoryPath,
            bool recursive = false,
            int maxConcurrency = 4,
            CancellationToken cancellationToken = default,
            IProgress<ClamBatchProgress>? progressCallback = null)
        {
            return await clamClient.BatchScanByExtensionsAsync(
                directoryPath, 
                ClamBatchUtilities.CommonExtensions.HighRisk, 
                recursive, 
                maxConcurrency, 
                cancellationToken, 
                progressCallback);
        }
    }
}