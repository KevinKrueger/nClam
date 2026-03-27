using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace nClam
{
    /// <summary>
    /// Provides batch processing capabilities for scanning multiple files with nClam
    /// </summary>
    public class ClamBatchProcessor
    {
        private readonly IClamClient _clamClient;
        private readonly int _maxConcurrency;
        private readonly TimeSpan _connectionTimeout;
        private volatile bool _clamAvailable = true;
        private DateTime _lastConnectionCheck = DateTime.MinValue;
        private readonly TimeSpan _connectionCheckInterval = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Initializes a new instance of the ClamBatchProcessor
        /// </summary>
        /// <param name="clamClient">The ClamClient instance to use for scanning</param>
        /// <param name="maxConcurrency">Maximum number of concurrent scans (default: 4)</param>
        /// <param name="connectionTimeoutSeconds">Connection timeout in seconds (default: 10)</param>
        public ClamBatchProcessor(IClamClient clamClient, int maxConcurrency = 4, int connectionTimeoutSeconds = 10)
        {
            _clamClient = clamClient ?? throw new ArgumentNullException(nameof(clamClient));
            _maxConcurrency = maxConcurrency > 0 ? maxConcurrency : 4;
            _connectionTimeout = TimeSpan.FromSeconds(connectionTimeoutSeconds);
        }

        /// <summary>
        /// Scans multiple files concurrently
        /// </summary>
        /// <param name="filePaths">Collection of file paths to scan</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <param name="progressCallback">Optional callback to report progress</param>
        /// <returns>Collection of batch scan results</returns>
        public async Task<IEnumerable<ClamBatchScanResult>> ScanFilesAsync(
            IEnumerable<string> filePaths,
            CancellationToken cancellationToken = default,
            IProgress<ClamBatchProgress>? progressCallback = null)
        {
            if (filePaths == null)
                throw new ArgumentNullException(nameof(filePaths));

            var fileList = filePaths.ToList();
            var results = new ConcurrentBag<ClamBatchScanResult>();
            var completedCount = 0;
            var totalCount = fileList.Count;

            progressCallback?.Report(new ClamBatchProgress
            {
                TotalFiles = totalCount,
                CompletedFiles = 0,
                CurrentFile = null
            });

            // Initial connection check
            if (!await CheckClamAvailabilityAsync(cancellationToken))
            {
                // If ClamAV is not available, return error results for all files
                return fileList.Select(filePath => new ClamBatchScanResult
                {
                    FilePath = filePath,
                    FileName = Path.GetFileName(filePath),
                    ScanResult = null,
                    Success = false,
                    ErrorMessage = "ClamAV daemon is not available",
                    ScanDuration = TimeSpan.Zero
                });
            }

            using var semaphore = new SemaphoreSlim(_maxConcurrency, _maxConcurrency);
            var tasks = fileList.Select(async filePath =>
            {
                await semaphore.WaitAsync(cancellationToken);
                try
                {
                    var scanResult = await ScanSingleFileAsync(filePath, cancellationToken);
                    results.Add(scanResult);

                    var completed = Interlocked.Increment(ref completedCount);
                    progressCallback?.Report(new ClamBatchProgress
                    {
                        TotalFiles = totalCount,
                        CompletedFiles = completed,
                        CurrentFile = filePath
                    });
                }
                finally
                {
                    semaphore.Release();
                }
            });

            await Task.WhenAll(tasks);
            return results.OrderBy(r => r.FilePath);
        }

        /// <summary>
        /// Scans all files in a directory (optionally recursive)
        /// </summary>
        /// <param name="directoryPath">Directory to scan</param>
        /// <param name="searchPattern">File search pattern (default: "*")</param>
        /// <param name="recursive">Whether to scan subdirectories (default: false)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <param name="progressCallback">Optional callback to report progress</param>
        /// <returns>Collection of batch scan results</returns>
        public async Task<IEnumerable<ClamBatchScanResult>> ScanDirectoryAsync(
            string directoryPath,
            string searchPattern = "*",
            bool recursive = false,
            CancellationToken cancellationToken = default,
            IProgress<ClamBatchProgress>? progressCallback = null)
        {
            if (string.IsNullOrEmpty(directoryPath))
                throw new ArgumentException("Directory path cannot be null or empty", nameof(directoryPath));

            if (!Directory.Exists(directoryPath))
                throw new DirectoryNotFoundException($"Directory not found: {directoryPath}");

            var searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            var files = Directory.GetFiles(directoryPath, searchPattern, searchOption);

            return await ScanFilesAsync(files, cancellationToken, progressCallback);
        }

        /// <summary>
        /// Scans files matching specific extensions
        /// </summary>
        /// <param name="directoryPath">Directory to scan</param>
        /// <param name="extensions">File extensions to include (e.g., ".exe", ".pdf")</param>
        /// <param name="recursive">Whether to scan subdirectories</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <param name="progressCallback">Optional callback to report progress</param>
        /// <returns>Collection of batch scan results</returns>
        public async Task<IEnumerable<ClamBatchScanResult>> ScanByExtensionsAsync(
            string directoryPath,
            IEnumerable<string> extensions,
            bool recursive = false,
            CancellationToken cancellationToken = default,
            IProgress<ClamBatchProgress>? progressCallback = null)
        {
            if (extensions == null)
                throw new ArgumentNullException(nameof(extensions));

            var extensionSet = new HashSet<string>(extensions.Select(ext => ext.ToLowerInvariant()), StringComparer.OrdinalIgnoreCase);
            var searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
            
            var files = Directory.GetFiles(directoryPath, "*", searchOption)
                .Where(file => extensionSet.Contains(Path.GetExtension(file).ToLowerInvariant()));

            return await ScanFilesAsync(files, cancellationToken, progressCallback);
        }

        private async Task<ClamBatchScanResult> ScanSingleFileAsync(string filePath, CancellationToken cancellationToken)
        {
            var startTime = DateTime.UtcNow;

            try
            {
                if (!File.Exists(filePath))
                {
                    return new ClamBatchScanResult
                    {
                        FilePath = filePath,
                        ScanResult = null,
                        Success = false,
                        ErrorMessage = "File not found",
                        ScanDuration = TimeSpan.Zero
                    };
                }

                // Check if ClamAV is available before attempting scan
                if (!_clamAvailable && ShouldCheckConnection())
                {
                    if (!await CheckClamAvailabilityAsync(cancellationToken))
                    {
                        return new ClamBatchScanResult
                        {
                            FilePath = filePath,
                            FileName = Path.GetFileName(filePath),
                            ScanResult = null,
                            Success = false,
                            ErrorMessage = "ClamAV daemon is not available",
                            ScanDuration = DateTime.UtcNow - startTime
                        };
                    }
                }

                var fileInfo = new FileInfo(filePath);
                byte[] fileData;
                using (var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                using (var memoryStream = new MemoryStream())
                {
                    await fileStream.CopyToAsync(memoryStream, 81920, cancellationToken).ConfigureAwait(false);
                    fileData = memoryStream.ToArray();
                }

                // Use timeout for scan operation
                using var timeoutCts = new CancellationTokenSource(_connectionTimeout);
                using var combinedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

                var scanResult = await _clamClient.SendAndScanFileAsync(fileData, combinedCts.Token);

                return new ClamBatchScanResult
                {
                    FilePath = filePath,
                    FileName = fileInfo.Name,
                    FileSize = fileInfo.Length,
                    ScanResult = scanResult,
                    Success = true,
                    ErrorMessage = null,
                    ScanDuration = DateTime.UtcNow - startTime
                };
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return new ClamBatchScanResult
                {
                    FilePath = filePath,
                    FileName = Path.GetFileName(filePath),
                    ScanResult = null,
                    Success = false,
                    ErrorMessage = "Operation was cancelled",
                    ScanDuration = DateTime.UtcNow - startTime
                };
            }
            catch (System.Net.Sockets.SocketException ex)
            {
                _clamAvailable = false; // Mark as unavailable
                return new ClamBatchScanResult
                {
                    FilePath = filePath,
                    FileName = Path.GetFileName(filePath),
                    ScanResult = null,
                    Success = false,
                    ErrorMessage = $"Connection to ClamAV failed: {ex.Message}",
                    ScanDuration = DateTime.UtcNow - startTime
                };
            }
            catch (TimeoutException ex)
            {
                return new ClamBatchScanResult
                {
                    FilePath = filePath,
                    FileName = Path.GetFileName(filePath),
                    ScanResult = null,
                    Success = false,
                    ErrorMessage = $"Scan timeout: {ex.Message}",
                    ScanDuration = DateTime.UtcNow - startTime
                };
            }
            catch (Exception ex)
            {
                // Check if it's a connection-related error
                if (IsConnectionError(ex))
                {
                    _clamAvailable = false;
                }

                return new ClamBatchScanResult
                {
                    FilePath = filePath,
                    FileName = Path.GetFileName(filePath),
                    ScanResult = null,
                    Success = false,
                    ErrorMessage = ex.Message,
                    ScanDuration = DateTime.UtcNow - startTime
                };
            }
        }

        private async Task<bool> CheckClamAvailabilityAsync(CancellationToken cancellationToken)
        {
            try
            {
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                using var combinedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

                var isAvailable = await _clamClient.TryPingAsync(combinedCts.Token);
                _clamAvailable = isAvailable;
                _lastConnectionCheck = DateTime.UtcNow;
                return isAvailable;
            }
            catch
            {
                _clamAvailable = false;
                _lastConnectionCheck = DateTime.UtcNow;
                return false;
            }
        }

        private bool ShouldCheckConnection()
        {
            return DateTime.UtcNow - _lastConnectionCheck > _connectionCheckInterval;
        }

        private static bool IsConnectionError(Exception ex)
        {
            return ex is System.Net.Sockets.SocketException ||
                   ex is System.IO.IOException ||
                   ex is TimeoutException ||
                   (ex.InnerException != null && IsConnectionError(ex.InnerException));
        }
    }

    /// <summary>
    /// Represents the result of a single file scan in a batch operation
    /// </summary>
    public class ClamBatchScanResult
    {
        /// <summary>
        /// Full path to the scanned file
        /// </summary>
        public string FilePath { get; set; } = string.Empty;

        /// <summary>
        /// File name without path
        /// </summary>
        public string FileName { get; set; } = string.Empty;

        /// <summary>
        /// File size in bytes
        /// </summary>
        public long FileSize { get; set; }

        /// <summary>
        /// Scan result from ClamAV, null if scan failed
        /// </summary>
        public ClamScanResult? ScanResult { get; set; }

        /// <summary>
        /// Whether the scan was successful (no errors occurred)
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Error message if scan failed, null if successful
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// Time taken to scan this file
        /// </summary>
        public TimeSpan ScanDuration { get; set; }

        /// <summary>
        /// True if the file was successfully scanned and is clean
        /// </summary>
        public bool IsClean => Success && ScanResult?.Result == ClamScanResults.Clean;

        /// <summary>
        /// True if the file was successfully scanned and contains a virus
        /// </summary>
        public bool IsInfected => Success && ScanResult?.Result == ClamScanResults.VirusDetected;

        /// <summary>
        /// True if there was an error scanning the file or ClamAV reported an error
        /// </summary>
        public bool HasError => !Success || ScanResult?.Result == ClamScanResults.Error;
    }

    /// <summary>
    /// Represents progress information for batch scanning operations
    /// </summary>
    public class ClamBatchProgress
    {
        /// <summary>
        /// Total number of files to scan
        /// </summary>
        public int TotalFiles { get; set; }

        /// <summary>
        /// Number of files completed
        /// </summary>
        public int CompletedFiles { get; set; }

        /// <summary>
        /// Currently scanning file path
        /// </summary>
        public string? CurrentFile { get; set; }

        /// <summary>
        /// Percentage of completion (0-100)
        /// </summary>
        public double PercentageComplete => TotalFiles > 0 ? (double)CompletedFiles / TotalFiles * 100 : 0;
    }
}