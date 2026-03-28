using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using VirusScanner.Core;

namespace VirusScanner.ClamAV
{
    /// <summary>
    /// Provides batch processing capabilities for scanning multiple files with ClamAV.
    /// </summary>
    public class ClamAvBatchProcessor : IBatchProcessor
    {
        private readonly IVirusScanner _scanner;
        private readonly IClamAvScanner? _clamAvScanner;
        private readonly int _maxConcurrency;
        private readonly TimeSpan _connectionTimeout;
        private volatile bool _scannerAvailable = true;
        private DateTime _lastConnectionCheck = DateTime.MinValue;
        private readonly TimeSpan _connectionCheckInterval = TimeSpan.FromSeconds(30);

        /// <summary>
        /// Gets or sets the maximum stream size in bytes sent to ClamAV per file.
        /// Maps directly to <see cref="IClamAvScanner.MaxStreamSize"/>.
        /// Must match or be lower than <c>StreamMaxLength</c> in clamd.conf (default 25 MB, max 4 GB).
        /// </summary>
        public long MaxStreamSize
        {
            get => _clamAvScanner?.MaxStreamSize ?? long.MaxValue;
            set
            {
                if (_clamAvScanner != null)
                    _clamAvScanner.MaxStreamSize = value;
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ClamAvBatchProcessor"/>.
        /// </summary>
        /// <param name="scanner">The <see cref="IVirusScanner"/> instance to use for scanning.</param>
        /// <param name="maxConcurrency">Maximum number of concurrent scans (default: 4).</param>
        /// <param name="connectionTimeoutSeconds">Connection timeout in seconds (default: 10).</param>
        public ClamAvBatchProcessor(IVirusScanner scanner, int maxConcurrency = 4, int connectionTimeoutSeconds = 10)
        {
            _scanner = scanner ?? throw new ArgumentNullException(nameof(scanner));
            _clamAvScanner = scanner as IClamAvScanner;
            _maxConcurrency = maxConcurrency > 0 ? maxConcurrency : 4;
            _connectionTimeout = TimeSpan.FromSeconds(connectionTimeoutSeconds);
        }

        /// <inheritdoc/>
        public async Task<IEnumerable<BatchScanResult>> ScanFilesAsync(
            IEnumerable<string> filePaths,
            CancellationToken cancellationToken = default,
            IProgress<BatchProgress>? progressCallback = null)
        {
            if (filePaths == null)
                throw new ArgumentNullException(nameof(filePaths));

            var fileList = filePaths.ToList();
            var results = new ConcurrentBag<BatchScanResult>();
            var completedCount = 0;
            var totalCount = fileList.Count;

            progressCallback?.Report(new BatchProgress
            {
                TotalFiles = totalCount,
                CompletedFiles = 0,
                CurrentFile = null
            });

            if (!await CheckScannerAvailabilityAsync(cancellationToken))
            {
                return fileList.Select(filePath => new BatchScanResult
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
                    progressCallback?.Report(new BatchProgress
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

        /// <inheritdoc/>
        public async Task<IEnumerable<BatchScanResult>> ScanDirectoryAsync(
            string directoryPath,
            string searchPattern = "*",
            bool recursive = false,
            CancellationToken cancellationToken = default,
            IProgress<BatchProgress>? progressCallback = null)
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
        /// Scans files matching specific extensions.
        /// </summary>
        public async Task<IEnumerable<BatchScanResult>> ScanByExtensionsAsync(
            string directoryPath,
            IEnumerable<string> extensions,
            bool recursive = false,
            CancellationToken cancellationToken = default,
            IProgress<BatchProgress>? progressCallback = null)
        {
            if (extensions == null)
                throw new ArgumentNullException(nameof(extensions));

            var extensionSet = new HashSet<string>(extensions.Select(ext => ext.ToLowerInvariant()), StringComparer.OrdinalIgnoreCase);
            var searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;

            var files = Directory.GetFiles(directoryPath, "*", searchOption)
                .Where(file => extensionSet.Contains(Path.GetExtension(file).ToLowerInvariant()));

            return await ScanFilesAsync(files, cancellationToken, progressCallback);
        }

        private async Task<BatchScanResult> ScanSingleFileAsync(string filePath, CancellationToken cancellationToken)
        {
            var startTime = DateTime.UtcNow;

            try
            {
                if (!File.Exists(filePath))
                {
                    return new BatchScanResult
                    {
                        FilePath = filePath,
                        ScanResult = null,
                        Success = false,
                        ErrorMessage = "File not found",
                        ScanDuration = TimeSpan.Zero
                    };
                }

                if (!_scannerAvailable && ShouldCheckConnection())
                {
                    if (!await CheckScannerAvailabilityAsync(cancellationToken))
                    {
                        return new BatchScanResult
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

                // Check file size against MaxStreamSize before opening the stream.
                // Raise this limit via MaxStreamSize (client) AND StreamMaxLength (clamd.conf).
                if (_clamAvScanner != null && fileInfo.Length > _clamAvScanner.MaxStreamSize)
                {
                    return new BatchScanResult
                    {
                        FilePath = filePath,
                        FileName = fileInfo.Name,
                        FileSize = fileInfo.Length,
                        ScanResult = null,
                        Success = false,
                        ErrorMessage = $"File size ({fileInfo.Length:N0} bytes) exceeds MaxStreamSize " +
                                       $"({_clamAvScanner.MaxStreamSize:N0} bytes). " +
                                       $"Increase MaxStreamSize on the scanner and StreamMaxLength in clamd.conf (max 4 GB).",
                        ScanDuration = DateTime.UtcNow - startTime
                    };
                }

                using var timeoutCts = new CancellationTokenSource(_connectionTimeout);
                using var combinedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

                // Stream directly to ClamAV â€” avoids loading the full file into RAM first.
                ScanResult scanResult;
                using (var fileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true))
                {
                    scanResult = await _scanner.ScanAsync(fileStream, combinedCts.Token);
                }

                return new BatchScanResult
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
            catch (MaxStreamSizeExceededException ex)
            {
                return new BatchScanResult
                {
                    FilePath = filePath,
                    FileName = Path.GetFileName(filePath),
                    FileSize = new FileInfo(filePath).Length,
                    ScanResult = null,
                    Success = false,
                    ErrorMessage = $"File too large for ClamAV stream: {ex.Message}",
                    ScanDuration = DateTime.UtcNow - startTime
                };
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return new BatchScanResult
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
                _scannerAvailable = false;
                return new BatchScanResult
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
                return new BatchScanResult
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
                if (IsConnectionError(ex))
                    _scannerAvailable = false;

                return new BatchScanResult
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

        private async Task<bool> CheckScannerAvailabilityAsync(CancellationToken cancellationToken)
        {
            try
            {
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                using var combinedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

                var isAvailable = await _scanner.IsAvailableAsync(combinedCts.Token);
                _scannerAvailable = isAvailable;
                _lastConnectionCheck = DateTime.UtcNow;
                return isAvailable;
            }
            catch
            {
                _scannerAvailable = false;
                _lastConnectionCheck = DateTime.UtcNow;
                return false;
            }
        }

        private bool ShouldCheckConnection()
            => DateTime.UtcNow - _lastConnectionCheck > _connectionCheckInterval;

        private static bool IsConnectionError(Exception ex)
            => ex is System.Net.Sockets.SocketException ||
               ex is System.IO.IOException ||
               ex is TimeoutException ||
               (ex.InnerException != null && IsConnectionError(ex.InnerException));
    }
}

