using System;

namespace VirusScanner.Core
{
    /// <summary>
    /// Represents the scan result for a single file in a batch operation.
    /// </summary>
    public class BatchScanResult
    {
        /// <summary>
        /// Full path to the scanned file.
        /// </summary>
        public string FilePath { get; set; } = string.Empty;

        /// <summary>
        /// File name without path.
        /// </summary>
        public string FileName { get; set; } = string.Empty;

        /// <summary>
        /// File size in bytes.
        /// </summary>
        public long FileSize { get; set; }

        /// <summary>
        /// The scan result, or null if the scan failed.
        /// </summary>
        public ScanResult? ScanResult { get; set; }

        /// <summary>
        /// Whether the scan completed without errors.
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Error message if the scan failed, otherwise null.
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// Time taken to scan this file.
        /// </summary>
        public TimeSpan ScanDuration { get; set; }

        /// <summary>
        /// True if the file was scanned successfully and is clean.
        /// </summary>
        public bool IsClean => Success && ScanResult?.IsClean == true;

        /// <summary>
        /// True if the file was scanned successfully and a virus was found.
        /// </summary>
        public bool IsInfected => Success && ScanResult?.IsInfected == true;

        /// <summary>
        /// True if there was an error scanning the file.
        /// </summary>
        public bool HasError => !Success || ScanResult?.HasError == true;
    }
}
