namespace VirusScanner.Core
{
    /// <summary>
    /// Represents progress information for a batch scan operation.
    /// </summary>
    public class BatchProgress
    {
        /// <summary>
        /// Total number of files to scan.
        /// </summary>
        public int TotalFiles { get; set; }

        /// <summary>
        /// Number of files completed so far.
        /// </summary>
        public int CompletedFiles { get; set; }

        /// <summary>
        /// Path of the file currently being scanned.
        /// </summary>
        public string? CurrentFile { get; set; }

        /// <summary>
        /// Percentage of completion (0–100).
        /// </summary>
        public double PercentageComplete => TotalFiles > 0 ? (double)CompletedFiles / TotalFiles * 100 : 0;
    }
}
