using System.Collections.Generic;

namespace VirusScanner.Core
{
    /// <summary>
    /// Represents the result of a virus scan operation.
    /// </summary>
    public class ScanResult
    {
        /// <summary>
        /// The status of the scan.
        /// </summary>
        public ScanStatus Status { get; }

        /// <summary>
        /// List of infected files. Null if <see cref="Status"/> is not <see cref="ScanStatus.VirusDetected"/>.
        /// </summary>
        public IReadOnlyList<InfectedFile>? InfectedFiles { get; }

        /// <summary>
        /// True if the scan completed successfully with no viruses found.
        /// </summary>
        public bool IsClean => Status == ScanStatus.Clean;

        /// <summary>
        /// True if the scan found one or more viruses.
        /// </summary>
        public bool IsInfected => Status == ScanStatus.VirusDetected;

        /// <summary>
        /// True if the scan encountered an error.
        /// </summary>
        public bool HasError => Status == ScanStatus.Error;

        public ScanResult(ScanStatus status, IReadOnlyList<InfectedFile>? infectedFiles = null)
        {
            Status = status;
            InfectedFiles = infectedFiles;
        }
    }
}

