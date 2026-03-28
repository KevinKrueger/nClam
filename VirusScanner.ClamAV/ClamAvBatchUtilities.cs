using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using VirusScanner.Core;

namespace VirusScanner.ClamAV
{
    /// <summary>
    /// Utility methods for batch scan results.
    /// </summary>
    public static class ClamAvBatchUtilities
    {
        /// <summary>
        /// Generates a detailed scan report in text format.
        /// </summary>
        public static string GenerateReport(IEnumerable<BatchScanResult> results, DateTime scanStartTime)
        {
            var resultList = results.ToList();
            var totalDuration = DateTime.Now - scanStartTime;

            var cleanCount = resultList.Count(r => r.IsClean);
            var infectedCount = resultList.Count(r => r.IsInfected);
            var errorCount = resultList.Count(r => r.HasError);

            var report = $@"
===============================================
VirusScanner.ClamAV Batch Scan Report
===============================================
Scan Date: {scanStartTime:yyyy-MM-dd HH:mm:ss}
Total Duration: {totalDuration:hh\:mm\:ss}
Total Files Scanned: {resultList.Count}

Results Summary:
  âœ… Clean Files: {cleanCount}
  ðŸ¦  Infected Files: {infectedCount}
  âŒ Errors: {errorCount}

===============================================
Detailed Results:
===============================================
";
            foreach (var result in resultList.OrderBy(r => r.FilePath))
            {
                var status = result.IsClean ? "CLEAN" : result.IsInfected ? "INFECTED" : "ERROR";
                report += $"\n[{status}] {result.FilePath}";
                report += $"\n  File Size: {result.FileSize:N0} bytes";
                report += $"\n  Scan Duration: {result.ScanDuration.TotalMilliseconds:F0}ms";

                if (result.IsInfected && result.ScanResult?.InfectedFiles?.Any() == true)
                {
                    foreach (var infection in result.ScanResult.InfectedFiles)
                        report += $"\n  ðŸ¦  Virus Detected: {infection.VirusName}";
                }
                else if (result.HasError && !string.IsNullOrEmpty(result.ErrorMessage))
                {
                    report += $"\n  âŒ Error: {result.ErrorMessage}";
                }

                report += "\n" + new string('-', 50);
            }

            return report;
        }

        /// <summary>
        /// Saves scan results to a CSV file.
        /// </summary>
        public static async Task SaveToCsvAsync(IEnumerable<BatchScanResult> results, string csvPath)
        {
            var csvLines = new List<string>
            {
                "FilePath,FileName,FileSize,ScanResult,VirusName,Success,ErrorMessage,ScanDurationMs"
            };

            foreach (var result in results)
            {
                var virusName = result.IsInfected && result.ScanResult?.InfectedFiles?.Any() == true
                    ? result.ScanResult.InfectedFiles.First().VirusName
                    : "";

                var scanResultText = result.Success
                    ? result.ScanResult?.Status.ToString() ?? "Unknown"
                    : "Error";

                csvLines.Add(
                    $"\"{EscapeCsv(result.FilePath)}\"," +
                    $"\"{EscapeCsv(result.FileName)}\"," +
                    $"{result.FileSize}," +
                    $"\"{scanResultText}\"," +
                    $"\"{EscapeCsv(virusName)}\"," +
                    $"{result.Success}," +
                    $"\"{EscapeCsv(result.ErrorMessage ?? "")}\"," +
                    $"{result.ScanDuration.TotalMilliseconds:F0}");
            }

            using var writer = new StreamWriter(csvPath);
            foreach (var line in csvLines)
                await writer.WriteLineAsync(line);
        }

        /// <summary>
        /// Returns only infected files from a result set.
        /// </summary>
        public static IEnumerable<BatchScanResult> GetInfectedFiles(IEnumerable<BatchScanResult> results)
            => results.Where(r => r.IsInfected);

        /// <summary>
        /// Returns only files that had scan errors.
        /// </summary>
        public static IEnumerable<BatchScanResult> GetErrorFiles(IEnumerable<BatchScanResult> results)
            => results.Where(r => r.HasError);

        /// <summary>
        /// Returns only clean files.
        /// </summary>
        public static IEnumerable<BatchScanResult> GetCleanFiles(IEnumerable<BatchScanResult> results)
            => results.Where(r => r.IsClean);

        /// <summary>
        /// Computes statistics from a set of scan results.
        /// </summary>
        public static ClamAvBatchStatistics GetStatistics(IEnumerable<BatchScanResult> results)
        {
            var list = results.ToList();
            return new ClamAvBatchStatistics
            {
                TotalFiles = list.Count,
                CleanFiles = list.Count(r => r.IsClean),
                InfectedFiles = list.Count(r => r.IsInfected),
                ErrorFiles = list.Count(r => r.HasError),
                TotalScanTime = TimeSpan.FromMilliseconds(list.Sum(r => r.ScanDuration.TotalMilliseconds)),
                AverageScanTime = list.Any()
                    ? TimeSpan.FromMilliseconds(list.Average(r => r.ScanDuration.TotalMilliseconds))
                    : TimeSpan.Zero,
                TotalFileSize = list.Sum(r => r.FileSize),
                LargestFile = list.OrderByDescending(r => r.FileSize).FirstOrDefault(),
                SlowestScan = list.OrderByDescending(r => r.ScanDuration).FirstOrDefault()
            };
        }

        private static string EscapeCsv(string value) => value?.Replace("\"", "\"\"") ?? "";

        /// <summary>
        /// Common file extension sets for targeted scanning.
        /// </summary>
        public static class CommonExtensions
        {
            public static readonly string[] Executable = { ".exe", ".dll", ".bat", ".cmd", ".com", ".scr", ".pif", ".msi", ".jar", ".app", ".deb", ".rpm", ".vbs", ".js", ".ps1" };
            public static readonly string[] Document = { ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".odt", ".ods", ".odp", ".txt" };
            public static readonly string[] Archive = { ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".cab", ".iso", ".dmg", ".pkg" };
            public static readonly string[] Media = { ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".svg", ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".wav" };
            public static readonly string[] HighRisk = { ".exe", ".dll", ".bat", ".cmd", ".com", ".scr", ".pif", ".vbs", ".js", ".jar", ".msi", ".ps1", ".reg" };
        }
    }

    /// <summary>
    /// Statistical summary of a batch scan.
    /// </summary>
    public class ClamAvBatchStatistics
    {
        public int TotalFiles { get; set; }
        public int CleanFiles { get; set; }
        public int InfectedFiles { get; set; }
        public int ErrorFiles { get; set; }
        public TimeSpan TotalScanTime { get; set; }
        public TimeSpan AverageScanTime { get; set; }
        public long TotalFileSize { get; set; }
        public BatchScanResult? LargestFile { get; set; }
        public BatchScanResult? SlowestScan { get; set; }
        public double InfectionRate => TotalFiles > 0 ? (double)InfectedFiles / TotalFiles * 100 : 0;
        public double ErrorRate => TotalFiles > 0 ? (double)ErrorFiles / TotalFiles * 100 : 0;
        public double SuccessRate => TotalFiles > 0 ? (double)(TotalFiles - ErrorFiles) / TotalFiles * 100 : 0;
    }
}

