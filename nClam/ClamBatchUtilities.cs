using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace nClam
{
    /// <summary>
    /// Provides additional utilities for batch processing operations
    /// </summary>
    public static class ClamBatchUtilities
    {
        /// <summary>
        /// Generates a detailed scan report in text format
        /// </summary>
        /// <param name="results">Scan results to include in the report</param>
        /// <param name="scanStartTime">When the scan started</param>
        /// <returns>Formatted report string</returns>
        public static string GenerateReport(IEnumerable<ClamBatchScanResult> results, DateTime scanStartTime)
        {
            var resultList = results.ToList();
            var scanEndTime = DateTime.Now;
            var totalDuration = scanEndTime - scanStartTime;

            var cleanCount = resultList.Count(r => r.IsClean);
            var infectedCount = resultList.Count(r => r.IsInfected);
            var errorCount = resultList.Count(r => r.HasError);
            var totalFiles = resultList.Count;

            var report = $@"
===============================================
nClam Batch Scan Report
===============================================
Scan Date: {scanStartTime:yyyy-MM-dd HH:mm:ss}
Total Duration: {totalDuration:hh\:mm\:ss}
Total Files Scanned: {totalFiles}

Results Summary:
  ✅ Clean Files: {cleanCount}
  🦠 Infected Files: {infectedCount}
  ❌ Errors: {errorCount}

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
                    {
                        report += $"\n  🦠 Virus Detected: {infection.VirusName}";
                    }
                }
                else if (result.HasError && !string.IsNullOrEmpty(result.ErrorMessage))
                {
                    report += $"\n  ❌ Error: {result.ErrorMessage}";
                }

                report += "\n" + new string('-', 50);
            }

            return report;
        }

        /// <summary>
        /// Saves scan results to a CSV file
        /// </summary>
        /// <param name="results">Scan results to save</param>
        /// <param name="csvPath">Path to save the CSV file</param>
        public static async Task SaveToCsvAsync(IEnumerable<ClamBatchScanResult> results, string csvPath)
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
                    ? result.ScanResult?.Result.ToString() ?? "Unknown"
                    : "Error";

                var csvLine = $"\"{EscapeCsv(result.FilePath)}\"," +
                             $"\"{EscapeCsv(result.FileName)}\"," +
                             $"{result.FileSize}," +
                             $"\"{scanResultText}\"," +
                             $"\"{EscapeCsv(virusName)}\"," +
                             $"{result.Success}," +
                             $"\"{EscapeCsv(result.ErrorMessage ?? "")}\"," +
                             $"{result.ScanDuration.TotalMilliseconds:F0}";

                csvLines.Add(csvLine);
            }

            using (var writer = new StreamWriter(csvPath))
            {
                foreach (var line in csvLines)
                {
                    await writer.WriteLineAsync(line).ConfigureAwait(false);
                }
            }
        }

        /// <summary>
        /// Filters results to show only infected files
        /// </summary>
        /// <param name="results">All scan results</param>
        /// <returns>Only infected files</returns>
        public static IEnumerable<ClamBatchScanResult> GetInfectedFiles(IEnumerable<ClamBatchScanResult> results)
        {
            return results.Where(r => r.IsInfected);
        }

        /// <summary>
        /// Filters results to show only files that had scan errors
        /// </summary>
        /// <param name="results">All scan results</param>
        /// <returns>Only files with errors</returns>
        public static IEnumerable<ClamBatchScanResult> GetErrorFiles(IEnumerable<ClamBatchScanResult> results)
        {
            return results.Where(r => r.HasError);
        }

        /// <summary>
        /// Filters results to show only clean files
        /// </summary>
        /// <param name="results">All scan results</param>
        /// <returns>Only clean files</returns>
        public static IEnumerable<ClamBatchScanResult> GetCleanFiles(IEnumerable<ClamBatchScanResult> results)
        {
            return results.Where(r => r.IsClean);
        }

        /// <summary>
        /// Groups results by scan result type
        /// </summary>
        /// <param name="results">All scan results</param>
        /// <returns>Dictionary grouped by result type</returns>
        public static Dictionary<string, List<ClamBatchScanResult>> GroupByResult(IEnumerable<ClamBatchScanResult> results)
        {
            var grouped = new Dictionary<string, List<ClamBatchScanResult>>();

            foreach (var result in results)
            {
                var key = result.IsClean ? "Clean" : result.IsInfected ? "Infected" : "Error";
                
                if (!grouped.ContainsKey(key))
                    grouped[key] = new List<ClamBatchScanResult>();
                
                grouped[key].Add(result);
            }

            return grouped;
        }

        /// <summary>
        /// Gets scan statistics
        /// </summary>
        /// <param name="results">Scan results</param>
        /// <returns>Statistics object</returns>
        public static ClamBatchStatistics GetStatistics(IEnumerable<ClamBatchScanResult> results)
        {
            var resultList = results.ToList();

            return new ClamBatchStatistics
            {
                TotalFiles = resultList.Count,
                CleanFiles = resultList.Count(r => r.IsClean),
                InfectedFiles = resultList.Count(r => r.IsInfected),
                ErrorFiles = resultList.Count(r => r.HasError),
                TotalScanTime = TimeSpan.FromMilliseconds(resultList.Sum(r => r.ScanDuration.TotalMilliseconds)),
                AverageScanTime = resultList.Any() 
                    ? TimeSpan.FromMilliseconds(resultList.Average(r => r.ScanDuration.TotalMilliseconds))
                    : TimeSpan.Zero,
                TotalFileSize = resultList.Sum(r => r.FileSize),
                LargestFile = resultList.OrderByDescending(r => r.FileSize).FirstOrDefault(),
                SlowestScan = resultList.OrderByDescending(r => r.ScanDuration).FirstOrDefault()
            };
        }

        /// <summary>
        /// Analyzes batch scan results to identify connection-related issues
        /// </summary>
        /// <param name="results">Scan results to analyze</param>
        /// <returns>Connection analysis report</returns>
        public static ClamConnectionAnalysis AnalyzeConnectionIssues(IEnumerable<ClamBatchScanResult> results)
        {
            var resultList = results.ToList();

            var connectionErrors = resultList.Where(r => 
                !r.Success && IsConnectionError(r.ErrorMessage ?? "")).ToList();

            var timeoutErrors = resultList.Where(r => 
                !r.Success && (r.ErrorMessage?.ToLowerInvariant().Contains("timeout") == true)).ToList();

            var cancelledScans = resultList.Where(r => 
                !r.Success && (r.ErrorMessage?.ToLowerInvariant().Contains("cancelled") == true)).ToList();

            return new ClamConnectionAnalysis
            {
                TotalConnectionErrors = connectionErrors.Count,
                TimeoutErrors = timeoutErrors.Count,
                CancelledScans = cancelledScans.Count,
                AffectedFiles = connectionErrors.Select(r => r.FilePath).ToList(),
                SuggestedActions = GenerateConnectionSuggestions(connectionErrors, timeoutErrors)
            };
        }

        private static bool IsConnectionError(string errorMessage)
        {
            var connectionKeywords = new[] 
            {
                "connection", "socket", "network", "clamav daemon", 
                "host", "port", "unreachable", "refused"
            };

            var lowerMessage = errorMessage.ToLowerInvariant();
            return connectionKeywords.Any(keyword => lowerMessage.Contains(keyword));
        }

        private static List<string> GenerateConnectionSuggestions(
            List<ClamBatchScanResult> connectionErrors, 
            List<ClamBatchScanResult> timeoutErrors)
        {
            var suggestions = new List<string>();

            if (connectionErrors.Any())
            {
                suggestions.Add("🔌 Check if ClamAV daemon is running: docker ps | grep clam");
                suggestions.Add("🌐 Verify port accessibility: telnet localhost 3310");
                suggestions.Add("🔥 Check firewall settings and network connectivity");
            }

            if (timeoutErrors.Any())
            {
                suggestions.Add("⏱️ Increase connection timeout in ClamBatchProcessor constructor");
                suggestions.Add("🔄 Reduce concurrency to avoid overwhelming the daemon");
                suggestions.Add("💾 Check if ClamAV daemon has sufficient memory/CPU resources");
            }

            if (connectionErrors.Count > timeoutErrors.Count)
            {
                suggestions.Add("🚀 ClamAV daemon likely stopped during batch operation");
                suggestions.Add("🔄 Restart ClamAV container and retry failed files");
            }

            return suggestions;
        }

        /// <summary>
        /// Common file extensions for different categories
        /// </summary>
        public static class CommonExtensions
        {
            /// <summary>
            /// Executable file extensions that are commonly targeted by malware
            /// </summary>
            public static readonly string[] Executable = new[]
            {
                ".exe", ".dll", ".bat", ".cmd", ".com", ".scr", ".pif", 
                ".msi", ".jar", ".app", ".deb", ".rpm", ".vbs", ".js", ".ps1"
            };

            /// <summary>
            /// Document file extensions
            /// </summary>
            public static readonly string[] Document = new[]
            {
                ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", 
                ".rtf", ".odt", ".ods", ".odp", ".txt"
            };

            /// <summary>
            /// Archive file extensions
            /// </summary>
            public static readonly string[] Archive = new[]
            {
                ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".cab", 
                ".iso", ".dmg", ".pkg"
            };

            /// <summary>
            /// Media file extensions
            /// </summary>
            public static readonly string[] Media = new[]
            {
                ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".svg",
                ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".wav"
            };

            /// <summary>
            /// High-risk file extensions that should be scanned with priority
            /// </summary>
            public static readonly string[] HighRisk = new[]
            {
                ".exe", ".dll", ".bat", ".cmd", ".com", ".scr", ".pif",
                ".vbs", ".js", ".jar", ".msi", ".ps1", ".reg"
            };
        }

        private static string EscapeCsv(string value)
        {
            return value?.Replace("\"", "\"\"") ?? "";
        }
    }

    /// <summary>
    /// Contains statistical information about batch scan results
    /// </summary>
    public class ClamBatchStatistics
    {
        /// <summary>
        /// Total number of files scanned
        /// </summary>
        public int TotalFiles { get; set; }

        /// <summary>
        /// Number of clean files
        /// </summary>
        public int CleanFiles { get; set; }

        /// <summary>
        /// Number of infected files
        /// </summary>
        public int InfectedFiles { get; set; }

        /// <summary>
        /// Number of files that had scan errors
        /// </summary>
        public int ErrorFiles { get; set; }

        /// <summary>
        /// Total time spent scanning all files
        /// </summary>
        public TimeSpan TotalScanTime { get; set; }

        /// <summary>
        /// Average time per file scan
        /// </summary>
        public TimeSpan AverageScanTime { get; set; }

        /// <summary>
        /// Total size of all scanned files in bytes
        /// </summary>
        public long TotalFileSize { get; set; }

        /// <summary>
        /// Information about the largest file scanned
        /// </summary>
        public ClamBatchScanResult? LargestFile { get; set; }

        /// <summary>
        /// Information about the file that took longest to scan
        /// </summary>
        public ClamBatchScanResult? SlowestScan { get; set; }

        /// <summary>
        /// Percentage of files that were infected (0-100)
        /// </summary>
        public double InfectionRate => TotalFiles > 0 ? (double)InfectedFiles / TotalFiles * 100 : 0;

        /// <summary>
        /// Percentage of files that had scan errors (0-100)
        /// </summary>
        public double ErrorRate => TotalFiles > 0 ? (double)ErrorFiles / TotalFiles * 100 : 0;

        /// <summary>
        /// Percentage of files that were successfully scanned (0-100)
        /// </summary>
        public double SuccessRate => TotalFiles > 0 ? (double)(TotalFiles - ErrorFiles) / TotalFiles * 100 : 0;
    }

    /// <summary>
    /// Contains analysis of connection-related issues in batch scan results
    /// </summary>
    public class ClamConnectionAnalysis
    {
        /// <summary>
        /// Total number of connection-related errors
        /// </summary>
        public int TotalConnectionErrors { get; set; }

        /// <summary>
        /// Number of timeout-related errors
        /// </summary>
        public int TimeoutErrors { get; set; }

        /// <summary>
        /// Number of cancelled scan operations
        /// </summary>
        public int CancelledScans { get; set; }

        /// <summary>
        /// List of file paths that were affected by connection issues
        /// </summary>
        public List<string> AffectedFiles { get; set; } = new List<string>();

        /// <summary>
        /// Suggested actions to resolve connection issues
        /// </summary>
        public List<string> SuggestedActions { get; set; } = new List<string>();

        /// <summary>
        /// True if connection issues were detected
        /// </summary>
        public bool HasConnectionIssues => TotalConnectionErrors > 0 || TimeoutErrors > 0;
    }
}