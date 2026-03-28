using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using VirusScanner.Core;

namespace VirusScanner.ClamAV
{
    /// <summary>
    /// Represents the result of a ClamAV scan, including the raw server response.
    /// </summary>
    public class ClamAvScanResult : ScanResult
    {
        /// <summary>
        /// The raw string returned by the ClamAV server.
        /// </summary>
        public string RawResult { get; }

        public ClamAvScanResult(string rawResult)
            : base(ParseStatus(rawResult), ParseInfectedFiles(rawResult))
        {
            RawResult = rawResult;
        }

        private static ScanStatus ParseStatus(string rawResult)
        {
            if (rawResult.EndsWith("ok", StringComparison.OrdinalIgnoreCase))
                return ScanStatus.Clean;
            if (rawResult.EndsWith("error", StringComparison.OrdinalIgnoreCase))
                return ScanStatus.Error;
            if (rawResult.EndsWith("found", StringComparison.OrdinalIgnoreCase))
                return ScanStatus.VirusDetected;
            return ScanStatus.Unknown;
        }

        private static IReadOnlyList<InfectedFile>? ParseInfectedFiles(string rawResult)
        {
            if (!rawResult.EndsWith("found", StringComparison.OrdinalIgnoreCase))
                return null;

            var files = rawResult.Split(new[] { "FOUND" }, StringSplitOptions.RemoveEmptyEntries);
            var infectedFiles = new List<InfectedFile>();
            foreach (var file in files)
            {
                var trimFile = file.Trim();
                infectedFiles.Add(new InfectedFile(ExtractFileName(trimFile), ExtractVirusName(trimFile)));
            }

            return new ReadOnlyCollection<InfectedFile>(infectedFiles);
        }

        internal static string ExtractFileName(string s)
        {
            int l = s.LastIndexOf(':');
            return l > 0 ? s.Substring(0, l) : "";
        }

        internal static string ExtractVirusName(string s)
        {
            int l = s.LastIndexOf(' ');
            return l > 0 ? s.Substring(l) : "";
        }

        public override string ToString() => RawResult;
    }
}

