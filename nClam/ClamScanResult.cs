namespace nClam
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;

    public class ClamScanResult
    {
        /// <summary>
        /// The raw string returned by the ClamAV server.
        /// </summary>
        public string RawResult { get; private set; }

        /// <summary>
        /// The parsed results of scan.
        /// </summary>
        public ClamScanResults Result { get; private set; }

        /// <summary>
        /// List of infected files with what viruses they are infected with. Null if the Result is not VirusDetected.
        /// </summary>
        public ReadOnlyCollection<ClamScanInfectedFile>? InfectedFiles { get; private set; }

        public ClamScanResult(string rawResult)
        {
            RawResult = rawResult;

            if (rawResult.EndsWith("ok", StringComparison.OrdinalIgnoreCase))
            {
                Result = ClamScanResults.Clean;
            }
            else if (rawResult.EndsWith("error", StringComparison.OrdinalIgnoreCase))
            {
                Result = ClamScanResults.Error;
            }
            else if (rawResult.EndsWith("found", StringComparison.OrdinalIgnoreCase))
            {
                Result = ClamScanResults.VirusDetected;

                var files = rawResult.Split(new[] {"FOUND"}, StringSplitOptions.RemoveEmptyEntries);
                var infectedFiles = new List<ClamScanInfectedFile>();
                foreach (var file in files)
                {
                    var trimFile = file.Trim();
                    infectedFiles.Add(new ClamScanInfectedFile(ExtractFileName(trimFile), ExtractVirusName(trimFile)));
                }

                InfectedFiles = new ReadOnlyCollection<ClamScanInfectedFile>(infectedFiles);
            }
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

        public override string ToString()
        {
            return RawResult;
        }
    }
}
