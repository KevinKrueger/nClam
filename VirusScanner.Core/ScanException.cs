using System;

namespace VirusScanner.Core
{
    /// <summary>
    /// Base exception for virus scanner errors.
    /// </summary>
    public class ScanException : Exception
    {
        public ScanException(string message) : base(message) { }

        public ScanException(string message, Exception innerException) : base(message, innerException) { }
    }
}
