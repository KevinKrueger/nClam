using System;

namespace VirusScanner.ClamAV
{
    /// <summary>
    /// Thrown when the ClamAV server returns a response that cannot be parsed.
    /// </summary>
    public class UnknownClamResponseException : Exception
    {
        public UnknownClamResponseException(string response)
            : base($"Unable to parse the server response: {response}")
        {
        }
    }
}
