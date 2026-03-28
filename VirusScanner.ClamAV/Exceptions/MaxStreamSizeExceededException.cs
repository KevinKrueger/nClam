using System;

namespace VirusScanner.ClamAV
{
    /// <summary>
    /// Signifies that the maximum stream size for the INSTREAM command has been exceeded.
    /// </summary>
    [Serializable]
    public class MaxStreamSizeExceededException : Exception
    {
        public MaxStreamSizeExceededException(long maxStreamSize)
            : base($"The maximum stream size of {maxStreamSize} bytes has been exceeded.")
        {
        }
    }
}
