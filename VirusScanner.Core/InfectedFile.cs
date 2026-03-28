namespace VirusScanner.Core
{
    /// <summary>
    /// Represents a file detected as infected during a virus scan.
    /// </summary>
    public record InfectedFile(string FileName, string VirusName);
}
