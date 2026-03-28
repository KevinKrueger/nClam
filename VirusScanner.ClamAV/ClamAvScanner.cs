using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VirusScanner.Core;

namespace VirusScanner.ClamAV
{
    /// <summary>
    /// Connects to a ClamAV server and performs virus scanning.
    /// </summary>
    public class ClamAvScanner : IClamAvScanner
    {
        /// <summary>
        /// Maximum chunk size in bytes when streaming data to ClamAV. Default is 128 KB.
        /// </summary>
        public int MaxChunkSize { get; set; }

        /// <summary>
        /// Maximum stream size in bytes before ClamAV terminates the connection. Default is 25 MB.
        /// </summary>
        public long MaxStreamSize { get; set; }

        /// <summary>
        /// Hostname of the ClamAV server.
        /// </summary>
        public string? Server { get; set; }

        /// <summary>
        /// IP address of the ClamAV server.
        /// </summary>
        public IPAddress? ServerIP { get; set; }

        /// <summary>
        /// Port the ClamAV server is listening on.
        /// </summary>
        public int Port { get; set; }

        private ClamAvScanner()
        {
            MaxChunkSize = 131072; // 128 KB
            MaxStreamSize = 26214400; // 25 MB
        }

        /// <summary>
        /// Initializes a new instance using a hostname.
        /// </summary>
        /// <param name="server">Hostname of the ClamAV server.</param>
        /// <param name="port">Port the ClamAV server is listening on.</param>
        /// <param name="maxStreamSize">Maximum stream size in bytes. If null, uses the default of 25 MB.</param>
        public ClamAvScanner(string server, int port = 3310, long? maxStreamSize = null) : this()
        {
            Server = server;
            Port = port;

            if (maxStreamSize.HasValue)
                MaxStreamSize = maxStreamSize.Value;
        }

        /// <summary>
        /// Initializes a new instance using an IP address.
        /// </summary>
        /// <param name="serverIP">IP address of the ClamAV server.</param>
        /// <param name="port">Port the ClamAV server is listening on.</param>
        /// <param name="maxStreamSize">Maximum stream size in bytes. If null, uses the default of 25 MB.</param>
        public ClamAvScanner(IPAddress serverIP, int port = 3310, long? maxStreamSize = null) : this()
        {
            ServerIP = serverIP;
            Port = port;

            if (maxStreamSize.HasValue)
                MaxStreamSize = maxStreamSize.Value;
        }

        private async Task<string> ExecuteClamCommandAsync(string command, CancellationToken cancellationToken, Func<Stream, CancellationToken, Task>? additionalCommand = null)
        {
#if DEBUG
            var stopWatch = System.Diagnostics.Stopwatch.StartNew();
#endif
            string result;

            using var clam = new TcpClient(AddressFamily.InterNetwork);
            using var stream = await CreateConnection(clam).ConfigureAwait(false);

            var commandText = $"z{command}\0";
            var commandBytes = Encoding.UTF8.GetBytes(commandText);
            await stream.WriteAsync(commandBytes, 0, commandBytes.Length, cancellationToken).ConfigureAwait(false);

            if (additionalCommand != null)
                await additionalCommand(stream, cancellationToken).ConfigureAwait(false);

            using var reader = new StreamReader(stream);
            result = await reader.ReadToEndAsync().ConfigureAwait(false);

            if (!string.IsNullOrEmpty(result))
                result = result.TrimEnd('\0');

#if DEBUG
            stopWatch.Stop();
            System.Diagnostics.Debug.WriteLine("Command {0} took: {1}", command, stopWatch.Elapsed);
#endif
            return result;
        }

        private async Task SendStreamFileChunksAsync(Stream sourceData, Stream clamStream, CancellationToken cancellationToken)
        {
            var streamSize = 0;
            int readByteCount;
            var bytes = new byte[MaxChunkSize];

            while ((readByteCount = await sourceData.ReadAsync(bytes, 0, MaxChunkSize, cancellationToken).ConfigureAwait(false)) > 0)
            {
                streamSize += readByteCount;

                if (streamSize > MaxStreamSize)
                    throw new MaxStreamSizeExceededException(MaxStreamSize);

                var readBytes = BitConverter.GetBytes(IPAddress.HostToNetworkOrder(readByteCount));
                await clamStream.WriteAsync(readBytes, 0, readBytes.Length, cancellationToken).ConfigureAwait(false);
                await clamStream.WriteAsync(bytes, 0, readByteCount, cancellationToken).ConfigureAwait(false);
            }

            var newMessage = BitConverter.GetBytes(0);
            await clamStream.WriteAsync(newMessage, 0, newMessage.Length, cancellationToken).ConfigureAwait(false);
        }

#if NETSTANDARD2_1_OR_GREATER
        private async Task SendStreamFileChunksAsync(ReadOnlyMemory<byte> sourceData, Stream clamStream, CancellationToken cancellationToken)
        {
            var readByteCount = 0;

            if (sourceData.Length > MaxStreamSize)
                throw new MaxStreamSizeExceededException(MaxStreamSize);

            while (readByteCount < sourceData.Length)
            {
                var toRead = (sourceData.Length - readByteCount) > MaxChunkSize ? MaxChunkSize : sourceData.Length - readByteCount;
                var readBytes = BitConverter.GetBytes((uint)System.Net.IPAddress.HostToNetworkOrder(toRead));

                await clamStream.WriteAsync(readBytes, 0, readBytes.Length, cancellationToken).ConfigureAwait(false);
                await clamStream.WriteAsync(sourceData.Slice(readByteCount, toRead), cancellationToken).ConfigureAwait(false);

                readByteCount += toRead;
            }

            await clamStream.WriteAsync(BitConverter.GetBytes(0));
        }
#endif

        protected async virtual Task<Stream> CreateConnection(TcpClient clam)
        {
            await (ServerIP == null ? clam.ConnectAsync(Server!, Port) : clam.ConnectAsync(ServerIP, Port));
            return clam.GetStream();
        }

        // ── IVirusScanner ────────────────────────────────────────────────────

        /// <inheritdoc/>
        public Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
            => TryPingAsync(cancellationToken);

        /// <inheritdoc/>
        public async Task<ScanResult> ScanAsync(byte[] data, CancellationToken cancellationToken = default)
        {
            using var sourceStream = new MemoryStream(data);
            return new ClamAvScanResult(await ExecuteClamCommandAsync("INSTREAM", cancellationToken, (stream, token) => SendStreamFileChunksAsync(sourceStream, stream, token)).ConfigureAwait(false));
        }

        /// <inheritdoc/>
        public async Task<ScanResult> ScanAsync(Stream data, CancellationToken cancellationToken = default)
        {
            return new ClamAvScanResult(await ExecuteClamCommandAsync("INSTREAM", cancellationToken, (stream, token) => SendStreamFileChunksAsync(data, stream, token)).ConfigureAwait(false));
        }

        /// <inheritdoc/>
        public async Task<ScanResult> ScanAsync(string filePath, CancellationToken cancellationToken = default)
        {
            using var stream = File.OpenRead(filePath);
            return await ScanAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        // ── IClamAvScanner ───────────────────────────────────────────────────

        /// <inheritdoc/>
        public Task<string> GetVersionAsync(CancellationToken cancellationToken = default)
            => ExecuteClamCommandAsync("VERSION", cancellationToken);

        /// <inheritdoc/>
        public Task<string> GetStatsAsync(CancellationToken cancellationToken = default)
            => ExecuteClamCommandAsync("STATS", cancellationToken);

        /// <inheritdoc/>
        public async Task<bool> PingAsync(CancellationToken cancellationToken = default)
        {
            var result = await ExecuteClamCommandAsync("PING", cancellationToken).ConfigureAwait(false);
            return string.Equals(result, "PONG", StringComparison.OrdinalIgnoreCase);
        }

        /// <inheritdoc/>
        public async Task<bool> TryPingAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                var result = await ExecuteClamCommandAsync("PING", cancellationToken).ConfigureAwait(false);
                return string.Equals(result, "PONG", StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        /// <inheritdoc/>
        public async Task<ClamAvScanResult> ScanFileOnServerAsync(string filePath, CancellationToken cancellationToken = default)
            => new ClamAvScanResult(await ExecuteClamCommandAsync($"SCAN {filePath}", cancellationToken).ConfigureAwait(false));

        /// <inheritdoc/>
        public async Task<ClamAvScanResult> ScanFileOnServerMultithreadedAsync(string filePath, CancellationToken cancellationToken = default)
            => new ClamAvScanResult(await ExecuteClamCommandAsync($"MULTISCAN {filePath}", cancellationToken).ConfigureAwait(false));

        /// <inheritdoc/>
        public async Task<ClamAvScanResult> ContScanFileOnServerAsync(string filePath, CancellationToken cancellationToken = default)
            => new ClamAvScanResult(await ExecuteClamCommandAsync($"CONTSCAN {filePath}", cancellationToken).ConfigureAwait(false));

        /// <inheritdoc/>
        public async Task<ClamAvScanResult> AllMatchScanFileOnServerAsync(string filePath, CancellationToken cancellationToken = default)
            => new ClamAvScanResult(await ExecuteClamCommandAsync($"ALLMATCHSCAN {filePath}", cancellationToken).ConfigureAwait(false));

        // SendAndScanFileAsync overloads kept for convenience on concrete type

        public async Task<ClamAvScanResult> SendAndScanFileAsync(byte[] fileData, CancellationToken cancellationToken = default)
        {
            using var sourceStream = new MemoryStream(fileData);
            return await SendAndScanFileAsync(sourceStream, cancellationToken).ConfigureAwait(false);
        }

        public async Task<ClamAvScanResult> SendAndScanFileAsync(Stream sourceStream, CancellationToken cancellationToken = default)
            => new ClamAvScanResult(await ExecuteClamCommandAsync("INSTREAM", cancellationToken, (stream, token) => SendStreamFileChunksAsync(sourceStream, stream, token)).ConfigureAwait(false));

        public async Task<ClamAvScanResult> SendAndScanFileAsync(string filePath, CancellationToken cancellationToken = default)
        {
            using var stream = File.OpenRead(filePath);
            return await SendAndScanFileAsync(stream, cancellationToken).ConfigureAwait(false);
        }

#if NETSTANDARD2_1_OR_GREATER
        public async Task<ClamAvScanResult> SendAndScanFileAsync(ReadOnlyMemory<byte> fileData, CancellationToken cancellationToken = default)
            => new ClamAvScanResult(await ExecuteClamCommandAsync("INSTREAM", cancellationToken, (stream, token) => SendStreamFileChunksAsync(fileData, stream, token)).ConfigureAwait(false));
#endif

        /// <inheritdoc/>
        public async Task Shutdown(CancellationToken cancellationToken)
            => await ExecuteClamCommandAsync("SHUTDOWN", cancellationToken).ConfigureAwait(false);

        /// <inheritdoc/>
        public async Task ReloadVirusDatabaseAsync(CancellationToken cancellationToken = default)
            => await ExecuteClamCommandAsync("RELOAD", cancellationToken).ConfigureAwait(false);
    }
}
