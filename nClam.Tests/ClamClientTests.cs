using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace nClam.Tests
{
    /// <summary>
    /// A stream that separates read and write channels to simulate a network stream.
    /// Writes are captured for verification, reads return pre-configured response data.
    /// </summary>
    internal class FakeClamStream : Stream
    {
        private readonly MemoryStream _readStream;
        private readonly MemoryStream _writeStream = new MemoryStream();

        public FakeClamStream(string response)
        {
            _readStream = new MemoryStream(Encoding.UTF8.GetBytes(response));
        }

        public byte[] GetWrittenData() => _writeStream.ToArray();

        public string GetWrittenString() => Encoding.UTF8.GetString(_writeStream.ToArray());

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => _readStream.Length;
        public override long Position
        {
            get => _readStream.Position;
            set => _readStream.Position = value;
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            _readStream.Read(buffer, offset, count);

        public override void Write(byte[] buffer, int offset, int count) =>
            _writeStream.Write(buffer, offset, count);

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _readStream.Dispose();
                _writeStream.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    /// <summary>
    /// A testable ClamClient that overrides CreateConnection to return a fake stream
    /// with a pre-configured response, enabling unit tests without a real ClamAV server.
    /// </summary>
    internal class TestableClamClient : ClamClient
    {
        private readonly string _response;
        public FakeClamStream? LastStream { get; private set; }

        public TestableClamClient(string response) : base("localhost")
        {
            _response = response;
        }

        protected override Task<Stream> CreateConnection(TcpClient clam)
        {
            LastStream = new FakeClamStream(_response);
            return Task.FromResult<Stream>(LastStream);
        }
    }

    /// <summary>
    /// A testable ClamClient that throws on connection, simulating connection failure.
    /// </summary>
    internal class FailingClamClient : ClamClient
    {
        public FailingClamClient() : base("localhost") { }

        protected override Task<Stream> CreateConnection(TcpClient clam)
        {
            throw new SocketException((int)SocketError.ConnectionRefused);
        }
    }

    public class ClamClientTests
    {
        #region Interface verification

        [Fact]
        public void ClamClient_Implements_IClamClient()
        {
            var client = new ClamClient("localhost");
            Assert.IsAssignableFrom<IClamClient>(client);
        }

        #endregion

        #region PingAsync

        [Fact]
        public async Task PingAsync_ReturnsTrue_WhenServerRespondsPong()
        {
            var client = new TestableClamClient("PONG\0");
            var result = await client.PingAsync();
            Assert.True(result);
        }

        [Fact]
        public async Task PingAsync_ReturnsFalse_WhenServerRespondsOther()
        {
            var client = new TestableClamClient("INVALID\0");
            var result = await client.PingAsync();
            Assert.False(result);
        }

        [Fact]
        public async Task PingAsync_WithCancellationToken()
        {
            var client = new TestableClamClient("PONG\0");
            using var cts = new CancellationTokenSource();
            var result = await client.PingAsync(cts.Token);
            Assert.True(result);
        }

        #endregion

        #region TryPingAsync

        [Fact]
        public async Task TryPingAsync_ReturnsTrue_WhenServerRespondsPong()
        {
            var client = new TestableClamClient("PONG\0");
            var result = await client.TryPingAsync();
            Assert.True(result);
        }

        [Fact]
        public async Task TryPingAsync_ReturnsFalse_WhenServerRespondsOther()
        {
            var client = new TestableClamClient("INVALID\0");
            var result = await client.TryPingAsync();
            Assert.False(result);
        }

        [Fact]
        public async Task TryPingAsync_ReturnsFalse_WhenConnectionFails()
        {
            var client = new FailingClamClient();
            var result = await client.TryPingAsync();
            Assert.False(result);
        }

        [Fact]
        public async Task TryPingAsync_WithCancellationToken()
        {
            var client = new TestableClamClient("PONG\0");
            using var cts = new CancellationTokenSource();
            var result = await client.TryPingAsync(cts.Token);
            Assert.True(result);
        }

        #endregion

        #region GetVersionAsync

        [Fact]
        public async Task GetVersionAsync_ReturnsVersionString()
        {
            var client = new TestableClamClient("ClamAV 1.0.0/12345/Mon Jan 1 00:00:00 2024\0");
            var result = await client.GetVersionAsync();
            Assert.Equal("ClamAV 1.0.0/12345/Mon Jan 1 00:00:00 2024", result);
        }

        [Fact]
        public async Task GetVersionAsync_WithCancellationToken()
        {
            var client = new TestableClamClient("ClamAV 1.4.4\0");
            using var cts = new CancellationTokenSource();
            var result = await client.GetVersionAsync(cts.Token);
            Assert.Equal("ClamAV 1.4.4", result);
        }

        #endregion

        #region GetStatsAsync

        [Fact]
        public async Task GetStatsAsync_ReturnsStatsString()
        {
            var stats = "POOLS: 1\nSTATE: VALID PRIMARY\nTHREADS: live 1  idle 0 max 10\nQUEUE: 0 items\n";
            var client = new TestableClamClient(stats + "\0");
            var result = await client.GetStatsAsync();
            Assert.Equal(stats, result);
        }

        [Fact]
        public async Task GetStatsAsync_WithCancellationToken()
        {
            var client = new TestableClamClient("STATS_DATA\0");
            using var cts = new CancellationTokenSource();
            var result = await client.GetStatsAsync(cts.Token);
            Assert.Equal("STATS_DATA", result);
        }

        #endregion

        #region ScanFileOnServerAsync

        [Fact]
        public async Task ScanFileOnServerAsync_Clean()
        {
            var client = new TestableClamClient("/test/file.txt: OK\0");
            var result = await client.ScanFileOnServerAsync("/test/file.txt");
            Assert.Equal(ClamScanResults.Clean, result.Result);
        }

        [Fact]
        public async Task ScanFileOnServerAsync_VirusDetected()
        {
            var client = new TestableClamClient("/test/file.txt: Eicar-Test-Signature FOUND\0");
            var result = await client.ScanFileOnServerAsync("/test/file.txt");
            Assert.Equal(ClamScanResults.VirusDetected, result.Result);
            Assert.NotNull(result.InfectedFiles);
            Assert.Single(result.InfectedFiles);
        }

        [Fact]
        public async Task ScanFileOnServerAsync_Error()
        {
            var client = new TestableClamClient("/test/nonexistent: lstat() failed: No such file or directory. ERROR\0");
            var result = await client.ScanFileOnServerAsync("/test/nonexistent");
            Assert.Equal(ClamScanResults.Error, result.Result);
        }

        [Fact]
        public async Task ScanFileOnServerAsync_WithCancellationToken()
        {
            var client = new TestableClamClient("/test/file.txt: OK\0");
            using var cts = new CancellationTokenSource();
            var result = await client.ScanFileOnServerAsync("/test/file.txt", cts.Token);
            Assert.Equal(ClamScanResults.Clean, result.Result);
        }

        #endregion

        #region ScanFileOnServerMultithreadedAsync

        [Fact]
        public async Task ScanFileOnServerMultithreadedAsync_Clean()
        {
            var client = new TestableClamClient("/test/file.txt: OK\0");
            var result = await client.ScanFileOnServerMultithreadedAsync("/test/file.txt");
            Assert.Equal(ClamScanResults.Clean, result.Result);
        }

        [Fact]
        public async Task ScanFileOnServerMultithreadedAsync_VirusDetected()
        {
            var client = new TestableClamClient("/test/file.txt: Eicar-Test-Signature FOUND\0");
            var result = await client.ScanFileOnServerMultithreadedAsync("/test/file.txt");
            Assert.Equal(ClamScanResults.VirusDetected, result.Result);
        }

        [Fact]
        public async Task ScanFileOnServerMultithreadedAsync_WithCancellationToken()
        {
            var client = new TestableClamClient("/test/file.txt: OK\0");
            using var cts = new CancellationTokenSource();
            var result = await client.ScanFileOnServerMultithreadedAsync("/test/file.txt", cts.Token);
            Assert.Equal(ClamScanResults.Clean, result.Result);
        }

        #endregion

        #region ContScanFileOnServerAsync

        [Fact]
        public async Task ContScanFileOnServerAsync_Clean()
        {
            var client = new TestableClamClient("/test/file.txt: OK\0");
            var result = await client.ContScanFileOnServerAsync("/test/file.txt");
            Assert.Equal(ClamScanResults.Clean, result.Result);
        }

        [Fact]
        public async Task ContScanFileOnServerAsync_VirusDetected_MultipleFiles()
        {
            var response = "/dir/file1.exe: Win.Trojan.Agent FOUND\n/dir/file2.doc: Doc.Malware.Macro FOUND\0";
            var client = new TestableClamClient(response);
            var result = await client.ContScanFileOnServerAsync("/dir");
            Assert.Equal(ClamScanResults.VirusDetected, result.Result);
            Assert.NotNull(result.InfectedFiles);
            Assert.Equal(2, result.InfectedFiles.Count);
        }

        [Fact]
        public async Task ContScanFileOnServerAsync_WithCancellationToken()
        {
            var client = new TestableClamClient("/test/file.txt: OK\0");
            using var cts = new CancellationTokenSource();
            var result = await client.ContScanFileOnServerAsync("/test/file.txt", cts.Token);
            Assert.Equal(ClamScanResults.Clean, result.Result);
        }

        #endregion

        #region AllMatchScanFileOnServerAsync

        [Fact]
        public async Task AllMatchScanFileOnServerAsync_Clean()
        {
            var client = new TestableClamClient("/test/file.txt: OK\0");
            var result = await client.AllMatchScanFileOnServerAsync("/test/file.txt");
            Assert.Equal(ClamScanResults.Clean, result.Result);
        }

        [Fact]
        public async Task AllMatchScanFileOnServerAsync_VirusDetected()
        {
            var client = new TestableClamClient("/test/file.exe: Win.Trojan.Agent FOUND\0");
            var result = await client.AllMatchScanFileOnServerAsync("/test/file.exe");
            Assert.Equal(ClamScanResults.VirusDetected, result.Result);
            Assert.NotNull(result.InfectedFiles);
            Assert.Single(result.InfectedFiles);
        }

        [Fact]
        public async Task AllMatchScanFileOnServerAsync_MultipleSignatures()
        {
            var response = "/test/file.exe: Win.Trojan.Agent FOUND\n/test/file.exe: Win.Adware.Generic FOUND\0";
            var client = new TestableClamClient(response);
            var result = await client.AllMatchScanFileOnServerAsync("/test/file.exe");
            Assert.Equal(ClamScanResults.VirusDetected, result.Result);
            Assert.NotNull(result.InfectedFiles);
            Assert.Equal(2, result.InfectedFiles.Count);
        }

        [Fact]
        public async Task AllMatchScanFileOnServerAsync_WithCancellationToken()
        {
            var client = new TestableClamClient("/test/file.txt: OK\0");
            using var cts = new CancellationTokenSource();
            var result = await client.AllMatchScanFileOnServerAsync("/test/file.txt", cts.Token);
            Assert.Equal(ClamScanResults.Clean, result.Result);
        }

        #endregion

        #region SendAndScanFileAsync (byte[])

        [Fact]
        public async Task SendAndScanFileAsync_ByteArray_Clean()
        {
            var client = new TestableClamClient("stream: OK\0");
            var result = await client.SendAndScanFileAsync(new byte[] { 1, 2, 3 });
            Assert.Equal(ClamScanResults.Clean, result.Result);
        }

        [Fact]
        public async Task SendAndScanFileAsync_ByteArray_VirusDetected()
        {
            var client = new TestableClamClient("stream: Win.Test.EICAR_HDB-1 FOUND\0");
            var data = Encoding.UTF8.GetBytes("test data");
            var result = await client.SendAndScanFileAsync(data);
            Assert.Equal(ClamScanResults.VirusDetected, result.Result);
        }

        [Fact]
        public async Task SendAndScanFileAsync_ByteArray_WithCancellationToken()
        {
            var client = new TestableClamClient("stream: OK\0");
            using var cts = new CancellationTokenSource();
            var result = await client.SendAndScanFileAsync(new byte[] { 1, 2, 3 }, cts.Token);
            Assert.Equal(ClamScanResults.Clean, result.Result);
        }

        #endregion

        #region SendAndScanFileAsync (Stream)

        [Fact]
        public async Task SendAndScanFileAsync_Stream_Clean()
        {
            var client = new TestableClamClient("stream: OK\0");
            using var ms = new MemoryStream(new byte[] { 1, 2, 3 });
            var result = await client.SendAndScanFileAsync(ms);
            Assert.Equal(ClamScanResults.Clean, result.Result);
        }

        [Fact]
        public async Task SendAndScanFileAsync_Stream_VirusDetected()
        {
            var client = new TestableClamClient("stream: Eicar-Signature FOUND\0");
            using var ms = new MemoryStream(Encoding.UTF8.GetBytes("suspicious content"));
            var result = await client.SendAndScanFileAsync(ms);
            Assert.Equal(ClamScanResults.VirusDetected, result.Result);
        }

        [Fact]
        public async Task SendAndScanFileAsync_Stream_WithCancellationToken()
        {
            var client = new TestableClamClient("stream: OK\0");
            using var ms = new MemoryStream(new byte[] { 1, 2, 3 });
            using var cts = new CancellationTokenSource();
            var result = await client.SendAndScanFileAsync(ms, cts.Token);
            Assert.Equal(ClamScanResults.Clean, result.Result);
        }

        #endregion

        #region SendAndScanFileAsync - MaxStreamSize exceeded

        [Fact]
        public async Task SendAndScanFileAsync_Stream_ThrowsWhenMaxStreamSizeExceeded()
        {
            var client = new TestableClamClient("stream: OK\0");
            client.MaxStreamSize = 5;
            using var ms = new MemoryStream(new byte[100]);
            await Assert.ThrowsAsync<MaxStreamSizeExceededException>(
                () => client.SendAndScanFileAsync(ms));
        }

        [Fact]
        public async Task SendAndScanFileAsync_ByteArray_ThrowsWhenMaxStreamSizeExceeded()
        {
            var client = new TestableClamClient("stream: OK\0");
            client.MaxStreamSize = 5;
            await Assert.ThrowsAsync<MaxStreamSizeExceededException>(
                () => client.SendAndScanFileAsync(new byte[100]));
        }

        #endregion

        #region ReloadVirusDatabaseAsync

        [Fact]
        public async Task ReloadVirusDatabaseAsync_CompletesSuccessfully()
        {
            var client = new TestableClamClient("RELOADING\0");
            await client.ReloadVirusDatabaseAsync();
        }

        [Fact]
        public async Task ReloadVirusDatabaseAsync_WithCancellationToken()
        {
            var client = new TestableClamClient("RELOADING\0");
            using var cts = new CancellationTokenSource();
            await client.ReloadVirusDatabaseAsync(cts.Token);
        }

        #endregion

        #region Shutdown

        [Fact]
        public async Task Shutdown_CompletesSuccessfully()
        {
            var client = new TestableClamClient("\0");
            using var cts = new CancellationTokenSource();
            await client.Shutdown(cts.Token);
        }

        #endregion

        #region Command protocol format

        [Fact]
        public async Task PingAsync_SendsCorrectCommand()
        {
            var client = new TestableClamClient("PONG\0");
            await client.PingAsync();
            var sent = client.LastStream!.GetWrittenString();
            Assert.StartsWith("zPING\0", sent);
        }

        [Fact]
        public async Task GetVersionAsync_SendsCorrectCommand()
        {
            var client = new TestableClamClient("ClamAV 1.0\0");
            await client.GetVersionAsync();
            var sent = client.LastStream!.GetWrittenString();
            Assert.StartsWith("zVERSION\0", sent);
        }

        [Fact]
        public async Task GetStatsAsync_SendsCorrectCommand()
        {
            var client = new TestableClamClient("stats\0");
            await client.GetStatsAsync();
            var sent = client.LastStream!.GetWrittenString();
            Assert.StartsWith("zSTATS\0", sent);
        }

        [Fact]
        public async Task ScanFileOnServerAsync_SendsCorrectCommand()
        {
            var client = new TestableClamClient("/path: OK\0");
            await client.ScanFileOnServerAsync("/path");
            var sent = client.LastStream!.GetWrittenString();
            Assert.StartsWith("zSCAN /path\0", sent);
        }

        [Fact]
        public async Task ScanFileOnServerMultithreadedAsync_SendsCorrectCommand()
        {
            var client = new TestableClamClient("/path: OK\0");
            await client.ScanFileOnServerMultithreadedAsync("/path");
            var sent = client.LastStream!.GetWrittenString();
            Assert.StartsWith("zMULTISCAN /path\0", sent);
        }

        [Fact]
        public async Task ContScanFileOnServerAsync_SendsCorrectCommand()
        {
            var client = new TestableClamClient("/path: OK\0");
            await client.ContScanFileOnServerAsync("/path");
            var sent = client.LastStream!.GetWrittenString();
            Assert.StartsWith("zCONTSCAN /path\0", sent);
        }

        [Fact]
        public async Task AllMatchScanFileOnServerAsync_SendsCorrectCommand()
        {
            var client = new TestableClamClient("/path: OK\0");
            await client.AllMatchScanFileOnServerAsync("/path");
            var sent = client.LastStream!.GetWrittenString();
            Assert.StartsWith("zALLMATCHSCAN /path\0", sent);
        }

        [Fact]
        public async Task SendAndScanFileAsync_SendsInstreamCommand()
        {
            var client = new TestableClamClient("stream: OK\0");
            await client.SendAndScanFileAsync(new byte[] { 1, 2, 3 });
            var sent = client.LastStream!.GetWrittenString();
            Assert.StartsWith("zINSTREAM\0", sent);
        }

        [Fact]
        public async Task ReloadVirusDatabaseAsync_SendsCorrectCommand()
        {
            var client = new TestableClamClient("RELOADING\0");
            await client.ReloadVirusDatabaseAsync();
            var sent = client.LastStream!.GetWrittenString();
            Assert.StartsWith("zRELOAD\0", sent);
        }

        [Fact]
        public async Task Shutdown_SendsCorrectCommand()
        {
            var client = new TestableClamClient("\0");
            await client.Shutdown(CancellationToken.None);
            var sent = client.LastStream!.GetWrittenString();
            Assert.StartsWith("zSHUTDOWN\0", sent);
        }

        #endregion

        #region Response null-character trimming

        [Fact]
        public async Task Response_NullCharacterIsTrimmed()
        {
            var client = new TestableClamClient("ClamAV 1.0\0\0\0");
            var result = await client.GetVersionAsync();
            Assert.Equal("ClamAV 1.0", result);
            Assert.DoesNotContain('\0', result);
        }

        [Fact]
        public async Task Response_EmptyResponseHandled()
        {
            var client = new TestableClamClient("");
            var result = await client.GetVersionAsync();
            Assert.Equal("", result);
        }

        [Fact]
        public async Task Response_OnlyNullCharacter_ReturnEmpty()
        {
            var client = new TestableClamClient("\0");
            var result = await client.GetVersionAsync();
            Assert.Equal("", result);
        }

        #endregion

        #region UnknownClamResponseException

        [Fact]
        public void UnknownClamResponseException_ContainsResponse()
        {
            var ex = new UnknownClamResponseException("WEIRD RESPONSE");
            Assert.Contains("WEIRD RESPONSE", ex.Message);
        }

        [Fact]
        public void UnknownClamResponseException_IsException()
        {
            var ex = new UnknownClamResponseException("test");
            Assert.IsAssignableFrom<Exception>(ex);
        }

        #endregion
    }
}
