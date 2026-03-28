using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using VirusScanner.ClamAV;
using VirusScanner.Core;

namespace VirusScanner.Tests
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
    /// A testable ClamAvScanner that overrides CreateConnection to return a fake stream
    /// with a pre-configured response, enabling unit tests without a real ClamAV server.
    /// </summary>
    internal class TestableClamAvScanner : ClamAvScanner
    {
        private readonly string _response;
        public FakeClamStream? LastStream { get; private set; }

        public TestableClamAvScanner(string response) : base("localhost")
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
    /// A testable ClamAvScanner that throws on connection, simulating connection failure.
    /// </summary>
    internal class FailingClamAvScanner : ClamAvScanner
    {
        public FailingClamAvScanner() : base("localhost") { }

        protected override Task<Stream> CreateConnection(TcpClient clam)
        {
            throw new SocketException((int)SocketError.ConnectionRefused);
        }
    }

    [TestFixture]
    public class ClamClientTests
    {
        #region Interface verification

        [Test]
        public void ClamClient_Implements_IClamClient()
        {
            var client = new ClamAvScanner("localhost");
            Assert.That(client, Is.AssignableTo<IClamAvScanner>());
        }

        #endregion

        #region PingAsync

        [Test]
        public async Task PingAsync_ReturnsTrue_WhenServerRespondsPong()
        {
            var client = new TestableClamAvScanner("PONG\0");
            var result = await client.PingAsync();
            Assert.That(result, Is.True);
        }

        [Test]
        public async Task PingAsync_ReturnsFalse_WhenServerRespondsOther()
        {
            var client = new TestableClamAvScanner("INVALID\0");
            var result = await client.PingAsync();
            Assert.That(result, Is.False);
        }

        [Test]
        public async Task PingAsync_WithCancellationToken()
        {
            var client = new TestableClamAvScanner("PONG\0");
            using var cts = new CancellationTokenSource();
            var result = await client.PingAsync(cts.Token);
            Assert.That(result, Is.True);
        }

        #endregion

        #region TryPingAsync

        [Test]
        public async Task TryPingAsync_ReturnsTrue_WhenServerRespondsPong()
        {
            var client = new TestableClamAvScanner("PONG\0");
            var result = await client.TryPingAsync();
            Assert.That(result, Is.True);
        }

        [Test]
        public async Task TryPingAsync_ReturnsFalse_WhenServerRespondsOther()
        {
            var client = new TestableClamAvScanner("INVALID\0");
            var result = await client.TryPingAsync();
            Assert.That(result, Is.False);
        }

        [Test]
        public async Task TryPingAsync_ReturnsFalse_WhenConnectionFails()
        {
            var client = new FailingClamAvScanner();
            var result = await client.TryPingAsync();
            Assert.That(result, Is.False);
        }

        [Test]
        public async Task TryPingAsync_WithCancellationToken()
        {
            var client = new TestableClamAvScanner("PONG\0");
            using var cts = new CancellationTokenSource();
            var result = await client.TryPingAsync(cts.Token);
            Assert.That(result, Is.True);
        }

        #endregion

        #region GetVersionAsync

        [Test]
        public async Task GetVersionAsync_ReturnsVersionString()
        {
            var client = new TestableClamAvScanner("ClamAV 1.0.0/12345/Mon Jan 1 00:00:00 2024\0");
            var result = await client.GetVersionAsync();
            Assert.That(result, Is.EqualTo("ClamAV 1.0.0/12345/Mon Jan 1 00:00:00 2024"));
        }

        [Test]
        public async Task GetVersionAsync_WithCancellationToken()
        {
            var client = new TestableClamAvScanner("ClamAV 1.4.4\0");
            using var cts = new CancellationTokenSource();
            var result = await client.GetVersionAsync(cts.Token);
            Assert.That(result, Is.EqualTo("ClamAV 1.4.4"));
        }

        #endregion

        #region GetStatsAsync

        [Test]
        public async Task GetStatsAsync_ReturnsStatsString()
        {
            var stats = "POOLS: 1\nSTATE: VALID PRIMARY\nTHREADS: live 1  idle 0 max 10\nQUEUE: 0 items\n";
            var client = new TestableClamAvScanner(stats + "\0");
            var result = await client.GetStatsAsync();
            Assert.That(result, Is.EqualTo(stats));
        }

        [Test]
        public async Task GetStatsAsync_WithCancellationToken()
        {
            var client = new TestableClamAvScanner("STATS_DATA\0");
            using var cts = new CancellationTokenSource();
            var result = await client.GetStatsAsync(cts.Token);
            Assert.That(result, Is.EqualTo("STATS_DATA"));
        }

        #endregion

        #region ScanFileOnServerAsync

        [Test]
        public async Task ScanFileOnServerAsync_Clean()
        {
            var client = new TestableClamAvScanner("/test/file.txt: OK\0");
            var result = await client.ScanFileOnServerAsync("/test/file.txt");
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
        }

        [Test]
        public async Task ScanFileOnServerAsync_VirusDetected()
        {
            var client = new TestableClamAvScanner("/test/file.txt: Eicar-Test-Signature FOUND\0");
            var result = await client.ScanFileOnServerAsync("/test/file.txt");
            Assert.That(result.Status, Is.EqualTo(ScanStatus.VirusDetected));
            Assert.That(result.InfectedFiles, Is.Not.Null);
            Assert.That(result.InfectedFiles, Has.Count.EqualTo(1));
        }

        [Test]
        public async Task ScanFileOnServerAsync_Error()
        {
            var client = new TestableClamAvScanner("/test/nonexistent: lstat() failed: No such file or directory. ERROR\0");
            var result = await client.ScanFileOnServerAsync("/test/nonexistent");
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Error));
        }

        [Test]
        public async Task ScanFileOnServerAsync_WithCancellationToken()
        {
            var client = new TestableClamAvScanner("/test/file.txt: OK\0");
            using var cts = new CancellationTokenSource();
            var result = await client.ScanFileOnServerAsync("/test/file.txt", cts.Token);
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
        }

        #endregion

        #region ScanFileOnServerMultithreadedAsync

        [Test]
        public async Task ScanFileOnServerMultithreadedAsync_Clean()
        {
            var client = new TestableClamAvScanner("/test/file.txt: OK\0");
            var result = await client.ScanFileOnServerMultithreadedAsync("/test/file.txt");
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
        }

        [Test]
        public async Task ScanFileOnServerMultithreadedAsync_VirusDetected()
        {
            var client = new TestableClamAvScanner("/test/file.txt: Eicar-Test-Signature FOUND\0");
            var result = await client.ScanFileOnServerMultithreadedAsync("/test/file.txt");
            Assert.That(result.Status, Is.EqualTo(ScanStatus.VirusDetected));
        }

        [Test]
        public async Task ScanFileOnServerMultithreadedAsync_WithCancellationToken()
        {
            var client = new TestableClamAvScanner("/test/file.txt: OK\0");
            using var cts = new CancellationTokenSource();
            var result = await client.ScanFileOnServerMultithreadedAsync("/test/file.txt", cts.Token);
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
        }

        #endregion

        #region ContScanFileOnServerAsync

        [Test]
        public async Task ContScanFileOnServerAsync_Clean()
        {
            var client = new TestableClamAvScanner("/test/file.txt: OK\0");
            var result = await client.ContScanFileOnServerAsync("/test/file.txt");
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
        }

        [Test]
        public async Task ContScanFileOnServerAsync_VirusDetected_MultipleFiles()
        {
            var response = "/dir/file1.exe: Win.Trojan.Agent FOUND\n/dir/file2.doc: Doc.Malware.Macro FOUND\0";
            var client = new TestableClamAvScanner(response);
            var result = await client.ContScanFileOnServerAsync("/dir");
            Assert.That(result.Status, Is.EqualTo(ScanStatus.VirusDetected));
            Assert.That(result.InfectedFiles, Is.Not.Null);
            Assert.That(result.InfectedFiles, Has.Count.EqualTo(2));
        }

        [Test]
        public async Task ContScanFileOnServerAsync_WithCancellationToken()
        {
            var client = new TestableClamAvScanner("/test/file.txt: OK\0");
            using var cts = new CancellationTokenSource();
            var result = await client.ContScanFileOnServerAsync("/test/file.txt", cts.Token);
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
        }

        #endregion

        #region AllMatchScanFileOnServerAsync

        [Test]
        public async Task AllMatchScanFileOnServerAsync_Clean()
        {
            var client = new TestableClamAvScanner("/test/file.txt: OK\0");
            var result = await client.AllMatchScanFileOnServerAsync("/test/file.txt");
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
        }

        [Test]
        public async Task AllMatchScanFileOnServerAsync_VirusDetected()
        {
            var client = new TestableClamAvScanner("/test/file.exe: Win.Trojan.Agent FOUND\0");
            var result = await client.AllMatchScanFileOnServerAsync("/test/file.exe");
            Assert.That(result.Status, Is.EqualTo(ScanStatus.VirusDetected));
            Assert.That(result.InfectedFiles, Is.Not.Null);
            Assert.That(result.InfectedFiles, Has.Count.EqualTo(1));
        }

        [Test]
        public async Task AllMatchScanFileOnServerAsync_MultipleSignatures()
        {
            var response = "/test/file.exe: Win.Trojan.Agent FOUND\n/test/file.exe: Win.Adware.Generic FOUND\0";
            var client = new TestableClamAvScanner(response);
            var result = await client.AllMatchScanFileOnServerAsync("/test/file.exe");
            Assert.That(result.Status, Is.EqualTo(ScanStatus.VirusDetected));
            Assert.That(result.InfectedFiles, Is.Not.Null);
            Assert.That(result.InfectedFiles, Has.Count.EqualTo(2));
        }

        [Test]
        public async Task AllMatchScanFileOnServerAsync_WithCancellationToken()
        {
            var client = new TestableClamAvScanner("/test/file.txt: OK\0");
            using var cts = new CancellationTokenSource();
            var result = await client.AllMatchScanFileOnServerAsync("/test/file.txt", cts.Token);
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
        }

        #endregion

        #region SendAndScanFileAsync (byte[])

        [Test]
        public async Task SendAndScanFileAsync_ByteArray_Clean()
        {
            var client = new TestableClamAvScanner("stream: OK\0");
            var result = await client.SendAndScanFileAsync(new byte[] { 1, 2, 3 });
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
        }

        [Test]
        public async Task SendAndScanFileAsync_ByteArray_VirusDetected()
        {
            var client = new TestableClamAvScanner("stream: Win.Test.EICAR_HDB-1 FOUND\0");
            var data = Encoding.UTF8.GetBytes("test data");
            var result = await client.SendAndScanFileAsync(data);
            Assert.That(result.Status, Is.EqualTo(ScanStatus.VirusDetected));
        }

        [Test]
        public async Task SendAndScanFileAsync_ByteArray_WithCancellationToken()
        {
            var client = new TestableClamAvScanner("stream: OK\0");
            using var cts = new CancellationTokenSource();
            var result = await client.SendAndScanFileAsync(new byte[] { 1, 2, 3 }, cts.Token);
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
        }

        #endregion

        #region SendAndScanFileAsync (Stream)

        [Test]
        public async Task SendAndScanFileAsync_Stream_Clean()
        {
            var client = new TestableClamAvScanner("stream: OK\0");
            using var ms = new MemoryStream(new byte[] { 1, 2, 3 });
            var result = await client.SendAndScanFileAsync(ms);
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
        }

        [Test]
        public async Task SendAndScanFileAsync_Stream_VirusDetected()
        {
            var client = new TestableClamAvScanner("stream: Eicar-Signature FOUND\0");
            using var ms = new MemoryStream(Encoding.UTF8.GetBytes("suspicious content"));
            var result = await client.SendAndScanFileAsync(ms);
            Assert.That(result.Status, Is.EqualTo(ScanStatus.VirusDetected));
        }

        [Test]
        public async Task SendAndScanFileAsync_Stream_WithCancellationToken()
        {
            var client = new TestableClamAvScanner("stream: OK\0");
            using var ms = new MemoryStream(new byte[] { 1, 2, 3 });
            using var cts = new CancellationTokenSource();
            var result = await client.SendAndScanFileAsync(ms, cts.Token);
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
        }

        #endregion

        #region SendAndScanFileAsync - MaxStreamSize exceeded

        [Test]
        public void SendAndScanFileAsync_Stream_ThrowsWhenMaxStreamSizeExceeded()
        {
            var client = new TestableClamAvScanner("stream: OK\0");
            client.MaxStreamSize = 5;
            using var ms = new MemoryStream(new byte[100]);
            Assert.ThrowsAsync<MaxStreamSizeExceededException>(
                async () => await client.SendAndScanFileAsync(ms));
        }

        [Test]
        public void SendAndScanFileAsync_ByteArray_ThrowsWhenMaxStreamSizeExceeded()
        {
            var client = new TestableClamAvScanner("stream: OK\0");
            client.MaxStreamSize = 5;
            Assert.ThrowsAsync<MaxStreamSizeExceededException>(
                async () => await client.SendAndScanFileAsync(new byte[100]));
        }

        #endregion

        #region ReloadVirusDatabaseAsync

        [Test]
        public async Task ReloadVirusDatabaseAsync_CompletesSuccessfully()
        {
            var client = new TestableClamAvScanner("RELOADING\0");
            await client.ReloadVirusDatabaseAsync();
        }

        [Test]
        public async Task ReloadVirusDatabaseAsync_WithCancellationToken()
        {
            var client = new TestableClamAvScanner("RELOADING\0");
            using var cts = new CancellationTokenSource();
            await client.ReloadVirusDatabaseAsync(cts.Token);
        }

        #endregion

        #region Shutdown

        [Test]
        public async Task Shutdown_CompletesSuccessfully()
        {
            var client = new TestableClamAvScanner("\0");
            using var cts = new CancellationTokenSource();
            await client.Shutdown(cts.Token);
        }

        #endregion

        #region Command protocol format

        [Test]
        public async Task PingAsync_SendsCorrectCommand()
        {
            var client = new TestableClamAvScanner("PONG\0");
            await client.PingAsync();
            var sent = client.LastStream!.GetWrittenString();
            Assert.That(sent, Does.StartWith("zPING\0"));
        }

        [Test]
        public async Task GetVersionAsync_SendsCorrectCommand()
        {
            var client = new TestableClamAvScanner("ClamAV 1.0\0");
            await client.GetVersionAsync();
            var sent = client.LastStream!.GetWrittenString();
            Assert.That(sent, Does.StartWith("zVERSION\0"));
        }

        [Test]
        public async Task GetStatsAsync_SendsCorrectCommand()
        {
            var client = new TestableClamAvScanner("stats\0");
            await client.GetStatsAsync();
            var sent = client.LastStream!.GetWrittenString();
            Assert.That(sent, Does.StartWith("zSTATS\0"));
        }

        [Test]
        public async Task ScanFileOnServerAsync_SendsCorrectCommand()
        {
            var client = new TestableClamAvScanner("/path: OK\0");
            await client.ScanFileOnServerAsync("/path");
            var sent = client.LastStream!.GetWrittenString();
            Assert.That(sent, Does.StartWith("zSCAN /path\0"));
        }

        [Test]
        public async Task ScanFileOnServerMultithreadedAsync_SendsCorrectCommand()
        {
            var client = new TestableClamAvScanner("/path: OK\0");
            await client.ScanFileOnServerMultithreadedAsync("/path");
            var sent = client.LastStream!.GetWrittenString();
            Assert.That(sent, Does.StartWith("zMULTISCAN /path\0"));
        }

        [Test]
        public async Task ContScanFileOnServerAsync_SendsCorrectCommand()
        {
            var client = new TestableClamAvScanner("/path: OK\0");
            await client.ContScanFileOnServerAsync("/path");
            var sent = client.LastStream!.GetWrittenString();
            Assert.That(sent, Does.StartWith("zCONTSCAN /path\0"));
        }

        [Test]
        public async Task AllMatchScanFileOnServerAsync_SendsCorrectCommand()
        {
            var client = new TestableClamAvScanner("/path: OK\0");
            await client.AllMatchScanFileOnServerAsync("/path");
            var sent = client.LastStream!.GetWrittenString();
            Assert.That(sent, Does.StartWith("zALLMATCHSCAN /path\0"));
        }

        [Test]
        public async Task SendAndScanFileAsync_SendsInstreamCommand()
        {
            var client = new TestableClamAvScanner("stream: OK\0");
            await client.SendAndScanFileAsync(new byte[] { 1, 2, 3 });
            var sent = client.LastStream!.GetWrittenString();
            Assert.That(sent, Does.StartWith("zINSTREAM\0"));
        }

        [Test]
        public async Task ReloadVirusDatabaseAsync_SendsCorrectCommand()
        {
            var client = new TestableClamAvScanner("RELOADING\0");
            await client.ReloadVirusDatabaseAsync();
            var sent = client.LastStream!.GetWrittenString();
            Assert.That(sent, Does.StartWith("zRELOAD\0"));
        }

        [Test]
        public async Task Shutdown_SendsCorrectCommand()
        {
            var client = new TestableClamAvScanner("\0");
            await client.Shutdown(CancellationToken.None);
            var sent = client.LastStream!.GetWrittenString();
            Assert.That(sent, Does.StartWith("zSHUTDOWN\0"));
        }

        #endregion

        #region Response null-character trimming

        [Test]
        public async Task Response_NullCharacterIsTrimmed()
        {
            var client = new TestableClamAvScanner("ClamAV 1.0\0\0\0");
            var result = await client.GetVersionAsync();
            Assert.That(result, Is.EqualTo("ClamAV 1.0"));
            Assert.That(result.Contains('\0'), Is.False);
        }

        [Test]
        public async Task Response_EmptyResponseHandled()
        {
            var client = new TestableClamAvScanner("");
            var result = await client.GetVersionAsync();
            Assert.That(result, Is.EqualTo(""));
        }

        [Test]
        public async Task Response_OnlyNullCharacter_ReturnEmpty()
        {
            var client = new TestableClamAvScanner("\0");
            var result = await client.GetVersionAsync();
            Assert.That(result, Is.EqualTo(""));
        }

        #endregion

        #region UnknownClamResponseException

        [Test]
        public void UnknownClamResponseException_ContainsResponse()
        {
            var ex = new UnknownClamResponseException("WEIRD RESPONSE");
            Assert.That(ex.Message, Does.Contain("WEIRD RESPONSE"));
        }

        [Test]
        public void UnknownClamResponseException_IsException()
        {
            var ex = new UnknownClamResponseException("test");
            Assert.That(ex, Is.AssignableTo<Exception>());
        }

        #endregion
    }
}

