using System;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using VirusScanner.ClamAV;
using VirusScanner.Core;

namespace VirusScanner.Tests
{
    [TestFixture]
    [Category("Integration")]
    public class ClamClientIntegrationTests
    {
        private const string ClamHost = "localhost";
        private const int ClamPort = 3310;
        private const string EicarTestString = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        private ClamAvScanner _client = null!;
        private bool _serverAvailable;

        [SetUp]
        public async Task SetUp()
        {
            _client = new ClamAvScanner(ClamHost, ClamPort);
            _serverAvailable = await _client.TryPingAsync();
        }

        private void RequireServer()
        {
            if (!_serverAvailable)
                Assert.Ignore($"ClamAV server not available at {ClamHost}:{ClamPort}. Start with: docker compose up -d");
        }

        [Test]
        public async Task PingAsync_ReturnsTrue()
        {
            RequireServer();
            var result = await _client.PingAsync();
            Assert.That(result, Is.True);
        }

        [Test]
        public async Task PingAsync_WithCancellationToken_ReturnsTrue()
        {
            RequireServer();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var result = await _client.PingAsync(cts.Token);
            Assert.That(result, Is.True);
        }

        [Test]
        public async Task TryPingAsync_ReturnsTrue()
        {
            RequireServer();
            var result = await _client.TryPingAsync();
            Assert.That(result, Is.True);
        }

        [Test]
        public async Task GetVersionAsync_ReturnsClamAVVersion()
        {
            RequireServer();
            var version = await _client.GetVersionAsync();
            Assert.That(version, Is.Not.Null);
            Assert.That(version, Is.Not.Empty);
            Assert.That(version, Does.StartWith("ClamAV"));
        }

        [Test]
        public async Task GetVersionAsync_WithCancellationToken()
        {
            RequireServer();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var version = await _client.GetVersionAsync(cts.Token);
            Assert.That(version, Does.StartWith("ClamAV"));
        }

        [Test]
        public async Task GetStatsAsync_ReturnsStatistics()
        {
            RequireServer();
            var stats = await _client.GetStatsAsync();
            Assert.That(stats, Is.Not.Null);
            Assert.That(stats, Is.Not.Empty);
            Assert.That(stats, Does.Contain("POOLS"));
        }

        [Test]
        public async Task SendAndScanFileAsync_Stream_DetectsEicar()
        {
            RequireServer();
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(EicarTestString));
            var result = await _client.SendAndScanFileAsync(stream);
            Assert.That(result.Status, Is.EqualTo(ScanStatus.VirusDetected));
            Assert.That(result.InfectedFiles, Is.Not.Null);
            Assert.That(result.InfectedFiles, Has.Count.EqualTo(1));
            Assert.That(result.InfectedFiles[0].VirusName.ToUpperInvariant(), Does.Contain("EICAR"));
        }

        [Test]
        public async Task SendAndScanFileAsync_ByteArray_DetectsEicar()
        {
            RequireServer();
            var data = Encoding.UTF8.GetBytes(EicarTestString);
            var result = await _client.SendAndScanFileAsync(data);
            Assert.That(result.Status, Is.EqualTo(ScanStatus.VirusDetected));
            Assert.That(result.InfectedFiles, Is.Not.Null);
            Assert.That(result.InfectedFiles, Has.Count.EqualTo(1));
        }

        [Test]
        public async Task SendAndScanFileAsync_Stream_CleanData()
        {
            RequireServer();
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes("This is perfectly safe content."));
            var result = await _client.SendAndScanFileAsync(stream);
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
            Assert.That(result.InfectedFiles, Is.Null);
        }

        [Test]
        public async Task SendAndScanFileAsync_ByteArray_CleanData()
        {
            RequireServer();
            var data = Encoding.UTF8.GetBytes("Completely harmless file content.");
            var result = await _client.SendAndScanFileAsync(data);
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
        }

        [Test]
        public async Task SendAndScanFileAsync_EmptyData_IsClean()
        {
            RequireServer();
            var result = await _client.SendAndScanFileAsync(Array.Empty<byte>());
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
        }

        [Test]
        public async Task SendAndScanFileAsync_WithCancellationToken()
        {
            RequireServer();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var data = Encoding.UTF8.GetBytes(EicarTestString);
            var result = await _client.SendAndScanFileAsync(data, cts.Token);
            Assert.That(result.Status, Is.EqualTo(ScanStatus.VirusDetected));
        }

        [Test]
        public async Task SendAndScanFileAsync_ViaIPAddress_DetectsEicar()
        {
            RequireServer();
            var ipClient = new ClamAvScanner(IPAddress.Loopback, ClamPort);
            var data = Encoding.UTF8.GetBytes(EicarTestString);
            var result = await ipClient.SendAndScanFileAsync(data);
            Assert.That(result.Status, Is.EqualTo(ScanStatus.VirusDetected));
        }

        [Test]
        public async Task SendAndScanFileAsync_ViaIPAddress_CleanData()
        {
            RequireServer();
            var ipClient = new ClamAvScanner(IPAddress.Loopback, ClamPort);
            var data = Encoding.UTF8.GetBytes("safe content");
            var result = await ipClient.SendAndScanFileAsync(data);
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
        }

        [Test]
        public void SendAndScanFileAsync_ThrowsWhenMaxStreamSizeExceeded()
        {
            RequireServer();
            _client.MaxStreamSize = 10;
            var data = new byte[100];
            Assert.ThrowsAsync<MaxStreamSizeExceededException>(
                async () => await _client.SendAndScanFileAsync(data));
        }

        [Test]
        public async Task ReloadVirusDatabaseAsync_CompletesWithoutError()
        {
            RequireServer();
            await _client.ReloadVirusDatabaseAsync();
        }

        [Test]
        public async Task ReloadVirusDatabaseAsync_WithCancellationToken()
        {
            RequireServer();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await _client.ReloadVirusDatabaseAsync(cts.Token);
        }

        [Test]
        public async Task ContScanFileOnServerAsync_NonExistentPath_ReturnsError()
        {
            RequireServer();
            var result = await _client.ContScanFileOnServerAsync("/nonexistent_path_for_test");
            Assert.That(
                result.Status == ScanStatus.Error || result.Status == ScanStatus.Unknown, Is.True,
                $"Expected Error or Unknown, got {result.Status}: {result.RawResult}");
        }

        [Test]
        public async Task AllMatchScanFileOnServerAsync_NonExistentPath_ReturnsError()
        {
            RequireServer();
            var result = await _client.AllMatchScanFileOnServerAsync("/nonexistent_path_for_test");
            Assert.That(
                result.Status == ScanStatus.Error || result.Status == ScanStatus.Unknown, Is.True,
                $"Expected Error or Unknown, got {result.Status}: {result.RawResult}");
        }

        [Test]
        public async Task ScanFileOnServerAsync_NonExistentPath_ReturnsError()
        {
            RequireServer();
            var result = await _client.ScanFileOnServerAsync("/nonexistent_path_for_test");
            Assert.That(
                result.Status == ScanStatus.Error || result.Status == ScanStatus.Unknown, Is.True,
                $"Expected Error or Unknown, got {result.Status}: {result.RawResult}");
        }

        [Test]
        public async Task ScanFileOnServerMultithreadedAsync_NonExistentPath_ReturnsError()
        {
            RequireServer();
            var result = await _client.ScanFileOnServerMultithreadedAsync("/nonexistent_path_for_test");
            Assert.That(
                result.Status == ScanStatus.Error || result.Status == ScanStatus.Unknown, Is.True,
                $"Expected Error or Unknown, got {result.Status}: {result.RawResult}");
        }

        [Test]
        public async Task SendAndScanFileAsync_RawResult_ContainsStreamPrefix()
        {
            RequireServer();
            var data = Encoding.UTF8.GetBytes(EicarTestString);
            var result = await _client.SendAndScanFileAsync(data);
            Assert.That(result.RawResult.ToUpperInvariant(), Does.Contain("STREAM"));
            Assert.That(result.RawResult, Does.Contain("FOUND"));
        }

        [Test]
        public async Task SendAndScanFileAsync_CleanData_RawResultContainsOK()
        {
            RequireServer();
            var data = Encoding.UTF8.GetBytes("safe");
            var result = await _client.SendAndScanFileAsync(data);
            Assert.That(result.RawResult, Does.Contain("OK"));
        }

        [Test]
        public async Task MultipleScans_InSequence_AllSucceed()
        {
            RequireServer();
            var eicarData = Encoding.UTF8.GetBytes(EicarTestString);
            var cleanData = Encoding.UTF8.GetBytes("clean content");

            var result1 = await _client.SendAndScanFileAsync(eicarData);
            Assert.That(result1.Status, Is.EqualTo(ScanStatus.VirusDetected));

            var result2 = await _client.SendAndScanFileAsync(cleanData);
            Assert.That(result2.Status, Is.EqualTo(ScanStatus.Clean));

            var result3 = await _client.SendAndScanFileAsync(eicarData);
            Assert.That(result3.Status, Is.EqualTo(ScanStatus.VirusDetected));
        }

        [Test]
        public async Task TryPingAsync_WrongPort_ReturnsFalse()
        {
            var badClient = new ClamAvScanner("localhost", 19999);
            var result = await badClient.TryPingAsync();
            Assert.That(result, Is.False);
        }

        [Test]
        public void PingAsync_WrongPort_Throws()
        {
            var badClient = new ClamAvScanner("localhost", 19999);
            Assert.CatchAsync<Exception>(async () => await badClient.PingAsync());
        }
    }
}

