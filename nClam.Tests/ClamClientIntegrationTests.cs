using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace nClam.Tests
{
    /// <summary>
    /// Integration tests that require a running ClamAV server on localhost:3310.
    /// Start with: docker compose up -d
    /// All tests use Trait("Category", "Integration") for selective execution.
    /// </summary>
    [Trait("Category", "Integration")]
    public class ClamClientIntegrationTests : IAsyncLifetime
    {
        private const string ClamHost = "localhost";
        private const int ClamPort = 3310;

        // EICAR test string - an industry standard test pattern recognized by all AV engines
        private const string EicarTestString = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        private ClamClient _client = null!;
        private bool _serverAvailable;

        public async Task InitializeAsync()
        {
            _client = new ClamClient(ClamHost, ClamPort);
            _serverAvailable = await _client.TryPingAsync();
        }

        public Task DisposeAsync() => Task.CompletedTask;

        private void RequireServer()
        {
            if (!_serverAvailable)
                throw new InvalidOperationException(
                    $"ClamAV server not available at {ClamHost}:{ClamPort}. Start with: docker compose up -d");
        }

        #region Ping

        [Fact]
        public async Task PingAsync_ReturnsTrue()
        {
            RequireServer();
            var result = await _client.PingAsync();
            Assert.True(result);
        }

        [Fact]
        public async Task PingAsync_WithCancellationToken_ReturnsTrue()
        {
            RequireServer();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var result = await _client.PingAsync(cts.Token);
            Assert.True(result);
        }

        [Fact]
        public async Task TryPingAsync_ReturnsTrue()
        {
            RequireServer();
            var result = await _client.TryPingAsync();
            Assert.True(result);
        }

        #endregion

        #region Version

        [Fact]
        public async Task GetVersionAsync_ReturnsClamAVVersion()
        {
            RequireServer();
            var version = await _client.GetVersionAsync();

            Assert.NotNull(version);
            Assert.NotEmpty(version);
            Assert.StartsWith("ClamAV", version);
        }

        [Fact]
        public async Task GetVersionAsync_WithCancellationToken()
        {
            RequireServer();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var version = await _client.GetVersionAsync(cts.Token);

            Assert.StartsWith("ClamAV", version);
        }

        #endregion

        #region Stats

        [Fact]
        public async Task GetStatsAsync_ReturnsStatistics()
        {
            RequireServer();
            var stats = await _client.GetStatsAsync();

            Assert.NotNull(stats);
            Assert.NotEmpty(stats);
            Assert.Contains("POOLS", stats);
        }

        #endregion

        #region SendAndScanFileAsync - EICAR virus detection

        [Fact]
        public async Task SendAndScanFileAsync_Stream_DetectsEicar()
        {
            RequireServer();
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(EicarTestString));
            var result = await _client.SendAndScanFileAsync(stream);

            Assert.Equal(ClamScanResults.VirusDetected, result.Result);
            Assert.NotNull(result.InfectedFiles);
            Assert.Single(result.InfectedFiles);
            Assert.Contains("EICAR", result.InfectedFiles[0].VirusName, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task SendAndScanFileAsync_ByteArray_DetectsEicar()
        {
            RequireServer();
            var data = Encoding.UTF8.GetBytes(EicarTestString);
            var result = await _client.SendAndScanFileAsync(data);

            Assert.Equal(ClamScanResults.VirusDetected, result.Result);
            Assert.NotNull(result.InfectedFiles);
            Assert.Single(result.InfectedFiles);
        }

        [Fact]
        public async Task SendAndScanFileAsync_Stream_CleanData()
        {
            RequireServer();
            using var stream = new MemoryStream(Encoding.UTF8.GetBytes("This is perfectly safe content."));
            var result = await _client.SendAndScanFileAsync(stream);

            Assert.Equal(ClamScanResults.Clean, result.Result);
            Assert.Null(result.InfectedFiles);
        }

        [Fact]
        public async Task SendAndScanFileAsync_ByteArray_CleanData()
        {
            RequireServer();
            var data = Encoding.UTF8.GetBytes("Completely harmless file content.");
            var result = await _client.SendAndScanFileAsync(data);

            Assert.Equal(ClamScanResults.Clean, result.Result);
        }

        [Fact]
        public async Task SendAndScanFileAsync_EmptyData_IsClean()
        {
            RequireServer();
            var result = await _client.SendAndScanFileAsync(Array.Empty<byte>());

            Assert.Equal(ClamScanResults.Clean, result.Result);
        }

        [Fact]
        public async Task SendAndScanFileAsync_WithCancellationToken()
        {
            RequireServer();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var data = Encoding.UTF8.GetBytes(EicarTestString);
            var result = await _client.SendAndScanFileAsync(data, cts.Token);

            Assert.Equal(ClamScanResults.VirusDetected, result.Result);
        }

        #endregion

        #region SendAndScanFileAsync - IP address connection

        [Fact]
        public async Task SendAndScanFileAsync_ViaIPAddress_DetectsEicar()
        {
            RequireServer();
            var ipClient = new ClamClient(IPAddress.Loopback, ClamPort);
            var data = Encoding.UTF8.GetBytes(EicarTestString);
            var result = await ipClient.SendAndScanFileAsync(data);

            Assert.Equal(ClamScanResults.VirusDetected, result.Result);
        }

        [Fact]
        public async Task SendAndScanFileAsync_ViaIPAddress_CleanData()
        {
            RequireServer();
            var ipClient = new ClamClient(IPAddress.Loopback, ClamPort);
            var data = Encoding.UTF8.GetBytes("safe content");
            var result = await ipClient.SendAndScanFileAsync(data);

            Assert.Equal(ClamScanResults.Clean, result.Result);
        }

        #endregion

        #region SendAndScanFileAsync - MaxStreamSize

        [Fact]
        public async Task SendAndScanFileAsync_ThrowsWhenMaxStreamSizeExceeded()
        {
            RequireServer();
            _client.MaxStreamSize = 10;
            var data = new byte[100];

            await Assert.ThrowsAsync<MaxStreamSizeExceededException>(
                () => _client.SendAndScanFileAsync(data));
        }

        #endregion

        #region ReloadVirusDatabaseAsync

        [Fact]
        public async Task ReloadVirusDatabaseAsync_CompletesWithoutError()
        {
            RequireServer();
            await _client.ReloadVirusDatabaseAsync();
        }

        [Fact]
        public async Task ReloadVirusDatabaseAsync_WithCancellationToken()
        {
            RequireServer();
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            await _client.ReloadVirusDatabaseAsync(cts.Token);
        }

        #endregion

        #region ContScanFileOnServerAsync (INSTREAM-based verification)

        [Fact]
        public async Task ContScanFileOnServerAsync_SendsContScanCommand()
        {
            RequireServer();
            // CONTSCAN on a non-existent server path returns an error
            var result = await _client.ContScanFileOnServerAsync("/nonexistent_path_for_test");
            // Should get error (path doesn't exist in container) or unknown
            Assert.True(
                result.Result == ClamScanResults.Error || result.Result == ClamScanResults.Unknown,
                $"Expected Error or Unknown, got {result.Result}: {result.RawResult}");
        }

        #endregion

        #region AllMatchScanFileOnServerAsync

        [Fact]
        public async Task AllMatchScanFileOnServerAsync_SendsAllMatchScanCommand()
        {
            RequireServer();
            // ALLMATCHSCAN on a non-existent server path returns an error
            var result = await _client.AllMatchScanFileOnServerAsync("/nonexistent_path_for_test");
            Assert.True(
                result.Result == ClamScanResults.Error || result.Result == ClamScanResults.Unknown,
                $"Expected Error or Unknown, got {result.Result}: {result.RawResult}");
        }

        #endregion

        #region ScanFileOnServerAsync

        [Fact]
        public async Task ScanFileOnServerAsync_NonExistentPath_ReturnsError()
        {
            RequireServer();
            var result = await _client.ScanFileOnServerAsync("/nonexistent_path_for_test");
            Assert.True(
                result.Result == ClamScanResults.Error || result.Result == ClamScanResults.Unknown,
                $"Expected Error or Unknown, got {result.Result}: {result.RawResult}");
        }

        #endregion

        #region ScanFileOnServerMultithreadedAsync

        [Fact]
        public async Task ScanFileOnServerMultithreadedAsync_NonExistentPath_ReturnsError()
        {
            RequireServer();
            var result = await _client.ScanFileOnServerMultithreadedAsync("/nonexistent_path_for_test");
            Assert.True(
                result.Result == ClamScanResults.Error || result.Result == ClamScanResults.Unknown,
                $"Expected Error or Unknown, got {result.Result}: {result.RawResult}");
        }

        #endregion

        #region RawResult verification

        [Fact]
        public async Task SendAndScanFileAsync_RawResult_ContainsStreamPrefix()
        {
            RequireServer();
            var data = Encoding.UTF8.GetBytes(EicarTestString);
            var result = await _client.SendAndScanFileAsync(data);

            Assert.Contains("stream", result.RawResult, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("FOUND", result.RawResult);
        }

        [Fact]
        public async Task SendAndScanFileAsync_CleanData_RawResultContainsOK()
        {
            RequireServer();
            var data = Encoding.UTF8.GetBytes("safe");
            var result = await _client.SendAndScanFileAsync(data);

            Assert.Contains("OK", result.RawResult);
        }

        #endregion

        #region Multiple sequential scans

        [Fact]
        public async Task MultipleScans_InSequence_AllSucceed()
        {
            RequireServer();
            var eicarData = Encoding.UTF8.GetBytes(EicarTestString);
            var cleanData = Encoding.UTF8.GetBytes("clean content");

            var result1 = await _client.SendAndScanFileAsync(eicarData);
            Assert.Equal(ClamScanResults.VirusDetected, result1.Result);

            var result2 = await _client.SendAndScanFileAsync(cleanData);
            Assert.Equal(ClamScanResults.Clean, result2.Result);

            var result3 = await _client.SendAndScanFileAsync(eicarData);
            Assert.Equal(ClamScanResults.VirusDetected, result3.Result);
        }

        #endregion

        #region Connection failure

        [Fact]
        public async Task TryPingAsync_WrongPort_ReturnsFalse()
        {
            var badClient = new ClamClient("localhost", 19999);
            var result = await badClient.TryPingAsync();
            Assert.False(result);
        }

        [Fact]
        public async Task PingAsync_WrongPort_Throws()
        {
            var badClient = new ClamClient("localhost", 19999);
            await Assert.ThrowsAnyAsync<Exception>(() => badClient.PingAsync());
        }

        #endregion
    }
}
