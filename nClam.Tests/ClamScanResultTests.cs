using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Xunit;

namespace nClam.Tests
{
    public class ClamScanResultTests
    {
        [Fact]
        public void OK_Response()
        {
            var result = new ClamScanResult(@"C:\test.txt: OK");

            Assert.Equal(ClamScanResults.Clean, result.Result);
        }

        [Fact]
        public void Error_Response()
        {
            var result = new ClamScanResult("error");

            Assert.Equal(ClamScanResults.Error, result.Result);
        }

        [Fact]
        public void VirusDetected_Response()
        {
            var result = new ClamScanResult(@"\\?\C:\test.txt: Eicar-Test-Signature FOUND");

            Assert.Equal(ClamScanResults.VirusDetected, result.Result);

            Assert.Single(result.InfectedFiles);

            Assert.Equal(@"\\?\C:\test.txt", result.InfectedFiles[0].FileName);
            Assert.Equal(" Eicar-Test-Signature", result.InfectedFiles[0].VirusName);
        }

        [Fact]
        public void Non_Matching()
        {
            var result = new ClamScanResult(Guid.NewGuid().ToString());

            Assert.Equal(ClamScanResults.Unknown, result.Result);
        }

        [Fact]
        public void Before_Tests()
        {
            Assert.Equal(
                "test:test1",
                ClamScanResult.ExtractFileName("test:test1:test2")
                );

            Assert.Equal(
                "",
                ClamScanResult.ExtractFileName("test")
                );

            Assert.Equal(
                "test",
                ClamScanResult.ExtractFileName("test:test1")
                );
        }

        [Fact]
        public void After_Tests()
        {
            //current released behavior to have initial space
            //(probably a bug)

            Assert.Equal(
                " test1",
                ClamScanResult.ExtractVirusName("test test1")
                );

            Assert.Equal(
                " test2",
                ClamScanResult.ExtractVirusName("test test1 test2")
                );

            Assert.Equal(
                "",
                ClamScanResult.ExtractVirusName("test")
                );
        }

        #region ClamScanResult - Case Insensitivity

        [Theory]
        [InlineData(@"C:\test.txt: OK")]
        [InlineData(@"C:\test.txt: ok")]
        [InlineData(@"C:\test.txt: Ok")]
        [InlineData(@"C:\test.txt: oK")]
        public void OK_Response_CaseInsensitive(string rawResult)
        {
            var result = new ClamScanResult(rawResult);
            Assert.Equal(ClamScanResults.Clean, result.Result);
        }

        [Theory]
        [InlineData("some error")]
        [InlineData("some ERROR")]
        [InlineData("some Error")]
        [InlineData("ERROR")]
        public void Error_Response_CaseInsensitive(string rawResult)
        {
            var result = new ClamScanResult(rawResult);
            Assert.Equal(ClamScanResults.Error, result.Result);
        }

        [Theory]
        [InlineData(@"C:\test.txt: Eicar-Test-Signature FOUND")]
        [InlineData(@"C:\test.txt: Eicar-Test-Signature found")]
        [InlineData(@"C:\test.txt: Eicar-Test-Signature Found")]
        public void VirusDetected_Response_CaseInsensitive(string rawResult)
        {
            var result = new ClamScanResult(rawResult);
            Assert.Equal(ClamScanResults.VirusDetected, result.Result);
        }

        #endregion

        #region ClamScanResult - RawResult and ToString

        [Fact]
        public void RawResult_IsPreserved()
        {
            var raw = @"C:\test.txt: OK";
            var result = new ClamScanResult(raw);
            Assert.Equal(raw, result.RawResult);
        }

        [Fact]
        public void ToString_ReturnsRawResult()
        {
            var raw = @"C:\test.txt: Eicar-Test-Signature FOUND";
            var result = new ClamScanResult(raw);
            Assert.Equal(raw, result.ToString());
        }

        #endregion

        #region ClamScanResult - InfectedFiles null checks

        [Fact]
        public void Clean_Result_InfectedFiles_IsNull()
        {
            var result = new ClamScanResult(@"C:\test.txt: OK");
            Assert.Equal(ClamScanResults.Clean, result.Result);
            Assert.Null(result.InfectedFiles);
        }

        [Fact]
        public void Error_Result_InfectedFiles_IsNull()
        {
            var result = new ClamScanResult("some error");
            Assert.Equal(ClamScanResults.Error, result.Result);
            Assert.Null(result.InfectedFiles);
        }

        [Fact]
        public void Unknown_Result_InfectedFiles_IsNull()
        {
            var result = new ClamScanResult("something completely unrecognized");
            Assert.Equal(ClamScanResults.Unknown, result.Result);
            Assert.Null(result.InfectedFiles);
        }

        #endregion

        #region ClamScanResult - Multiple infected files

        [Fact]
        public void VirusDetected_MultipleFiles()
        {
            var raw = "/files/test1.exe: Win.Trojan.Agent FOUND\n/files/test2.doc: Doc.Malware.Macro FOUND";
            var result = new ClamScanResult(raw);

            Assert.Equal(ClamScanResults.VirusDetected, result.Result);
            Assert.NotNull(result.InfectedFiles);
            Assert.Equal(2, result.InfectedFiles.Count);

            Assert.Equal("/files/test1.exe", result.InfectedFiles[0].FileName);
            Assert.Equal(" Win.Trojan.Agent", result.InfectedFiles[0].VirusName);

            Assert.Equal("/files/test2.doc", result.InfectedFiles[1].FileName);
            Assert.Equal(" Doc.Malware.Macro", result.InfectedFiles[1].VirusName);
        }

        [Fact]
        public void VirusDetected_StreamResult()
        {
            var result = new ClamScanResult("stream: Win.Test.EICAR_HDB-1 FOUND");

            Assert.Equal(ClamScanResults.VirusDetected, result.Result);
            Assert.NotNull(result.InfectedFiles);
            Assert.Single(result.InfectedFiles);
            Assert.Equal("stream", result.InfectedFiles[0].FileName);
            Assert.Equal(" Win.Test.EICAR_HDB-1", result.InfectedFiles[0].VirusName);
        }

        #endregion

        #region ClamScanResult - Edge cases

        [Fact]
        public void EmptyString_ReturnsUnknown()
        {
            var result = new ClamScanResult("");
            Assert.Equal(ClamScanResults.Unknown, result.Result);
            Assert.Null(result.InfectedFiles);
        }

        [Fact]
        public void WhitespaceOnly_ReturnsUnknown()
        {
            var result = new ClamScanResult("   ");
            Assert.Equal(ClamScanResults.Unknown, result.Result);
        }

        [Fact]
        public void JustOK_ReturnsClean()
        {
            var result = new ClamScanResult("OK");
            Assert.Equal(ClamScanResults.Clean, result.Result);
        }

        [Fact]
        public void JustFOUND_ReturnsVirusDetected()
        {
            var result = new ClamScanResult("FOUND");
            Assert.Equal(ClamScanResults.VirusDetected, result.Result);
        }

        #endregion

        #region ExtractFileName - Edge cases

        [Fact]
        public void ExtractFileName_EmptyString_ReturnsEmpty()
        {
            Assert.Equal("", ClamScanResult.ExtractFileName(""));
        }

        [Fact]
        public void ExtractFileName_ColonAtStart_ReturnsEmpty()
        {
            Assert.Equal("", ClamScanResult.ExtractFileName(":value"));
        }

        [Fact]
        public void ExtractFileName_UncPath()
        {
            Assert.Equal(
                @"\\server\share\file.txt",
                ClamScanResult.ExtractFileName(@"\\server\share\file.txt: virus")
                );
        }

        [Fact]
        public void ExtractFileName_WindowsPathWithDrive()
        {
            Assert.Equal(
                @"C:\Users\test\file.txt",
                ClamScanResult.ExtractFileName(@"C:\Users\test\file.txt: virus")
                );
        }

        #endregion

        #region ExtractVirusName - Edge cases

        [Fact]
        public void ExtractVirusName_EmptyString_ReturnsEmpty()
        {
            Assert.Equal("", ClamScanResult.ExtractVirusName(""));
        }

        [Fact]
        public void ExtractVirusName_NoSpaces_ReturnsEmpty()
        {
            Assert.Equal("", ClamScanResult.ExtractVirusName("nospaces"));
        }

        [Fact]
        public void ExtractVirusName_SpaceAtStart_ReturnsEmpty()
        {
            // Space at index 0 is not > 0, so returns empty
            Assert.Equal("", ClamScanResult.ExtractVirusName(" virusname"));
        }

        #endregion

        #region ClamScanInfectedFile

        [Fact]
        public void ClamScanInfectedFile_Properties_SetCorrectly()
        {
            var file = new ClamScanInfectedFile("test.txt", "Eicar");
            Assert.Equal("test.txt", file.FileName);
            Assert.Equal("Eicar", file.VirusName);
        }

        [Fact]
        public void ClamScanInfectedFile_Record_Equality()
        {
            var file1 = new ClamScanInfectedFile("test.txt", "Eicar");
            var file2 = new ClamScanInfectedFile("test.txt", "Eicar");
            Assert.Equal(file1, file2);
        }

        [Fact]
        public void ClamScanInfectedFile_Record_Inequality()
        {
            var file1 = new ClamScanInfectedFile("test.txt", "Eicar");
            var file2 = new ClamScanInfectedFile("other.txt", "Eicar");
            Assert.NotEqual(file1, file2);
        }

        #endregion

        #region ClamClient - Constructor and Defaults

        [Fact]
        public void ClamClient_StringConstructor_SetsProperties()
        {
            var client = new ClamClient("myserver", 9999);
            Assert.Equal("myserver", client.Server);
            Assert.Equal(9999, client.Port);
            Assert.Null(client.ServerIP);
        }

        [Fact]
        public void ClamClient_StringConstructor_DefaultPort()
        {
            var client = new ClamClient("myserver");
            Assert.Equal(3310, client.Port);
        }

        [Fact]
        public void ClamClient_IPConstructor_SetsProperties()
        {
            var ip = IPAddress.Parse("192.168.1.1");
            var client = new ClamClient(ip, 5555);
            Assert.Equal(ip, client.ServerIP);
            Assert.Equal(5555, client.Port);
            Assert.Null(client.Server);
        }

        [Fact]
        public void ClamClient_IPConstructor_DefaultPort()
        {
            var client = new ClamClient(IPAddress.Loopback);
            Assert.Equal(3310, client.Port);
        }

        [Fact]
        public void ClamClient_DefaultMaxChunkSize()
        {
            var client = new ClamClient("localhost");
            Assert.Equal(131072, client.MaxChunkSize);
        }

        [Fact]
        public void ClamClient_DefaultMaxStreamSize()
        {
            var client = new ClamClient("localhost");
            Assert.Equal(26214400, client.MaxStreamSize);
        }

        [Fact]
        public void ClamClient_MaxChunkSize_CanBeChanged()
        {
            var client = new ClamClient("localhost");
            client.MaxChunkSize = 65536;
            Assert.Equal(65536, client.MaxChunkSize);
        }

        [Fact]
        public void ClamClient_MaxStreamSize_CanBeChanged()
        {
            var client = new ClamClient("localhost");
            client.MaxStreamSize = 10_000_000;
            Assert.Equal(10_000_000, client.MaxStreamSize);
        }

        #endregion

        #region MaxStreamSizeExceededException

        [Fact]
        public void MaxStreamSizeExceededException_ContainsSize()
        {
            var ex = new MaxStreamSizeExceededException(1024);
            Assert.Contains("1024", ex.Message);
        }

        [Fact]
        public void MaxStreamSizeExceededException_IsException()
        {
            var ex = new MaxStreamSizeExceededException(5000);
            Assert.IsAssignableFrom<Exception>(ex);
        }

        #endregion

        #region Integration Tests (require ClamAV server)

        [Fact]
        public async Task TestSendAsyncTest()
        {
            string Eicartestcase = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            var client = new ClamClient("localhost");
            var result = await client.SendAndScanFileAsync(new MemoryStream(System.Text.Encoding.Default.GetBytes(Eicartestcase)));
            Assert.Equal(ClamScanResults.VirusDetected, result.Result);
        }

        [Fact]
        public async Task TestSendIPAsyncTest()
        {
            string Eicartestcase = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
            var client = new ClamClient(IPAddress.Parse("127.0.0.1"));
            var result = await client.SendAndScanFileAsync(new MemoryStream(System.Text.Encoding.Default.GetBytes(Eicartestcase)));
            Assert.Equal(ClamScanResults.VirusDetected, result.Result);
        }

        #endregion
    }
}
