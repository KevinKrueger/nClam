using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using NUnit.Framework;

namespace nClam.Tests
{
    [TestFixture]
    public class ClamScanResultTests
    {
        [Test]
        public void OK_Response()
        {
            var result = new ClamScanResult(@"C:\test.txt: OK");

            Assert.That(result.Result, Is.EqualTo(ClamScanResults.Clean));
        }

        [Test]
        public void Error_Response()
        {
            var result = new ClamScanResult("error");

            Assert.That(result.Result, Is.EqualTo(ClamScanResults.Error));
        }

        [Test]
        public void VirusDetected_Response()
        {
            var result = new ClamScanResult(@"\\?\C:\test.txt: Eicar-Test-Signature FOUND");

            Assert.That(result.Result, Is.EqualTo(ClamScanResults.VirusDetected));

            Assert.That(result.InfectedFiles, Has.Count.EqualTo(1));

            Assert.That(result.InfectedFiles[0].FileName, Is.EqualTo(@"\\?\C:\test.txt"));
            Assert.That(result.InfectedFiles[0].VirusName, Is.EqualTo(" Eicar-Test-Signature"));
        }

        [Test]
        public void Non_Matching()
        {
            var result = new ClamScanResult(Guid.NewGuid().ToString());

            Assert.That(result.Result, Is.EqualTo(ClamScanResults.Unknown));
        }

        [Test]
        public void Before_Tests()
        {
            Assert.That(
                ClamScanResult.ExtractFileName("test:test1:test2"),
                Is.EqualTo("test:test1")
                );

            Assert.That(
                ClamScanResult.ExtractFileName("test"),
                Is.EqualTo("")
                );

            Assert.That(
                ClamScanResult.ExtractFileName("test:test1"),
                Is.EqualTo("test")
                );
        }

        [Test]
        public void After_Tests()
        {
            //current released behavior to have initial space
            //(probably a bug)

            Assert.That(
                ClamScanResult.ExtractVirusName("test test1"),
                Is.EqualTo(" test1")
                );

            Assert.That(
                ClamScanResult.ExtractVirusName("test test1 test2"),
                Is.EqualTo(" test2")
                );

            Assert.That(
                ClamScanResult.ExtractVirusName("test"),
                Is.EqualTo("")
                );
        }

        #region ClamScanResult - Case Insensitivity

        [TestCase(@"C:\test.txt: OK")]
        [TestCase(@"C:\test.txt: ok")]
        [TestCase(@"C:\test.txt: Ok")]
        [TestCase(@"C:\test.txt: oK")]
        public void OK_Response_CaseInsensitive(string rawResult)
        {
            var result = new ClamScanResult(rawResult);
            Assert.That(result.Result, Is.EqualTo(ClamScanResults.Clean));
        }

        [TestCase("some error")]
        [TestCase("some ERROR")]
        [TestCase("some Error")]
        [TestCase("ERROR")]
        public void Error_Response_CaseInsensitive(string rawResult)
        {
            var result = new ClamScanResult(rawResult);
            Assert.That(result.Result, Is.EqualTo(ClamScanResults.Error));
        }

        [TestCase(@"C:\test.txt: Eicar-Test-Signature FOUND")]
        [TestCase(@"C:\test.txt: Eicar-Test-Signature found")]
        [TestCase(@"C:\test.txt: Eicar-Test-Signature Found")]
        public void VirusDetected_Response_CaseInsensitive(string rawResult)
        {
            var result = new ClamScanResult(rawResult);
            Assert.That(result.Result, Is.EqualTo(ClamScanResults.VirusDetected));
        }

        #endregion

        #region ClamScanResult - RawResult and ToString

        [Test]
        public void RawResult_IsPreserved()
        {
            var raw = @"C:\test.txt: OK";
            var result = new ClamScanResult(raw);
            Assert.That(result.RawResult, Is.EqualTo(raw));
        }

        [Test]
        public void ToString_ReturnsRawResult()
        {
            var raw = @"C:\test.txt: Eicar-Test-Signature FOUND";
            var result = new ClamScanResult(raw);
            Assert.That(result.ToString(), Is.EqualTo(raw));
        }

        #endregion

        #region ClamScanResult - InfectedFiles null checks

        [Test]
        public void Clean_Result_InfectedFiles_IsNull()
        {
            var result = new ClamScanResult(@"C:\test.txt: OK");
            Assert.That(result.Result, Is.EqualTo(ClamScanResults.Clean));
            Assert.That(result.InfectedFiles, Is.Null);
        }

        [Test]
        public void Error_Result_InfectedFiles_IsNull()
        {
            var result = new ClamScanResult("some error");
            Assert.That(result.Result, Is.EqualTo(ClamScanResults.Error));
            Assert.That(result.InfectedFiles, Is.Null);
        }

        [Test]
        public void Unknown_Result_InfectedFiles_IsNull()
        {
            var result = new ClamScanResult("something completely unrecognized");
            Assert.That(result.Result, Is.EqualTo(ClamScanResults.Unknown));
            Assert.That(result.InfectedFiles, Is.Null);
        }

        #endregion

        #region ClamScanResult - Multiple infected files

        [Test]
        public void VirusDetected_MultipleFiles()
        {
            var raw = "/files/test1.exe: Win.Trojan.Agent FOUND\n/files/test2.doc: Doc.Malware.Macro FOUND";
            var result = new ClamScanResult(raw);

            Assert.That(result.Result, Is.EqualTo(ClamScanResults.VirusDetected));
            Assert.That(result.InfectedFiles, Is.Not.Null);
            Assert.That(result.InfectedFiles, Has.Count.EqualTo(2));

            Assert.That(result.InfectedFiles[0].FileName, Is.EqualTo("/files/test1.exe"));
            Assert.That(result.InfectedFiles[0].VirusName, Is.EqualTo(" Win.Trojan.Agent"));

            Assert.That(result.InfectedFiles[1].FileName, Is.EqualTo("/files/test2.doc"));
            Assert.That(result.InfectedFiles[1].VirusName, Is.EqualTo(" Doc.Malware.Macro"));
        }

        [Test]
        public void VirusDetected_StreamResult()
        {
            var result = new ClamScanResult("stream: Win.Test.EICAR_HDB-1 FOUND");

            Assert.That(result.Result, Is.EqualTo(ClamScanResults.VirusDetected));
            Assert.That(result.InfectedFiles, Is.Not.Null);
            Assert.That(result.InfectedFiles, Has.Count.EqualTo(1));
            Assert.That(result.InfectedFiles[0].FileName, Is.EqualTo("stream"));
            Assert.That(result.InfectedFiles[0].VirusName, Is.EqualTo(" Win.Test.EICAR_HDB-1"));
        }

        #endregion

        #region ClamScanResult - Edge cases

        [Test]
        public void EmptyString_ReturnsUnknown()
        {
            var result = new ClamScanResult("");
            Assert.That(result.Result, Is.EqualTo(ClamScanResults.Unknown));
            Assert.That(result.InfectedFiles, Is.Null);
        }

        [Test]
        public void WhitespaceOnly_ReturnsUnknown()
        {
            var result = new ClamScanResult("   ");
            Assert.That(result.Result, Is.EqualTo(ClamScanResults.Unknown));
        }

        [Test]
        public void JustOK_ReturnsClean()
        {
            var result = new ClamScanResult("OK");
            Assert.That(result.Result, Is.EqualTo(ClamScanResults.Clean));
        }

        [Test]
        public void JustFOUND_ReturnsVirusDetected()
        {
            var result = new ClamScanResult("FOUND");
            Assert.That(result.Result, Is.EqualTo(ClamScanResults.VirusDetected));
        }

        #endregion

        #region ExtractFileName - Edge cases

        [Test]
        public void ExtractFileName_EmptyString_ReturnsEmpty()
        {
            Assert.That(ClamScanResult.ExtractFileName(""), Is.EqualTo(""));
        }

        [Test]
        public void ExtractFileName_ColonAtStart_ReturnsEmpty()
        {
            Assert.That(ClamScanResult.ExtractFileName(":value"), Is.EqualTo(""));
        }

        [Test]
        public void ExtractFileName_UncPath()
        {
            Assert.That(
                ClamScanResult.ExtractFileName(@"\\server\share\file.txt: virus"),
                Is.EqualTo(@"\\server\share\file.txt")
                );
        }

        [Test]
        public void ExtractFileName_WindowsPathWithDrive()
        {
            Assert.That(
                ClamScanResult.ExtractFileName(@"C:\Users\test\file.txt: virus"),
                Is.EqualTo(@"C:\Users\test\file.txt")
                );
        }

        #endregion

        #region ExtractVirusName - Edge cases

        [Test]
        public void ExtractVirusName_EmptyString_ReturnsEmpty()
        {
            Assert.That(ClamScanResult.ExtractVirusName(""), Is.EqualTo(""));
        }

        [Test]
        public void ExtractVirusName_NoSpaces_ReturnsEmpty()
        {
            Assert.That(ClamScanResult.ExtractVirusName("nospaces"), Is.EqualTo(""));
        }

        [Test]
        public void ExtractVirusName_SpaceAtStart_ReturnsEmpty()
        {
            // Space at index 0 is not > 0, so returns empty
            Assert.That(ClamScanResult.ExtractVirusName(" virusname"), Is.EqualTo(""));
        }

        #endregion

        #region ClamScanInfectedFile

        [Test]
        public void ClamScanInfectedFile_Properties_SetCorrectly()
        {
            var file = new ClamScanInfectedFile("test.txt", "Eicar");
            Assert.That(file.FileName, Is.EqualTo("test.txt"));
            Assert.That(file.VirusName, Is.EqualTo("Eicar"));
        }

        [Test]
        public void ClamScanInfectedFile_Record_Equality()
        {
            var file1 = new ClamScanInfectedFile("test.txt", "Eicar");
            var file2 = new ClamScanInfectedFile("test.txt", "Eicar");
            Assert.That(file1, Is.EqualTo(file2));
        }

        [Test]
        public void ClamScanInfectedFile_Record_Inequality()
        {
            var file1 = new ClamScanInfectedFile("test.txt", "Eicar");
            var file2 = new ClamScanInfectedFile("other.txt", "Eicar");
            Assert.That(file1, Is.Not.EqualTo(file2));
        }

        #endregion

        #region ClamClient - Constructor and Defaults

        [Test]
        public void ClamClient_StringConstructor_SetsProperties()
        {
            var client = new ClamClient("myserver", 9999);
            Assert.That(client.Server, Is.EqualTo("myserver"));
            Assert.That(client.Port, Is.EqualTo(9999));
            Assert.That(client.ServerIP, Is.Null);
        }

        [Test]
        public void ClamClient_StringConstructor_DefaultPort()
        {
            var client = new ClamClient("myserver");
            Assert.That(client.Port, Is.EqualTo(3310));
        }

        [Test]
        public void ClamClient_IPConstructor_SetsProperties()
        {
            var ip = IPAddress.Parse("192.168.1.1");
            var client = new ClamClient(ip, 5555);
            Assert.That(client.ServerIP, Is.EqualTo(ip));
            Assert.That(client.Port, Is.EqualTo(5555));
            Assert.That(client.Server, Is.Null);
        }

        [Test]
        public void ClamClient_IPConstructor_DefaultPort()
        {
            var client = new ClamClient(IPAddress.Loopback);
            Assert.That(client.Port, Is.EqualTo(3310));
        }

        [Test]
        public void ClamClient_DefaultMaxChunkSize()
        {
            var client = new ClamClient("localhost");
            Assert.That(client.MaxChunkSize, Is.EqualTo(131072));
        }

        [Test]
        public void ClamClient_DefaultMaxStreamSize()
        {
            var client = new ClamClient("localhost");
            Assert.That(client.MaxStreamSize, Is.EqualTo(26214400));
        }

        [Test]
        public void ClamClient_MaxChunkSize_CanBeChanged()
        {
            var client = new ClamClient("localhost");
            client.MaxChunkSize = 65536;
            Assert.That(client.MaxChunkSize, Is.EqualTo(65536));
        }

        [Test]
        public void ClamClient_MaxStreamSize_CanBeChanged()
        {
            var client = new ClamClient("localhost");
            client.MaxStreamSize = 10_000_000;
            Assert.That(client.MaxStreamSize, Is.EqualTo(10_000_000));
        }

        [Test]
        public void ClamClient_StringConstructor_MaxStreamSize_SetsValue()
        {
            var client = new ClamClient("localhost", maxStreamSize: 104_857_600);
            Assert.That(client.MaxStreamSize, Is.EqualTo(104_857_600));
        }

        [Test]
        public void ClamClient_StringConstructor_MaxStreamSize_DefaultWhenNull()
        {
            var client = new ClamClient("localhost");
            Assert.That(client.MaxStreamSize, Is.EqualTo(26214400));
        }

        [Test]
        public void ClamClient_IPConstructor_MaxStreamSize_SetsValue()
        {
            var client = new ClamClient(IPAddress.Loopback, maxStreamSize: 104_857_600);
            Assert.That(client.MaxStreamSize, Is.EqualTo(104_857_600));
        }

        [Test]
        public void ClamClient_IPConstructor_MaxStreamSize_DefaultWhenNull()
        {
            var client = new ClamClient(IPAddress.Loopback);
            Assert.That(client.MaxStreamSize, Is.EqualTo(26214400));
        }

        #endregion

        #region MaxStreamSizeExceededException

        [Test]
        public void MaxStreamSizeExceededException_ContainsSize()
        {
            var ex = new MaxStreamSizeExceededException(1024);
            Assert.That(ex.Message, Does.Contain("1024"));
        }

        [Test]
        public void MaxStreamSizeExceededException_IsException()
        {
            var ex = new MaxStreamSizeExceededException(5000);
            Assert.That(ex, Is.AssignableTo<Exception>());
        }

        #endregion
    }
}
