using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using NUnit.Framework;
using VirusScanner.ClamAV;
using VirusScanner.Core;

namespace VirusScanner.Tests
{
    [TestFixture]
    public class ClamScanResultTests
    {
        [Test]
        public void OK_Response()
        {
            var result = new ClamAvScanResult(@"C:\test.txt: OK");

            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
        }

        [Test]
        public void Error_Response()
        {
            var result = new ClamAvScanResult("error");

            Assert.That(result.Status, Is.EqualTo(ScanStatus.Error));
        }

        [Test]
        public void VirusDetected_Response()
        {
            var result = new ClamAvScanResult(@"\\?\C:\test.txt: Eicar-Test-Signature FOUND");

            Assert.That(result.Status, Is.EqualTo(ScanStatus.VirusDetected));

            Assert.That(result.InfectedFiles, Has.Count.EqualTo(1));

            Assert.That(result.InfectedFiles[0].FileName, Is.EqualTo(@"\\?\C:\test.txt"));
            Assert.That(result.InfectedFiles[0].VirusName, Is.EqualTo(" Eicar-Test-Signature"));
        }

        [Test]
        public void Non_Matching()
        {
            var result = new ClamAvScanResult(Guid.NewGuid().ToString());

            Assert.That(result.Status, Is.EqualTo(ScanStatus.Unknown));
        }

        [Test]
        public void Before_Tests()
        {
            Assert.That(
                ClamAvScanResult.ExtractFileName("test:test1:test2"),
                Is.EqualTo("test:test1")
                );

            Assert.That(
                ClamAvScanResult.ExtractFileName("test"),
                Is.EqualTo("")
                );

            Assert.That(
                ClamAvScanResult.ExtractFileName("test:test1"),
                Is.EqualTo("test")
                );
        }

        [Test]
        public void After_Tests()
        {
            //current released behavior to have initial space
            //(probably a bug)

            Assert.That(
                ClamAvScanResult.ExtractVirusName("test test1"),
                Is.EqualTo(" test1")
                );

            Assert.That(
                ClamAvScanResult.ExtractVirusName("test test1 test2"),
                Is.EqualTo(" test2")
                );

            Assert.That(
                ClamAvScanResult.ExtractVirusName("test"),
                Is.EqualTo("")
                );
        }

        #region ClamAvScanResult - Case Insensitivity

        [TestCase(@"C:\test.txt: OK")]
        [TestCase(@"C:\test.txt: ok")]
        [TestCase(@"C:\test.txt: Ok")]
        [TestCase(@"C:\test.txt: oK")]
        public void OK_Response_CaseInsensitive(string rawResult)
        {
            var result = new ClamAvScanResult(rawResult);
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
        }

        [TestCase("some error")]
        [TestCase("some ERROR")]
        [TestCase("some Error")]
        [TestCase("ERROR")]
        public void Error_Response_CaseInsensitive(string rawResult)
        {
            var result = new ClamAvScanResult(rawResult);
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Error));
        }

        [TestCase(@"C:\test.txt: Eicar-Test-Signature FOUND")]
        [TestCase(@"C:\test.txt: Eicar-Test-Signature found")]
        [TestCase(@"C:\test.txt: Eicar-Test-Signature Found")]
        public void VirusDetected_Response_CaseInsensitive(string rawResult)
        {
            var result = new ClamAvScanResult(rawResult);
            Assert.That(result.Status, Is.EqualTo(ScanStatus.VirusDetected));
        }

        #endregion

        #region ClamAvScanResult - RawResult and ToString

        [Test]
        public void RawResult_IsPreserved()
        {
            var raw = @"C:\test.txt: OK";
            var result = new ClamAvScanResult(raw);
            Assert.That(result.RawResult, Is.EqualTo(raw));
        }

        [Test]
        public void ToString_ReturnsRawResult()
        {
            var raw = @"C:\test.txt: Eicar-Test-Signature FOUND";
            var result = new ClamAvScanResult(raw);
            Assert.That(result.ToString(), Is.EqualTo(raw));
        }

        #endregion

        #region ClamAvScanResult - InfectedFiles null checks

        [Test]
        public void Clean_Result_InfectedFiles_IsNull()
        {
            var result = new ClamAvScanResult(@"C:\test.txt: OK");
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
            Assert.That(result.InfectedFiles, Is.Null);
        }

        [Test]
        public void Error_Result_InfectedFiles_IsNull()
        {
            var result = new ClamAvScanResult("some error");
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Error));
            Assert.That(result.InfectedFiles, Is.Null);
        }

        [Test]
        public void Unknown_Result_InfectedFiles_IsNull()
        {
            var result = new ClamAvScanResult("something completely unrecognized");
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Unknown));
            Assert.That(result.InfectedFiles, Is.Null);
        }

        #endregion

        #region ClamAvScanResult - Multiple infected files

        [Test]
        public void VirusDetected_MultipleFiles()
        {
            var raw = "/files/test1.exe: Win.Trojan.Agent FOUND\n/files/test2.doc: Doc.Malware.Macro FOUND";
            var result = new ClamAvScanResult(raw);

            Assert.That(result.Status, Is.EqualTo(ScanStatus.VirusDetected));
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
            var result = new ClamAvScanResult("stream: Win.Test.EICAR_HDB-1 FOUND");

            Assert.That(result.Status, Is.EqualTo(ScanStatus.VirusDetected));
            Assert.That(result.InfectedFiles, Is.Not.Null);
            Assert.That(result.InfectedFiles, Has.Count.EqualTo(1));
            Assert.That(result.InfectedFiles[0].FileName, Is.EqualTo("stream"));
            Assert.That(result.InfectedFiles[0].VirusName, Is.EqualTo(" Win.Test.EICAR_HDB-1"));
        }

        #endregion

        #region ClamAvScanResult - Edge cases

        [Test]
        public void EmptyString_ReturnsUnknown()
        {
            var result = new ClamAvScanResult("");
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Unknown));
            Assert.That(result.InfectedFiles, Is.Null);
        }

        [Test]
        public void WhitespaceOnly_ReturnsUnknown()
        {
            var result = new ClamAvScanResult("   ");
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Unknown));
        }

        [Test]
        public void JustOK_ReturnsClean()
        {
            var result = new ClamAvScanResult("OK");
            Assert.That(result.Status, Is.EqualTo(ScanStatus.Clean));
        }

        [Test]
        public void JustFOUND_ReturnsVirusDetected()
        {
            var result = new ClamAvScanResult("FOUND");
            Assert.That(result.Status, Is.EqualTo(ScanStatus.VirusDetected));
        }

        #endregion

        #region ExtractFileName - Edge cases

        [Test]
        public void ExtractFileName_EmptyString_ReturnsEmpty()
        {
            Assert.That(ClamAvScanResult.ExtractFileName(""), Is.EqualTo(""));
        }

        [Test]
        public void ExtractFileName_ColonAtStart_ReturnsEmpty()
        {
            Assert.That(ClamAvScanResult.ExtractFileName(":value"), Is.EqualTo(""));
        }

        [Test]
        public void ExtractFileName_UncPath()
        {
            Assert.That(
                ClamAvScanResult.ExtractFileName(@"\\server\share\file.txt: virus"),
                Is.EqualTo(@"\\server\share\file.txt")
                );
        }

        [Test]
        public void ExtractFileName_WindowsPathWithDrive()
        {
            Assert.That(
                ClamAvScanResult.ExtractFileName(@"C:\Users\test\file.txt: virus"),
                Is.EqualTo(@"C:\Users\test\file.txt")
                );
        }

        #endregion

        #region ExtractVirusName - Edge cases

        [Test]
        public void ExtractVirusName_EmptyString_ReturnsEmpty()
        {
            Assert.That(ClamAvScanResult.ExtractVirusName(""), Is.EqualTo(""));
        }

        [Test]
        public void ExtractVirusName_NoSpaces_ReturnsEmpty()
        {
            Assert.That(ClamAvScanResult.ExtractVirusName("nospaces"), Is.EqualTo(""));
        }

        [Test]
        public void ExtractVirusName_SpaceAtStart_ReturnsEmpty()
        {
            // Space at index 0 is not > 0, so returns empty
            Assert.That(ClamAvScanResult.ExtractVirusName(" virusname"), Is.EqualTo(""));
        }

        #endregion

        #region InfectedFile

        [Test]
        public void ClamScanInfectedFile_Properties_SetCorrectly()
        {
            var file = new InfectedFile("test.txt", "Eicar");
            Assert.That(file.FileName, Is.EqualTo("test.txt"));
            Assert.That(file.VirusName, Is.EqualTo("Eicar"));
        }

        [Test]
        public void ClamScanInfectedFile_Record_Equality()
        {
            var file1 = new InfectedFile("test.txt", "Eicar");
            var file2 = new InfectedFile("test.txt", "Eicar");
            Assert.That(file1, Is.EqualTo(file2));
        }

        [Test]
        public void ClamScanInfectedFile_Record_Inequality()
        {
            var file1 = new InfectedFile("test.txt", "Eicar");
            var file2 = new InfectedFile("other.txt", "Eicar");
            Assert.That(file1, Is.Not.EqualTo(file2));
        }

        #endregion

        #region ClamAvScanner - Constructor and Defaults

        [Test]
        public void ClamClient_StringConstructor_SetsProperties()
        {
            var client = new ClamAvScanner("myserver", 9999);
            Assert.That(client.Server, Is.EqualTo("myserver"));
            Assert.That(client.Port, Is.EqualTo(9999));
            Assert.That(client.ServerIP, Is.Null);
        }

        [Test]
        public void ClamClient_StringConstructor_DefaultPort()
        {
            var client = new ClamAvScanner("myserver");
            Assert.That(client.Port, Is.EqualTo(3310));
        }

        [Test]
        public void ClamClient_IPConstructor_SetsProperties()
        {
            var ip = IPAddress.Parse("192.168.1.1");
            var client = new ClamAvScanner(ip, 5555);
            Assert.That(client.ServerIP, Is.EqualTo(ip));
            Assert.That(client.Port, Is.EqualTo(5555));
            Assert.That(client.Server, Is.Null);
        }

        [Test]
        public void ClamClient_IPConstructor_DefaultPort()
        {
            var client = new ClamAvScanner(IPAddress.Loopback);
            Assert.That(client.Port, Is.EqualTo(3310));
        }

        [Test]
        public void ClamClient_DefaultMaxChunkSize()
        {
            var client = new ClamAvScanner("localhost");
            Assert.That(client.MaxChunkSize, Is.EqualTo(131072));
        }

        [Test]
        public void ClamClient_DefaultMaxStreamSize()
        {
            var client = new ClamAvScanner("localhost");
            Assert.That(client.MaxStreamSize, Is.EqualTo(26214400));
        }

        [Test]
        public void ClamClient_MaxChunkSize_CanBeChanged()
        {
            var client = new ClamAvScanner("localhost");
            client.MaxChunkSize = 65536;
            Assert.That(client.MaxChunkSize, Is.EqualTo(65536));
        }

        [Test]
        public void ClamClient_MaxStreamSize_CanBeChanged()
        {
            var client = new ClamAvScanner("localhost");
            client.MaxStreamSize = 10_000_000;
            Assert.That(client.MaxStreamSize, Is.EqualTo(10_000_000));
        }

        [Test]
        public void ClamClient_StringConstructor_MaxStreamSize_SetsValue()
        {
            var client = new ClamAvScanner("localhost", maxStreamSize: 104_857_600);
            Assert.That(client.MaxStreamSize, Is.EqualTo(104_857_600));
        }

        [Test]
        public void ClamClient_StringConstructor_MaxStreamSize_DefaultWhenNull()
        {
            var client = new ClamAvScanner("localhost");
            Assert.That(client.MaxStreamSize, Is.EqualTo(26214400));
        }

        [Test]
        public void ClamClient_IPConstructor_MaxStreamSize_SetsValue()
        {
            var client = new ClamAvScanner(IPAddress.Loopback, maxStreamSize: 104_857_600);
            Assert.That(client.MaxStreamSize, Is.EqualTo(104_857_600));
        }

        [Test]
        public void ClamClient_IPConstructor_MaxStreamSize_DefaultWhenNull()
        {
            var client = new ClamAvScanner(IPAddress.Loopback);
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

