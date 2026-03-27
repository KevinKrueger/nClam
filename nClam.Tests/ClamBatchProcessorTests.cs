using System.IO;
using System.Linq;
using System.Threading.Tasks;
using NUnit.Framework;

namespace nClam.Tests
{
    [TestFixture]
    public class ClamBatchProcessorTests
    {
        private ClamClient _clamClient = null!;
        
        [SetUp]
        public void Setup()
        {
            _clamClient = new ClamClient("localhost", 3310);
        }

        [Test]
        public void ClamBatchProcessor_Constructor_SetsPropertiesWithTimeout()
        {
            var processor = new ClamBatchProcessor(_clamClient, 8, 15);

            Assert.That(processor, Is.Not.Null);
        }

        [Test]
        public void ClamBatchProcessor_Constructor_SetsProperties()
        {
            var processor = new ClamBatchProcessor(_clamClient, 8);

            Assert.That(processor, Is.Not.Null);
        }

        [Test]
        public void ClamBatchScanResult_Properties_WorkCorrectly()
        {
            var result = new ClamBatchScanResult
            {
                FilePath = @"C:\test.exe",
                FileName = "test.exe",
                FileSize = 1024,
                Success = true,
                ScanResult = new ClamScanResult("stream: OK")
            };

            Assert.That(result.IsClean, Is.True);
            Assert.That(result.IsInfected, Is.False);
            Assert.That(result.HasError, Is.False);
        }

        [Test]
        public void ClamBatchProgress_PercentageComplete_CalculatesCorrectly()
        {
            var progress = new ClamBatchProgress
            {
                TotalFiles = 100,
                CompletedFiles = 25
            };

            Assert.That(progress.PercentageComplete, Is.EqualTo(25.0));
        }

        [Test]
        public void ClamBatchUtilities_CommonExtensions_ArePopulated()
        {
            Assert.That(ClamBatchUtilities.CommonExtensions.Executable, Is.Not.Empty);
            Assert.That(ClamBatchUtilities.CommonExtensions.Document, Is.Not.Empty);
            Assert.That(ClamBatchUtilities.CommonExtensions.Archive, Is.Not.Empty);
            Assert.That(ClamBatchUtilities.CommonExtensions.HighRisk, Is.Not.Empty);
            
            Assert.That(ClamBatchUtilities.CommonExtensions.Executable, Contains.Item(".exe"));
            Assert.That(ClamBatchUtilities.CommonExtensions.Document, Contains.Item(".pdf"));
            Assert.That(ClamBatchUtilities.CommonExtensions.Archive, Contains.Item(".zip"));
        }

        [Test]
        public void ClamBatchUtilities_GetStatistics_WorksWithEmptyResults()
        {
            var emptyResults = System.Array.Empty<ClamBatchScanResult>();
            var stats = ClamBatchUtilities.GetStatistics(emptyResults);

            Assert.That(stats.TotalFiles, Is.EqualTo(0));
            Assert.That(stats.CleanFiles, Is.EqualTo(0));
            Assert.That(stats.InfectedFiles, Is.EqualTo(0));
            Assert.That(stats.ErrorFiles, Is.EqualTo(0));
            Assert.That(stats.InfectionRate, Is.EqualTo(0));
        }

        [Test]
        public void ClamBatchUtilities_FilterMethods_WorkCorrectly()
        {
            var results = new[]
            {
                new ClamBatchScanResult 
                { 
                    Success = true, 
                    ScanResult = new ClamScanResult("stream: OK") 
                },
                new ClamBatchScanResult 
                { 
                    Success = true, 
                    ScanResult = new ClamScanResult("Win.Test.EICAR_HDB-1 FOUND") 
                },
                new ClamBatchScanResult 
                { 
                    Success = false, 
                    ErrorMessage = "File not found" 
                }
            };

            var clean = ClamBatchUtilities.GetCleanFiles(results);
            var infected = ClamBatchUtilities.GetInfectedFiles(results);
            var errors = ClamBatchUtilities.GetErrorFiles(results);

            Assert.That(clean.Count(), Is.EqualTo(1));
            Assert.That(infected.Count(), Is.EqualTo(1));
            Assert.That(errors.Count(), Is.EqualTo(1));
        }

        [Test]
        public void ClamClientBatchExtensions_CreateBatchProcessor_WithTimeout_Works()
        {
            var processor = _clamClient.CreateBatchProcessor(6, 20);
            Assert.That(processor, Is.Not.Null);
        }

        [Test]
        public void ClamClientBatchExtensions_CreateBatchProcessor_Works()
        {
            var processor = _clamClient.CreateBatchProcessor(6);
            Assert.That(processor, Is.Not.Null);
        }
    }
}