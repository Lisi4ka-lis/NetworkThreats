using System.Security.Cryptography;
using System.Text;

namespace NetworkThreats.Tests;

public class FileAnalyzerServiceTests
{
    private static FileAnalyzerService Build(
        KnownMaliciousHash? sha256Hit  = null,
        KnownMaliciousHash? md5Hit     = null,
        IEnumerable<FileHeuristic>? heuristics = null)
    {
        var hashRepo = new Mock<IKnownHashRepository>();
        hashRepo.Setup(r => r.FindBySha256Async(It.IsAny<string>())).ReturnsAsync(sha256Hit);
        hashRepo.Setup(r => r.FindByMd5Async(It.IsAny<string>())).ReturnsAsync(md5Hit);

        var heurRepo = new Mock<IFileHeuristicRepository>();
        heurRepo.Setup(r => r.GetAllAsync()).ReturnsAsync(heuristics ?? []);

        return new FileAnalyzerService(hashRepo.Object, heurRepo.Object);
    }

    private static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);

    private static FileHeuristic StringRule(string pattern, string risk = "medium") =>
        new() { Id = 1, Pattern = pattern, PatternType = "string", Description = "test rule", Category = "malware", RiskLevel = risk };

    private static FileHeuristic RegexRule(string pattern, string risk = "medium") =>
        new() { Id = 2, Pattern = pattern, PatternType = "regex", Description = "test rule", Category = "execution", RiskLevel = risk };

    [Fact]
    public async Task KnownSha256_IsKnownMalicious_True()
    {
        var known = new KnownMaliciousHash { Id = 1, Sha256 = "aaa", ThreatName = "Trojan", Severity = "critical" };
        var svc = Build(sha256Hit: known);

        var result = await svc.AnalyzeFileAsync("test.exe", Bytes("content"));

        Assert.True(result.IsKnownMalicious);
        Assert.NotNull(result.KnownHash);
        Assert.Equal("critical", result.OverallRisk);
        Assert.True(result.ThreatDetected);
    }

    [Fact]
    public async Task Md5Fallback_WhenSha256NotFound()
    {
        var known = new KnownMaliciousHash { Id = 1, Sha256 = "xxx", ThreatName = "Virus", Severity = "high" };
        var svc = Build(sha256Hit: null, md5Hit: known);

        var result = await svc.AnalyzeFileAsync("file.exe", Bytes("data"));

        Assert.True(result.IsKnownMalicious);
        Assert.Equal("high", result.OverallRisk);
    }

    [Fact]
    public async Task CleanFile_NoThreats_RiskNone()
    {
        var svc = Build();
        var result = await svc.AnalyzeFileAsync("clean.txt", Bytes("hello world"));
        Assert.False(result.ThreatDetected);
        Assert.False(result.IsKnownMalicious);
        Assert.Equal("none", result.OverallRisk);
        Assert.Empty(result.HeuristicFindings);
    }

    [Fact]
    public async Task StringHeuristicMatch_DetectsThreat()
    {
        var svc = Build(heuristics: [StringRule("CreateRemoteThread", "high")]);

        var result = await svc.AnalyzeFileAsync("suspect.dll", Bytes("call to CreateRemoteThread here"));

        Assert.True(result.ThreatDetected);
        Assert.Single(result.HeuristicFindings);
        Assert.Equal("high", result.OverallRisk);
    }

    [Fact]
    public async Task RegexHeuristicMatch_DetectsThreat()
    {
        var svc = Build(heuristics: [RegexRule(@"cmd\.exe\s+/c", "medium")]);

        var result = await svc.AnalyzeFileAsync("script.bat", Bytes("Runs cmd.exe /c whoami to enumerate"));

        Assert.True(result.ThreatDetected);
        Assert.Equal("medium", result.OverallRisk);
    }

    [Fact]
    public async Task Sha256_ComputedCorrectly()
    {
        var data = Bytes("unit test data");
        var expected = Convert.ToHexString(SHA256.HashData(data)).ToLower();
        var svc = Build();

        var result = await svc.AnalyzeFileAsync("file.bin", data);

        Assert.Equal(expected, result.Sha256);
    }

    [Fact]
    public async Task Md5_ComputedCorrectly()
    {
        var data = Bytes("unit test data");
        var expected = Convert.ToHexString(MD5.HashData(data)).ToLower();
        var svc = Build();

        var result = await svc.AnalyzeFileAsync("file.bin", data);

        Assert.Equal(expected, result.Md5);
    }

    [Fact]
    public async Task ExtractsReadableStrings_FromContent()
    {
        var svc = Build();
        var result = await svc.AnalyzeFileAsync("file.exe", Bytes("STUB Hello World padding"));
        Assert.NotEmpty(result.ExtractedStrings);
        Assert.Contains(result.ExtractedStrings, s => s.Contains("Hello"));
    }

    [Fact]
    public async Task BinaryContent_ShortChunks_NotExtracted()
    {
        var data = new byte[] { 0x00, 0x41, 0x42, 0x00, 0x00 };
        var svc = Build();
        var result = await svc.AnalyzeFileAsync("file.bin", data);
        Assert.DoesNotContain(result.ExtractedStrings, s => s.Length < 4);
    }

    [Fact]
    public async Task RiskLevel_CriticalBeatsHigh()
    {
        var rules = new[]
        {
            new FileHeuristic { Id = 1, Pattern = "evil",    PatternType = "string", Description = "d", Category = "c", RiskLevel = "high" },
            new FileHeuristic { Id = 2, Pattern = "rootkit", PatternType = "string", Description = "d", Category = "c", RiskLevel = "critical" }
        };
        var svc = Build(heuristics: rules);

        var result = await svc.AnalyzeFileAsync("f.bin", Bytes("evil rootkit found"));

        Assert.Equal("critical", result.OverallRisk);
    }

    [Fact]
    public async Task FileMetadata_PopulatedCorrectly()
    {
        var data = Bytes("test content");
        var svc = Build();

        var result = await svc.AnalyzeFileAsync("report.pdf", data);

        Assert.Equal("report.pdf", result.FileName);
        Assert.Equal(data.Length, result.FileSize);
        Assert.Equal(".pdf", result.FileExtension);
    }

    [Fact]
    public async Task ExtractedStrings_LimitedTo100()
    {
        var sb = new StringBuilder();
        for (int i = 0; i < 200; i++)
            sb.Append($"LONGTOKEN{i:D3} ");
        var svc = Build();

        var result = await svc.AnalyzeFileAsync("big.bin", Bytes(sb.ToString()));

        Assert.True(result.ExtractedStrings.Count <= 100);
    }
}
