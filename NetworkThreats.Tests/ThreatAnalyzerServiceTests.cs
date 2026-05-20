namespace NetworkThreats.Tests;

public class ThreatAnalyzerServiceTests
{
    private static (ThreatAnalyzerService Svc, Mock<IIndicatorRepository> Repo) Setup(
        IEnumerable<ThreatIndicator> indicators)
    {
        var mock = new Mock<IIndicatorRepository>();
        mock.Setup(r => r.GetAllWithThreatsAsync()).ReturnsAsync(indicators);
        return (new ThreatAnalyzerService(mock.Object), mock);
    }

    private static ThreatIndicator Indicator(
        int threatId, string type, string pattern,
        string confidence = "medium", string severity = "high", int? id = null)
    {
        var cat    = new ThreatCategory { Id = 1, Name = "TestCat" };
        var threat = new Threat
        {
            Id               = threatId,
            Name             = $"Threat{threatId}",
            Severity         = severity,
            CategoryId       = 1,
            ShortDescription = "desc",
            Category         = cat
        };
        return new ThreatIndicator
        {
            Id            = id ?? threatId * 10,
            ThreatId      = threatId,
            IndicatorType = type,
            Pattern       = pattern,
            Confidence    = confidence,
            Threat        = threat
        };
    }

    [Fact]
    public async Task EmptyInput_ReturnsNoThreats()
    {
        var (svc, _) = Setup([Indicator(1, "keyword", "malware")]);
        var result = await svc.AnalyzeAsync("");
        Assert.False(result.ThreatDetected);
        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task WhitespaceInput_ReturnsNoThreats()
    {
        var (svc, _) = Setup([Indicator(1, "keyword", "malware")]);
        var result = await svc.AnalyzeAsync("   ");
        Assert.False(result.ThreatDetected);
        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task KeywordMatch_DetectsThreat()
    {
        var (svc, _) = Setup([Indicator(1, "keyword", "sql injection")]);
        var result = await svc.AnalyzeAsync("User entered sql injection payload");
        Assert.True(result.ThreatDetected);
        Assert.Single(result.Matches);
        Assert.Equal("Threat1", result.Matches[0].Name);
    }

    [Fact]
    public async Task KeywordMatch_IsCaseInsensitive()
    {
        var (svc, _) = Setup([Indicator(1, "keyword", "MALWARE")]);
        var result = await svc.AnalyzeAsync("system infected with malware");
        Assert.True(result.ThreatDetected);
    }

    [Fact]
    public async Task RegexMatch_DetectsThreat()
    {
        var (svc, _) = Setup([Indicator(1, "regex", @"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")]);
        var result = await svc.AnalyzeAsync("Connection from 192.168.1.1 detected");
        Assert.True(result.ThreatDetected);
    }

    [Fact]
    public async Task NoMatch_ReturnsNoThreats()
    {
        var (svc, _) = Setup([Indicator(1, "keyword", "ransomware")]);
        var result = await svc.AnalyzeAsync("Everything is fine, no issues here");
        Assert.False(result.ThreatDetected);
        Assert.Empty(result.Matches);
    }

    [Fact]
    public async Task InvalidRegex_DoesNotThrow()
    {
        var (svc, _) = Setup([Indicator(1, "regex", "[invalid(regex")]);
        var result = await svc.AnalyzeAsync("some text with content");
        Assert.False(result.ThreatDetected);
    }

    [Fact]
    public async Task MultipleIndicators_SameThreat_GroupedIntoOneMatch()
    {
        var ind1 = Indicator(1, "keyword", "keylogger", id: 10);
        var ind2 = Indicator(1, "keyword", "keystroke", id: 11);
        var (svc, _) = Setup([ind1, ind2]);

        var result = await svc.AnalyzeAsync("keylogger captures keystroke data");

        Assert.Single(result.Matches);
        Assert.Equal(2, result.Matches[0].Indicators.Count);
    }

    [Fact]
    public async Task HighConfidenceIndicator_SetsOverallConfidenceHigh()
    {
        var ind1 = Indicator(1, "keyword", "exploit",   confidence: "low",  id: 10);
        var ind2 = Indicator(1, "keyword", "shellcode", confidence: "high", id: 11);
        var (svc, _) = Setup([ind1, ind2]);

        var result = await svc.AnalyzeAsync("exploit with shellcode inside");

        Assert.Equal("high", result.Matches[0].OverallConfidence);
    }

    [Fact]
    public async Task MediumConfidence_WhenNoHighPresent()
    {
        var ind1 = Indicator(1, "keyword", "exploit",   confidence: "low",    id: 10);
        var ind2 = Indicator(1, "keyword", "shellcode", confidence: "medium", id: 11);
        var (svc, _) = Setup([ind1, ind2]);

        var result = await svc.AnalyzeAsync("exploit with shellcode inside");

        Assert.Equal("medium", result.Matches[0].OverallConfidence);
    }

    [Fact]
    public async Task Results_OrderedByConfidenceDescFirst()
    {
        var lowConf  = Indicator(1, "keyword", "lowkey",  confidence: "low",  severity: "critical", id: 10);
        var highConf = Indicator(2, "keyword", "highkey", confidence: "high", severity: "low",      id: 20);
        var (svc, _) = Setup([lowConf, highConf]);

        var result = await svc.AnalyzeAsync("lowkey and highkey both here");

        Assert.Equal(2, result.Matches.Count);
        Assert.Equal(2, result.Matches[0].ThreatId);
    }

    [Fact]
    public async Task Results_OrderedBySeverityWhenSameConfidence()
    {
        var lowSev  = Indicator(1, "keyword", "alpha", confidence: "medium", severity: "low",      id: 10);
        var highSev = Indicator(2, "keyword", "beta",  confidence: "medium", severity: "critical", id: 20);
        var (svc, _) = Setup([lowSev, highSev]);

        var result = await svc.AnalyzeAsync("alpha and beta found");

        Assert.Equal(2, result.Matches[0].ThreatId);
    }

    [Fact]
    public async Task TypeLabel_KeywordReturnsRussianLabel()
    {
        var (svc, _) = Setup([Indicator(1, "keyword", "trojan")]);
        var result = await svc.AnalyzeAsync("trojan found in system");
        Assert.Equal("Ключевое слово", result.Matches[0].Indicators[0].Type);
    }

    [Fact]
    public async Task TypeLabel_RegexReturnsRussianLabel()
    {
        var (svc, _) = Setup([Indicator(1, "regex", @"trojan.*exe")]);
        var result = await svc.AnalyzeAsync("trojan-bad.exe executed");
        Assert.Equal("Регулярное выражение", result.Matches[0].Indicators[0].Type);
    }

    [Fact]
    public async Task TypeLabel_DomainReturnsRussianLabel()
    {
        var (svc, _) = Setup([Indicator(1, "domain", "evil.com")]);
        var result = await svc.AnalyzeAsync("request to evil.com blocked");
        Assert.Equal("Домен", result.Matches[0].Indicators[0].Type);
    }

    [Fact]
    public async Task InputPreservedInResult()
    {
        var (svc, _) = Setup([]);
        var result = await svc.AnalyzeAsync("test input text");
        Assert.Equal("test input text", result.Input);
    }
}
