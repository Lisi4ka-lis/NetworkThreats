namespace NetworkThreats.Tests;

public class SearchServiceTests
{
    private static SearchService Build(
        IEnumerable<Threat>?           threats     = null,
        IEnumerable<ThreatCategory>?   categories  = null,
        IEnumerable<MitigationMethod>? mitigations = null)
    {
        var threatRepo = new Mock<IThreatRepository>();
        threatRepo.Setup(r => r.SearchAsync(It.IsAny<string>())).ReturnsAsync(threats ?? []);

        var catRepo = new Mock<ICategoryRepository>();
        catRepo.Setup(r => r.SearchAsync(It.IsAny<string>())).ReturnsAsync(categories ?? []);

        var mitRepo = new Mock<IMitigationRepository>();
        mitRepo.Setup(r => r.SearchAsync(It.IsAny<string>())).ReturnsAsync(mitigations ?? []);

        return new SearchService(threatRepo.Object, catRepo.Object, mitRepo.Object);
    }

    private static Threat MakeThreat(int id = 1) =>
        new()
        {
            Id               = id,
            Name             = $"Threat{id}",
            Severity         = "high",
            ShortDescription = "desc",
            CategoryId       = 1,
            Category         = new ThreatCategory { Id = 1, Name = "Cat" }
        };

    [Fact]
    public async Task EmptyQuery_ReturnsEmpty()
    {
        var svc = Build();
        var result = await svc.SearchAsync("");
        Assert.Empty(result);
    }

    [Fact]
    public async Task WhitespaceQuery_ReturnsEmpty()
    {
        var svc = Build();
        var result = await svc.SearchAsync("   ");
        Assert.Empty(result);
    }

    [Fact]
    public async Task ThreatResults_HaveCorrectEntityTypeAndUrl()
    {
        var svc = Build(threats: [MakeThreat(7)]);

        var result = (await svc.SearchAsync("sql")).ToList();

        Assert.Single(result);
        Assert.Equal("Угроза",      result[0].EntityType);
        Assert.Equal("/threats/7",  result[0].Url);
        Assert.Equal("Threat7",     result[0].Name);
        Assert.Equal("high",        result[0].Badge);
    }

    [Fact]
    public async Task ThreatResults_DescriptionFromShortDescription()
    {
        var threat = MakeThreat(1);
        var svc = Build(threats: [threat]);

        var result = (await svc.SearchAsync("q")).ToList();

        Assert.Equal("desc", result[0].Description);
    }

    [Fact]
    public async Task CategoryResults_HaveCorrectEntityTypeAndUrl()
    {
        var cat = new ThreatCategory { Id = 3, Name = "Malware", Description = "Malicious code" };
        var svc = Build(categories: [cat]);

        var result = (await svc.SearchAsync("malware")).ToList();

        Assert.Single(result);
        Assert.Equal("Категория",   result[0].EntityType);
        Assert.Equal("/categories", result[0].Url);
        Assert.Equal("Malware",     result[0].Name);
        Assert.Null(result[0].Badge);
    }

    [Fact]
    public async Task MitigationResults_HaveCorrectEntityTypeAndUrl()
    {
        var m = new MitigationMethod { Id = 5, Name = "Firewall", Type = "preventive", ShortDescription = "Blocks traffic" };
        var svc = Build(mitigations: [m]);

        var result = (await svc.SearchAsync("firewall")).ToList();

        Assert.Single(result);
        Assert.Equal("Метод защиты",    result[0].EntityType);
        Assert.Equal("/mitigations/5",  result[0].Url);
        Assert.Equal("preventive",      result[0].Badge);
    }

    [Fact]
    public async Task AggregatesResultsFromAllThreeRepos()
    {
        var threat = MakeThreat(1);
        var cat    = new ThreatCategory { Id = 1, Name = "C" };
        var mit    = new MitigationMethod { Id = 1, Name = "M", Type = "preventive" };
        var svc    = Build([threat], [cat], [mit]);

        var result = (await svc.SearchAsync("test")).ToList();

        Assert.Equal(3, result.Count);
    }

    [Fact]
    public async Task OnlyThreats_WhenCategoriesAndMitigationsEmpty()
    {
        var svc = Build(threats: [MakeThreat(1), MakeThreat(2)]);

        var result = (await svc.SearchAsync("q")).ToList();

        Assert.Equal(2, result.Count);
        Assert.All(result, r => Assert.Equal("Угроза", r.EntityType));
    }

    [Fact]
    public async Task NullQuery_ReturnsEmpty()
    {
        var svc = Build();
        var result = await svc.SearchAsync(null!);
        Assert.Empty(result);
    }
}
