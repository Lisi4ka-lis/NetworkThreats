namespace NetworkThreats.Tests;

public class ThreatServiceTests
{
    private static Threat MakeThreat(int id = 1, string severity = "high", int catId = 1)
    {
        var cat = new ThreatCategory { Id = catId, Name = "TestCategory" };
        return new Threat
        {
            Id               = id,
            Name             = $"Threat{id}",
            Severity         = severity,
            CategoryId       = catId,
            ShortDescription = "short desc",
            AttackVector     = "web",
            FirstDetectedYear = 2020,
            Category         = cat
        };
    }

    [Fact]
    public async Task GetAllAsync_MapsToDtos_AllFieldsCorrect()
    {
        var threats = new[] { MakeThreat(1), MakeThreat(2) };
        var repo = new Mock<IThreatRepository>();
        repo.Setup(r => r.GetAllAsync()).ReturnsAsync(threats);
        var svc = new ThreatService(repo.Object);

        var result = (await svc.GetAllAsync()).ToList();

        Assert.Equal(2, result.Count);
        Assert.Equal(1,              result[0].Id);
        Assert.Equal("Threat1",      result[0].Name);
        Assert.Equal("TestCategory", result[0].CategoryName);
        Assert.Equal("high",         result[0].Severity);
        Assert.Equal("web",          result[0].AttackVector);
        Assert.Equal(2020,           result[0].FirstDetectedYear);
        Assert.Equal(1,              result[0].CategoryId);
    }

    [Fact]
    public async Task GetByCategoryAsync_DelegatesWithCorrectId()
    {
        var repo = new Mock<IThreatRepository>();
        repo.Setup(r => r.GetByCategoryAsync(3)).ReturnsAsync([MakeThreat(1, catId: 3)]);
        var svc = new ThreatService(repo.Object);

        var result = (await svc.GetByCategoryAsync(3)).ToList();

        Assert.Single(result);
        Assert.Equal(3, result[0].CategoryId);
        repo.Verify(r => r.GetByCategoryAsync(3), Times.Once);
    }

    [Fact]
    public async Task GetBySeverityAsync_DelegatesWithCorrectSeverity()
    {
        var repo = new Mock<IThreatRepository>();
        repo.Setup(r => r.GetBySeverityAsync("critical")).ReturnsAsync([MakeThreat(1, "critical")]);
        var svc = new ThreatService(repo.Object);

        var result = (await svc.GetBySeverityAsync("critical")).ToList();

        Assert.Single(result);
        Assert.Equal("critical", result[0].Severity);
        repo.Verify(r => r.GetBySeverityAsync("critical"), Times.Once);
    }

    [Fact]
    public async Task GetWithDetailsAsync_DelegatesToRepo()
    {
        var threat = MakeThreat(5);
        var repo = new Mock<IThreatRepository>();
        repo.Setup(r => r.GetWithDetailsAsync(5)).ReturnsAsync(threat);
        var svc = new ThreatService(repo.Object);

        var result = await svc.GetWithDetailsAsync(5);

        Assert.NotNull(result);
        Assert.Equal(5, result.Id);
        repo.Verify(r => r.GetWithDetailsAsync(5), Times.Once);
    }

    [Fact]
    public async Task GetWithDetailsAsync_ReturnsNull_WhenNotFound()
    {
        var repo = new Mock<IThreatRepository>();
        repo.Setup(r => r.GetWithDetailsAsync(99)).ReturnsAsync((Threat?)null);
        var svc = new ThreatService(repo.Object);

        var result = await svc.GetWithDetailsAsync(99);

        Assert.Null(result);
    }

    [Fact]
    public async Task CreateAsync_DelegatesToRepo()
    {
        var threat = MakeThreat();
        var repo = new Mock<IThreatRepository>();
        repo.Setup(r => r.AddAsync(threat)).Returns(Task.CompletedTask);
        var svc = new ThreatService(repo.Object);

        await svc.CreateAsync(threat);

        repo.Verify(r => r.AddAsync(threat), Times.Once);
    }

    [Fact]
    public async Task UpdateAsync_DelegatesToRepo()
    {
        var threat = MakeThreat();
        var repo = new Mock<IThreatRepository>();
        repo.Setup(r => r.UpdateAsync(threat)).Returns(Task.CompletedTask);
        var svc = new ThreatService(repo.Object);

        await svc.UpdateAsync(threat);

        repo.Verify(r => r.UpdateAsync(threat), Times.Once);
    }

    [Fact]
    public async Task DeleteAsync_DelegatesToRepo()
    {
        var repo = new Mock<IThreatRepository>();
        repo.Setup(r => r.DeleteAsync(7)).Returns(Task.CompletedTask);
        var svc = new ThreatService(repo.Object);

        await svc.DeleteAsync(7);

        repo.Verify(r => r.DeleteAsync(7), Times.Once);
    }

    [Fact]
    public async Task GetAllAsync_EmptyRepo_ReturnsEmptyList()
    {
        var repo = new Mock<IThreatRepository>();
        repo.Setup(r => r.GetAllAsync()).ReturnsAsync([]);
        var svc = new ThreatService(repo.Object);

        var result = await svc.GetAllAsync();

        Assert.Empty(result);
    }
}
