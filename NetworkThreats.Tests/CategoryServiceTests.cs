namespace NetworkThreats.Tests;

public class CategoryServiceTests
{
    [Fact]
    public async Task GetAllAsync_MapsToDtoWithCorrectThreatsCount()
    {
        var cat = new ThreatCategory { Id = 1, Name = "Malware", Description = "Malicious software" };
        cat.Threats.Add(new Threat { Id = 1, Name = "T1", Severity = "high", ShortDescription = "d", CategoryId = 1 });
        cat.Threats.Add(new Threat { Id = 2, Name = "T2", Severity = "low",  ShortDescription = "d", CategoryId = 1 });

        var repo = new Mock<ICategoryRepository>();
        repo.Setup(r => r.GetWithThreatsCountAsync()).ReturnsAsync([cat]);
        var svc = new CategoryService(repo.Object);

        var result = (await svc.GetAllAsync()).ToList();

        Assert.Single(result);
        Assert.Equal(1,                   result[0].Id);
        Assert.Equal("Malware",           result[0].Name);
        Assert.Equal("Malicious software", result[0].Description);
        Assert.Equal(2,                   result[0].ThreatsCount);
    }

    [Fact]
    public async Task GetAllAsync_EmptyThreats_CountIsZero()
    {
        var cat = new ThreatCategory { Id = 2, Name = "Empty" };
        var repo = new Mock<ICategoryRepository>();
        repo.Setup(r => r.GetWithThreatsCountAsync()).ReturnsAsync([cat]);
        var svc = new CategoryService(repo.Object);

        var result = (await svc.GetAllAsync()).ToList();

        Assert.Equal(0, result[0].ThreatsCount);
    }

    [Fact]
    public async Task GetByIdAsync_DelegatesToRepo()
    {
        var cat = new ThreatCategory { Id = 4, Name = "Phishing" };
        var repo = new Mock<ICategoryRepository>();
        repo.Setup(r => r.GetByIdAsync(4)).ReturnsAsync(cat);
        var svc = new CategoryService(repo.Object);

        var result = await svc.GetByIdAsync(4);

        Assert.NotNull(result);
        Assert.Equal("Phishing", result.Name);
        repo.Verify(r => r.GetByIdAsync(4), Times.Once);
    }

    [Fact]
    public async Task GetByIdAsync_ReturnsNull_WhenNotFound()
    {
        var repo = new Mock<ICategoryRepository>();
        repo.Setup(r => r.GetByIdAsync(99)).ReturnsAsync((ThreatCategory?)null);
        var svc = new CategoryService(repo.Object);

        var result = await svc.GetByIdAsync(99);

        Assert.Null(result);
    }

    [Fact]
    public async Task CreateAsync_DelegatesToRepo()
    {
        var cat = new ThreatCategory { Id = 1, Name = "New" };
        var repo = new Mock<ICategoryRepository>();
        repo.Setup(r => r.AddAsync(cat)).Returns(Task.CompletedTask);
        var svc = new CategoryService(repo.Object);

        await svc.CreateAsync(cat);

        repo.Verify(r => r.AddAsync(cat), Times.Once);
    }

    [Fact]
    public async Task UpdateAsync_DelegatesToRepo()
    {
        var cat = new ThreatCategory { Id = 1, Name = "Updated" };
        var repo = new Mock<ICategoryRepository>();
        repo.Setup(r => r.UpdateAsync(cat)).Returns(Task.CompletedTask);
        var svc = new CategoryService(repo.Object);

        await svc.UpdateAsync(cat);

        repo.Verify(r => r.UpdateAsync(cat), Times.Once);
    }

    [Fact]
    public async Task DeleteAsync_DelegatesToRepo()
    {
        var repo = new Mock<ICategoryRepository>();
        repo.Setup(r => r.DeleteAsync(3)).Returns(Task.CompletedTask);
        var svc = new CategoryService(repo.Object);

        await svc.DeleteAsync(3);

        repo.Verify(r => r.DeleteAsync(3), Times.Once);
    }
}
