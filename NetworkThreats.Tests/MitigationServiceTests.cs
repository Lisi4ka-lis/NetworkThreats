namespace NetworkThreats.Tests;

public class MitigationServiceTests
{
    private static MitigationMethod MakeMethod(int id = 1, string type = "preventive") =>
        new() { Id = id, Name = $"Method{id}", Type = type, ShortDescription = "Short description" };

    [Fact]
    public async Task GetAllAsync_MapsToDtos_AllFieldsCorrect()
    {
        var methods = new[] { MakeMethod(1), MakeMethod(2, "detective") };
        var repo = new Mock<IMitigationRepository>();
        repo.Setup(r => r.GetAllAsync()).ReturnsAsync(methods);
        var svc = new MitigationService(repo.Object);

        var result = (await svc.GetAllAsync()).ToList();

        Assert.Equal(2, result.Count);
        Assert.Equal("Method1",           result[0].Name);
        Assert.Equal("preventive",        result[0].Type);
        Assert.Equal("Short description", result[0].ShortDescription);
        Assert.Equal("detective",         result[1].Type);
    }

    [Fact]
    public async Task GetByTypeAsync_DelegatesWithCorrectType()
    {
        var repo = new Mock<IMitigationRepository>();
        repo.Setup(r => r.GetByTypeAsync("detective")).ReturnsAsync([MakeMethod(3, "detective")]);
        var svc = new MitigationService(repo.Object);

        var result = (await svc.GetByTypeAsync("detective")).ToList();

        Assert.Single(result);
        Assert.Equal("detective", result[0].Type);
        repo.Verify(r => r.GetByTypeAsync("detective"), Times.Once);
    }

    [Fact]
    public async Task GetWithStepsAsync_DelegatesToRepo()
    {
        var method = MakeMethod(2);
        var repo = new Mock<IMitigationRepository>();
        repo.Setup(r => r.GetWithStepsAsync(2)).ReturnsAsync(method);
        var svc = new MitigationService(repo.Object);

        var result = await svc.GetWithStepsAsync(2);

        Assert.NotNull(result);
        Assert.Equal(2, result.Id);
        repo.Verify(r => r.GetWithStepsAsync(2), Times.Once);
    }

    [Fact]
    public async Task GetFullAsync_DelegatesToRepo()
    {
        var method = MakeMethod(5);
        var repo = new Mock<IMitigationRepository>();
        repo.Setup(r => r.GetFullAsync(5)).ReturnsAsync(method);
        var svc = new MitigationService(repo.Object);

        var result = await svc.GetFullAsync(5);

        Assert.NotNull(result);
        Assert.Equal(5, result.Id);
        repo.Verify(r => r.GetFullAsync(5), Times.Once);
    }

    [Fact]
    public async Task CreateAsync_DelegatesToRepo()
    {
        var method = MakeMethod();
        var repo = new Mock<IMitigationRepository>();
        repo.Setup(r => r.AddAsync(method)).Returns(Task.CompletedTask);
        var svc = new MitigationService(repo.Object);

        await svc.CreateAsync(method);

        repo.Verify(r => r.AddAsync(method), Times.Once);
    }

    [Fact]
    public async Task UpdateAsync_DelegatesToRepo()
    {
        var method = MakeMethod();
        var repo = new Mock<IMitigationRepository>();
        repo.Setup(r => r.UpdateAsync(method)).Returns(Task.CompletedTask);
        var svc = new MitigationService(repo.Object);

        await svc.UpdateAsync(method);

        repo.Verify(r => r.UpdateAsync(method), Times.Once);
    }

    [Fact]
    public async Task DeleteAsync_DelegatesToRepo()
    {
        var repo = new Mock<IMitigationRepository>();
        repo.Setup(r => r.DeleteAsync(5)).Returns(Task.CompletedTask);
        var svc = new MitigationService(repo.Object);

        await svc.DeleteAsync(5);

        repo.Verify(r => r.DeleteAsync(5), Times.Once);
    }

    [Fact]
    public async Task GetAllAsync_EmptyRepo_ReturnsEmptyList()
    {
        var repo = new Mock<IMitigationRepository>();
        repo.Setup(r => r.GetAllAsync()).ReturnsAsync([]);
        var svc = new MitigationService(repo.Object);

        var result = await svc.GetAllAsync();

        Assert.Empty(result);
    }
}
