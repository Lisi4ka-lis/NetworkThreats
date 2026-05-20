using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using NetworkThreats.Models;
using NetworkThreats.Repositories;

namespace NetworkThreats.Services;

/// <summary>
/// Сервис угроз: маппинг в DTO и делегация в репозиторий.
/// </summary>
public class ThreatService : IThreatService
{
    private readonly IThreatRepository _repo;

    /// <summary>Инициализирует сервис с переданным репозиторием.</summary>
    public ThreatService(IThreatRepository repo) => _repo = repo;

    /// <inheritdoc />
    public async Task<IEnumerable<ThreatDto>> GetAllAsync()
    {
        var threats = await _repo.GetAllAsync();
        return threats.Select(ToDto);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<ThreatDto>> GetByCategoryAsync(int categoryId)
    {
        var threats = await _repo.GetByCategoryAsync(categoryId);
        return threats.Select(ToDto);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<ThreatDto>> GetBySeverityAsync(string severity)
    {
        var threats = await _repo.GetBySeverityAsync(severity);
        return threats.Select(ToDto);
    }

    /// <inheritdoc />
    public Task<Threat?> GetWithDetailsAsync(int id) =>
        _repo.GetWithDetailsAsync(id);

    /// <inheritdoc />
    public Task CreateAsync(Threat threat) => _repo.AddAsync(threat);

    /// <inheritdoc />
    public Task UpdateAsync(Threat threat) => _repo.UpdateAsync(threat);

    /// <inheritdoc />
    public Task DeleteAsync(int id) => _repo.DeleteAsync(id);

    private static ThreatDto ToDto(Threat t) => new(
        t.Id, t.Name, t.CategoryName, t.ShortDescription,
        t.Severity, t.AttackVector, t.FirstDetectedYear, t.CategoryId);
}

/// <summary>
/// Сервис категорий угроз.
/// </summary>
public class CategoryService : ICategoryService
{
    private readonly ICategoryRepository _repo;

    /// <summary>Инициализирует сервис с переданным репозиторием.</summary>
    public CategoryService(ICategoryRepository repo) => _repo = repo;

    /// <inheritdoc />
    public async Task<IEnumerable<ThreatCategoryDto>> GetAllAsync()
    {
        var categories = await _repo.GetWithThreatsCountAsync();
        return categories.Select(c => new ThreatCategoryDto(
            c.Id, c.Name, c.Description, c.Threats.Count));
    }

    /// <inheritdoc />
    public Task<ThreatCategory?> GetByIdAsync(int id) => _repo.GetByIdAsync(id);

    /// <inheritdoc />
    public Task CreateAsync(ThreatCategory category) => _repo.AddAsync(category);

    /// <inheritdoc />
    public Task UpdateAsync(ThreatCategory category) => _repo.UpdateAsync(category);

    /// <inheritdoc />
    public Task DeleteAsync(int id) => _repo.DeleteAsync(id);
}

/// <summary>
/// Сервис методов защиты.
/// </summary>
public class MitigationService : IMitigationService
{
    private readonly IMitigationRepository _repo;

    /// <summary>Инициализирует сервис с переданным репозиторием.</summary>
    public MitigationService(IMitigationRepository repo) => _repo = repo;

    /// <inheritdoc />
    public async Task<IEnumerable<MitigationMethodDto>> GetAllAsync()
    {
        var methods = await _repo.GetAllAsync();
        return methods.Select(ToDto);
    }

    /// <inheritdoc />
    public async Task<IEnumerable<MitigationMethodDto>> GetByTypeAsync(string type)
    {
        var methods = await _repo.GetByTypeAsync(type);
        return methods.Select(ToDto);
    }

    /// <inheritdoc />
    public Task<MitigationMethod?> GetWithStepsAsync(int id) =>
        _repo.GetWithStepsAsync(id);

    /// <inheritdoc />
    public Task<MitigationMethod?> GetFullAsync(int id) =>
        _repo.GetFullAsync(id);

    /// <inheritdoc />
    public Task CreateAsync(MitigationMethod method) => _repo.AddAsync(method);

    /// <inheritdoc />
    public Task UpdateAsync(MitigationMethod method) => _repo.UpdateAsync(method);

    /// <inheritdoc />
    public Task DeleteAsync(int id) => _repo.DeleteAsync(id);

    private static MitigationMethodDto ToDto(MitigationMethod m) =>
        new(m.Id, m.Name, m.Type, m.ShortDescription);
}

/// <summary>
/// Анализатор входного текста на основе правил (индикаторов угроз).
/// </summary>
public class ThreatAnalyzerService : IThreatAnalyzerService
{
    private readonly IIndicatorRepository _repo;

    /// <summary>Инициализирует сервис с репозиторием индикаторов.</summary>
    public ThreatAnalyzerService(IIndicatorRepository repo) => _repo = repo;

    /// <inheritdoc />
    public async Task<AnalysisResultDto> AnalyzeAsync(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return new AnalysisResultDto(false, input, []);

        var indicators = await _repo.GetAllWithThreatsAsync();

        var grouped = new Dictionary<int, (Threat Threat, List<MatchedIndicatorDto> Hits)>();

        foreach (var ind in indicators)
        {
            if (!IsMatch(input, ind)) continue;

            if (!grouped.ContainsKey(ind.ThreatId))
                grouped[ind.ThreatId] = (ind.Threat, []);

            grouped[ind.ThreatId].Hits.Add(new MatchedIndicatorDto(
                TypeLabel(ind.IndicatorType),
                ind.Pattern,
                ind.Description,
                ind.Confidence));
        }

        var matches = grouped.Values.Select(g =>
        {
            var confidence = g.Hits.Any(h => h.Confidence == "high")   ? "high"   :
                             g.Hits.Any(h => h.Confidence == "medium") ? "medium" : "low";
            return new MatchedThreatDto(
                g.Threat.Id,
                g.Threat.Name,
                g.Threat.Severity,
                g.Threat.CategoryName,
                confidence,
                g.Hits);
        })
        .OrderByDescending(m => ConfidenceOrder(m.OverallConfidence))
        .ThenByDescending(m => SeverityOrder(m.Severity))
        .ToList();

        return new AnalysisResultDto(matches.Count > 0, input, matches);
    }

    private static bool IsMatch(string input, ThreatIndicator ind) =>
        ind.IndicatorType switch
        {
            "regex" => TryRegex(input, ind.Pattern),
            _       => input.Contains(ind.Pattern, StringComparison.CurrentCultureIgnoreCase)
        };

    private static bool TryRegex(string input, string pattern)
    {
        try { return Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase | RegexOptions.Multiline); }
        catch { return false; }
    }

    private static string TypeLabel(string t) => t switch
    {
        "keyword"     => "Ключевое слово",
        "regex"       => "Регулярное выражение",
        "ip"          => "IP-адрес",
        "domain"      => "Домен",
        "filepath"    => "Путь к файлу",
        "log_pattern" => "Паттерн лога",
        _             => t
    };

    private static int ConfidenceOrder(string c) => c switch { "high" => 2, "medium" => 1, _ => 0 };
    private static int SeverityOrder(string s)   => s switch { "critical" => 3, "high" => 2, "medium" => 1, _ => 0 };
}

/// <summary>
/// Сервис статического анализа файлов: хэш-сверка, извлечение строк, эвристика.
/// </summary>
public class FileAnalyzerService : IFileAnalyzerService
{
    private readonly IKnownHashRepository _hashRepo;
    private readonly IFileHeuristicRepository _heuristicRepo;

    /// <summary>Инициализирует сервис с репозиториями хэшей и эвристик.</summary>
    public FileAnalyzerService(IKnownHashRepository hashRepo, IFileHeuristicRepository heuristicRepo)
    {
        _hashRepo = hashRepo;
        _heuristicRepo = heuristicRepo;
    }

    /// <inheritdoc />
    public async Task<FileAnalysisResultDto> AnalyzeFileAsync(string fileName, byte[] content)
    {
        var sha256 = ComputeSha256(content);
        var md5    = ComputeMd5(content);

        var knownHash = await _hashRepo.FindBySha256Async(sha256)
                     ?? await _hashRepo.FindByMd5Async(md5);

        var extractedStrings = ExtractStrings(content);
        var joined = string.Join("\n", extractedStrings);

        var heuristics = await _heuristicRepo.GetAllAsync();
        var findings = new List<HeuristicFindingDto>();

        foreach (var h in heuristics)
        {
            bool hit = h.PatternType == "regex"
                ? TryRegex(joined, h.Pattern)
                : joined.Contains(h.Pattern, StringComparison.OrdinalIgnoreCase);

            if (hit)
                findings.Add(new HeuristicFindingDto(h.Pattern, h.Description, h.Category, h.RiskLevel));
        }

        bool threat = knownHash != null || findings.Any();
        string risk = knownHash?.Severity
                   ?? (findings.Any(f => f.RiskLevel == "critical") ? "critical" :
                       findings.Any(f => f.RiskLevel == "high")     ? "high"     :
                       findings.Any(f => f.RiskLevel == "medium")   ? "medium"   :
                       findings.Any()                                ? "low"      : "none");

        return new FileAnalysisResultDto(
            fileName, content.Length,
            Path.GetExtension(fileName).ToLowerInvariant(),
            sha256, md5,
            knownHash != null, knownHash,
            findings,
            extractedStrings.Take(100).ToList(),
            threat, risk);
    }

    private static string ComputeSha256(byte[] data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLower();

    private static string ComputeMd5(byte[] data) =>
        Convert.ToHexString(MD5.HashData(data)).ToLower();

    private static List<string> ExtractStrings(byte[] data, int minLength = 4)
    {
        var result = new List<string>();
        var buf = new StringBuilder();
        foreach (byte b in data)
        {
            if (b >= 0x20 && b < 0x7F)
            {
                buf.Append((char)b);
            }
            else
            {
                if (buf.Length >= minLength) result.Add(buf.ToString());
                buf.Clear();
            }
        }
        if (buf.Length >= minLength) result.Add(buf.ToString());
        return result;
    }

    private static bool TryRegex(string input, string pattern)
    {
        try { return Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase); }
        catch { return false; }
    }
}

/// <summary>
/// Сервис полнотекстового поиска по угрозам, категориям и методам защиты.
/// </summary>
public class SearchService : ISearchService
{
    private readonly IThreatRepository _threats;
    private readonly ICategoryRepository _categories;
    private readonly IMitigationRepository _mitigations;

    /// <summary>Инициализирует сервис с тремя репозиториями для поиска.</summary>
    public SearchService(
        IThreatRepository threats,
        ICategoryRepository categories,
        IMitigationRepository mitigations)
    {
        _threats = threats;
        _categories = categories;
        _mitigations = mitigations;
    }

    /// <inheritdoc />
    public async Task<IEnumerable<SearchResultDto>> SearchAsync(string query)
    {
        if (string.IsNullOrWhiteSpace(query))
            return [];

        var results = new List<SearchResultDto>();

        var threats = await _threats.SearchAsync(query);
        results.AddRange(threats.Select(t => new SearchResultDto(
            "Угроза", t.Id, t.Name, t.ShortDescription, t.Severity,
            $"/threats/{t.Id}")));

        var categories = await _categories.SearchAsync(query);
        results.AddRange(categories.Select(c => new SearchResultDto(
            "Категория", c.Id, c.Name, c.Description, null,
            $"/categories")));

        var mitigations = await _mitigations.SearchAsync(query);
        results.AddRange(mitigations.Select(m => new SearchResultDto(
            "Метод защиты", m.Id, m.Name, m.ShortDescription, m.Type,
            $"/mitigations/{m.Id}")));

        return results;
    }
}
