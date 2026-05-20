using Microsoft.EntityFrameworkCore;
using NetworkThreats.Data;
using NetworkThreats.Models;

namespace NetworkThreats.Repositories;

/// <summary>
/// Репозиторий угроз.
/// </summary>
public class ThreatRepository : IThreatRepository
{
    private readonly AppDbContext _db;

    /// <summary>Инициализирует репозиторий с переданным контекстом БД.</summary>
    public ThreatRepository(AppDbContext db) => _db = db;

    /// <inheritdoc />
    public async Task<IEnumerable<Threat>> GetAllAsync() =>
        await _db.Threats.Include(t => t.Category).ToListAsync();

    /// <inheritdoc />
    public async Task<Threat?> GetByIdAsync(int id) =>
        await _db.Threats.Include(t => t.Category).FirstOrDefaultAsync(t => t.Id == id);

    /// <inheritdoc />
    public async Task<IEnumerable<Threat>> GetByCategoryAsync(int categoryId) =>
        await _db.Threats.Include(t => t.Category)
                         .Where(t => t.CategoryId == categoryId)
                         .ToListAsync();

    /// <inheritdoc />
    public async Task<IEnumerable<Threat>> GetBySeverityAsync(string severity) =>
        await _db.Threats.Include(t => t.Category)
                         .Where(t => t.Severity == severity)
                         .ToListAsync();

    /// <inheritdoc />
    public async Task<IEnumerable<Threat>> GetWithDetailsAsync() =>
        await _db.Threats
                 .Include(t => t.Category)
                 .Include(t => t.AttackExamples)
                 .Include(t => t.ThreatMitigations)
                     .ThenInclude(tm => tm.MitigationMethod)
                 .ToListAsync();

    /// <inheritdoc />
    public async Task<Threat?> GetWithDetailsAsync(int id) =>
        await _db.Threats
                 .Include(t => t.Category)
                 .Include(t => t.ThreatDetail)
                 .Include(t => t.AttackExamples)
                 .Include(t => t.ThreatMitigations)
                     .ThenInclude(tm => tm.MitigationMethod)
                         .ThenInclude(m => m.MitigationSteps)
                 .FirstOrDefaultAsync(t => t.Id == id);

    /// <inheritdoc />
    public async Task<IEnumerable<Threat>> SearchAsync(string query)
    {
        var all = await _db.Threats.Include(t => t.Category).ToListAsync();
        return all.Where(t =>
            t.Name.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
            t.ShortDescription.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
            (t.AttackVector?.Contains(query, StringComparison.CurrentCultureIgnoreCase) ?? false));
    }

    /// <inheritdoc />
    public async Task AddAsync(Threat entity)
    {
        _db.Threats.Add(entity);
        await _db.SaveChangesAsync();
    }

    /// <inheritdoc />
    public async Task UpdateAsync(Threat entity)
    {
        _db.Threats.Update(entity);
        await _db.SaveChangesAsync();
    }

    /// <inheritdoc />
    public async Task DeleteAsync(int id)
    {
        var entity = await _db.Threats.FindAsync(id);
        if (entity is not null)
        {
            _db.Threats.Remove(entity);
            await _db.SaveChangesAsync();
        }
    }
}

/// <summary>
/// Репозиторий категорий угроз.
/// </summary>
public class CategoryRepository : ICategoryRepository
{
    private readonly AppDbContext _db;

    /// <summary>Инициализирует репозиторий с переданным контекстом БД.</summary>
    public CategoryRepository(AppDbContext db) => _db = db;

    /// <inheritdoc />
    public async Task<IEnumerable<ThreatCategory>> GetAllAsync() =>
        await _db.ThreatCategories.ToListAsync();

    /// <inheritdoc />
    public async Task<ThreatCategory?> GetByIdAsync(int id) =>
        await _db.ThreatCategories.FindAsync(id);

    /// <inheritdoc />
    public async Task<IEnumerable<ThreatCategory>> GetWithThreatsCountAsync() =>
        await _db.ThreatCategories.Include(c => c.Threats).ToListAsync();

    /// <inheritdoc />
    public async Task<IEnumerable<ThreatCategory>> SearchAsync(string query)
    {
        var all = await _db.ThreatCategories.ToListAsync();
        return all.Where(c =>
            c.Name.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
            (c.Description?.Contains(query, StringComparison.CurrentCultureIgnoreCase) ?? false));
    }

    /// <inheritdoc />
    public async Task AddAsync(ThreatCategory entity)
    {
        _db.ThreatCategories.Add(entity);
        await _db.SaveChangesAsync();
    }

    /// <inheritdoc />
    public async Task UpdateAsync(ThreatCategory entity)
    {
        _db.ThreatCategories.Update(entity);
        await _db.SaveChangesAsync();
    }

    /// <inheritdoc />
    public async Task DeleteAsync(int id)
    {
        var entity = await _db.ThreatCategories.FindAsync(id);
        if (entity is not null)
        {
            _db.ThreatCategories.Remove(entity);
            await _db.SaveChangesAsync();
        }
    }
}

/// <summary>
/// Репозиторий индикаторов угроз для системы анализа текста.
/// </summary>
public class IndicatorRepository : IIndicatorRepository
{
    private readonly AppDbContext _db;

    /// <summary>Инициализирует репозиторий с переданным контекстом БД.</summary>
    public IndicatorRepository(AppDbContext db) => _db = db;

    /// <inheritdoc />
    public async Task<IEnumerable<ThreatIndicator>> GetAllWithThreatsAsync() =>
        await _db.ThreatIndicators
                 .Include(i => i.Threat)
                     .ThenInclude(t => t.Category)
                 .ToListAsync();
}

/// <summary>
/// Репозиторий известных вредоносных хэшей.
/// </summary>
public class KnownHashRepository : IKnownHashRepository
{
    private readonly AppDbContext _db;

    /// <summary>Инициализирует репозиторий с переданным контекстом БД.</summary>
    public KnownHashRepository(AppDbContext db) => _db = db;

    /// <inheritdoc />
    public async Task<KnownMaliciousHash?> FindBySha256Async(string sha256) =>
        await _db.KnownMaliciousHashes.FirstOrDefaultAsync(h => h.Sha256 == sha256);

    /// <inheritdoc />
    public async Task<KnownMaliciousHash?> FindByMd5Async(string md5) =>
        await _db.KnownMaliciousHashes.FirstOrDefaultAsync(h => h.Md5 == md5);
}

/// <summary>
/// Репозиторий эвристических правил анализа файлов.
/// </summary>
public class FileHeuristicRepository : IFileHeuristicRepository
{
    private readonly AppDbContext _db;

    /// <summary>Инициализирует репозиторий с переданным контекстом БД.</summary>
    public FileHeuristicRepository(AppDbContext db) => _db = db;

    /// <inheritdoc />
    public async Task<IEnumerable<FileHeuristic>> GetAllAsync() =>
        await _db.FileHeuristics.ToListAsync();
}

/// <summary>
/// Репозиторий методов защиты.
/// </summary>
public class MitigationRepository : IMitigationRepository
{
    private readonly AppDbContext _db;

    /// <summary>Инициализирует репозиторий с переданным контекстом БД.</summary>
    public MitigationRepository(AppDbContext db) => _db = db;

    /// <inheritdoc />
    public async Task<IEnumerable<MitigationMethod>> GetAllAsync() =>
        await _db.MitigationMethods.ToListAsync();

    /// <inheritdoc />
    public async Task<MitigationMethod?> GetByIdAsync(int id) =>
        await _db.MitigationMethods.FindAsync(id);

    /// <inheritdoc />
    public async Task<IEnumerable<MitigationMethod>> GetByTypeAsync(string type) =>
        await _db.MitigationMethods.Where(m => m.Type == type).ToListAsync();

    /// <inheritdoc />
    public async Task<MitigationMethod?> GetWithStepsAsync(int id) =>
        await _db.MitigationMethods
                 .Include(m => m.MitigationSteps.OrderBy(s => s.StepOrder))
                 .FirstOrDefaultAsync(m => m.Id == id);

    /// <inheritdoc />
    public async Task<MitigationMethod?> GetFullAsync(int id) =>
        await _db.MitigationMethods
                 .Include(m => m.MitigationSteps.OrderBy(s => s.StepOrder))
                 .Include(m => m.ThreatMitigations)
                     .ThenInclude(tm => tm.Threat)
                         .ThenInclude(t => t.Category)
                 .FirstOrDefaultAsync(m => m.Id == id);

    /// <inheritdoc />
    public async Task<IEnumerable<MitigationMethod>> SearchAsync(string query)
    {
        var all = await _db.MitigationMethods.ToListAsync();
        return all.Where(m =>
            m.Name.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
            (m.ShortDescription?.Contains(query, StringComparison.CurrentCultureIgnoreCase) ?? false));
    }

    /// <inheritdoc />
    public async Task AddAsync(MitigationMethod entity)
    {
        _db.MitigationMethods.Add(entity);
        await _db.SaveChangesAsync();
    }

    /// <inheritdoc />
    public async Task UpdateAsync(MitigationMethod entity)
    {
        _db.MitigationMethods.Update(entity);
        await _db.SaveChangesAsync();
    }

    /// <inheritdoc />
    public async Task DeleteAsync(int id)
    {
        var entity = await _db.MitigationMethods.FindAsync(id);
        if (entity is not null)
        {
            _db.MitigationMethods.Remove(entity);
            await _db.SaveChangesAsync();
        }
    }
}
