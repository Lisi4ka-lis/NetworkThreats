using NetworkThreats.Models;

namespace NetworkThreats.Repositories;

/// <summary>
/// Базовый интерфейс репозитория с CRUD-операциями.
/// </summary>
public interface IRepository<T> where T : class
{
    /// <summary>Возвращает все записи.</summary>
    Task<IEnumerable<T>> GetAllAsync();

    /// <summary>Возвращает запись по идентификатору или <c>null</c>.</summary>
    Task<T?> GetByIdAsync(int id);

    /// <summary>Добавляет новую запись и сохраняет изменения.</summary>
    Task AddAsync(T entity);

    /// <summary>Обновляет существующую запись и сохраняет изменения.</summary>
    Task UpdateAsync(T entity);

    /// <summary>Удаляет запись по идентификатору и сохраняет изменения.</summary>
    Task DeleteAsync(int id);
}

/// <summary>
/// Репозиторий угроз с расширенной фильтрацией.
/// </summary>
public interface IThreatRepository : IRepository<Threat>
{
    /// <summary>Возвращает угрозы заданной категории.</summary>
    Task<IEnumerable<Threat>> GetByCategoryAsync(int categoryId);

    /// <summary>Возвращает угрозы заданного уровня критичности.</summary>
    Task<IEnumerable<Threat>> GetBySeverityAsync(string severity);

    /// <summary>Возвращает все угрозы с вложенными данными (без фильтра).</summary>
    Task<IEnumerable<Threat>> GetWithDetailsAsync();

    /// <summary>Возвращает угрозу с полными деталями по идентификатору или <c>null</c>.</summary>
    Task<Threat?> GetWithDetailsAsync(int id);

    /// <summary>Полнотекстовый поиск угроз по имени, описанию и вектору атаки.</summary>
    Task<IEnumerable<Threat>> SearchAsync(string query);
}

/// <summary>
/// Репозиторий категорий угроз.
/// </summary>
public interface ICategoryRepository : IRepository<ThreatCategory>
{
    /// <summary>Возвращает категории вместе с количеством связанных угроз.</summary>
    Task<IEnumerable<ThreatCategory>> GetWithThreatsCountAsync();

    /// <summary>Полнотекстовый поиск категорий по имени и описанию.</summary>
    Task<IEnumerable<ThreatCategory>> SearchAsync(string query);
}

/// <summary>
/// Репозиторий индикаторов угроз для системы анализа.
/// </summary>
public interface IIndicatorRepository
{
    /// <summary>Возвращает все индикаторы с загруженными угрозами и категориями.</summary>
    Task<IEnumerable<ThreatIndicator>> GetAllWithThreatsAsync();
}

/// <summary>
/// Репозиторий известных вредоносных хэшей.
/// </summary>
public interface IKnownHashRepository
{
    /// <summary>Ищет запись по SHA-256 хэшу.</summary>
    Task<KnownMaliciousHash?> FindBySha256Async(string sha256);

    /// <summary>Ищет запись по MD5 хэшу.</summary>
    Task<KnownMaliciousHash?> FindByMd5Async(string md5);
}

/// <summary>
/// Репозиторий эвристических правил анализа файлов.
/// </summary>
public interface IFileHeuristicRepository
{
    /// <summary>Возвращает все эвристические правила.</summary>
    Task<IEnumerable<FileHeuristic>> GetAllAsync();
}

/// <summary>
/// Репозиторий методов защиты.
/// </summary>
public interface IMitigationRepository : IRepository<MitigationMethod>
{
    /// <summary>Возвращает методы защиты заданного типа.</summary>
    Task<IEnumerable<MitigationMethod>> GetByTypeAsync(string type);

    /// <summary>Возвращает метод защиты вместе с шагами реализации или <c>null</c>.</summary>
    Task<MitigationMethod?> GetWithStepsAsync(int id);

    /// <summary>Возвращает метод защиты со шагами и связанными угрозами или <c>null</c>.</summary>
    Task<MitigationMethod?> GetFullAsync(int id);

    /// <summary>Полнотекстовый поиск методов защиты по имени и описанию.</summary>
    Task<IEnumerable<MitigationMethod>> SearchAsync(string query);
}
