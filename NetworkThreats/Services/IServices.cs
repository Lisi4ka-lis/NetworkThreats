using NetworkThreats.Models;

namespace NetworkThreats.Services;

/// <summary>
/// Сервис управления угрозами.
/// </summary>
public interface IThreatService
{
    /// <summary>Возвращает все угрозы в виде DTO.</summary>
    Task<IEnumerable<ThreatDto>> GetAllAsync();

    /// <summary>Возвращает угрозы заданной категории в виде DTO.</summary>
    Task<IEnumerable<ThreatDto>> GetByCategoryAsync(int categoryId);

    /// <summary>Возвращает угрозы заданного уровня критичности в виде DTO.</summary>
    Task<IEnumerable<ThreatDto>> GetBySeverityAsync(string severity);

    /// <summary>Возвращает угрозу с полными деталями по идентификатору или <c>null</c>.</summary>
    Task<Threat?> GetWithDetailsAsync(int id);

    /// <summary>Создаёт новую угрозу.</summary>
    Task CreateAsync(Threat threat);

    /// <summary>Обновляет существующую угрозу.</summary>
    Task UpdateAsync(Threat threat);

    /// <summary>Удаляет угрозу по идентификатору.</summary>
    Task DeleteAsync(int id);
}

/// <summary>
/// Сервис управления категориями угроз.
/// </summary>
public interface ICategoryService
{
    /// <summary>Возвращает все категории с количеством угроз в виде DTO.</summary>
    Task<IEnumerable<ThreatCategoryDto>> GetAllAsync();

    /// <summary>Возвращает категорию по идентификатору или <c>null</c>.</summary>
    Task<ThreatCategory?> GetByIdAsync(int id);

    /// <summary>Создаёт новую категорию.</summary>
    Task CreateAsync(ThreatCategory category);

    /// <summary>Обновляет существующую категорию.</summary>
    Task UpdateAsync(ThreatCategory category);

    /// <summary>Удаляет категорию по идентификатору.</summary>
    Task DeleteAsync(int id);
}

/// <summary>
/// Сервис управления методами защиты.
/// </summary>
public interface IMitigationService
{
    /// <summary>Возвращает все методы защиты в виде DTO.</summary>
    Task<IEnumerable<MitigationMethodDto>> GetAllAsync();

    /// <summary>Возвращает методы защиты заданного типа в виде DTO.</summary>
    Task<IEnumerable<MitigationMethodDto>> GetByTypeAsync(string type);

    /// <summary>Возвращает метод защиты с шагами реализации по идентификатору или <c>null</c>.</summary>
    Task<MitigationMethod?> GetWithStepsAsync(int id);

    /// <summary>Возвращает метод защиты со шагами и связанными угрозами или <c>null</c>.</summary>
    Task<MitigationMethod?> GetFullAsync(int id);

    /// <summary>Создаёт новый метод защиты.</summary>
    Task CreateAsync(MitigationMethod method);

    /// <summary>Обновляет существующий метод защиты.</summary>
    Task UpdateAsync(MitigationMethod method);

    /// <summary>Удаляет метод защиты по идентификатору.</summary>
    Task DeleteAsync(int id);
}

/// <summary>
/// Сервис анализа входного текста на наличие признаков угроз.
/// </summary>
public interface IThreatAnalyzerService
{
    /// <summary>Анализирует текст и возвращает сопоставленные угрозы.</summary>
    Task<AnalysisResultDto> AnalyzeAsync(string input);
}

/// <summary>
/// Сервис полнотекстового поиска по всем сущностям.
/// </summary>
public interface ISearchService
{
    /// <summary>Ищет совпадения по угрозам, категориям и методам защиты.</summary>
    Task<IEnumerable<SearchResultDto>> SearchAsync(string query);
}

/// <summary>
/// Сервис статического анализа загружаемых файлов.
/// </summary>
public interface IFileAnalyzerService
{
    /// <summary>Анализирует байты файла: хэш-сверка, извлечение строк, эвристика.</summary>
    Task<FileAnalysisResultDto> AnalyzeFileAsync(string fileName, byte[] content);
}
