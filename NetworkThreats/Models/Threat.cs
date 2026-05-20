using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace NetworkThreats.Models;

/// <summary>
/// Угроза информационной безопасности с описанием, вектором атаки и уровнем критичности.
/// </summary>
[Table("threats")]
public class Threat
{
    /// <summary>Уникальный идентификатор угрозы.</summary>
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    [Column("id")]
    public int Id { get; set; }

    /// <summary>Название угрозы (например, SQL Injection).</summary>
    [Required]
    [MaxLength(150)]
    [Column("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>Идентификатор категории угрозы.</summary>
    [Column("category_id")]
    [Range(1, int.MaxValue, ErrorMessage = "Выберите категорию")]
    public int CategoryId { get; set; }

    /// <summary>Краткое описание угрозы и механизма её действия.</summary>
    [Required]
    [MaxLength(2000)]
    [Column("short_description")]
    public string ShortDescription { get; set; } = string.Empty;

    /// <summary>Уровень критичности: low, medium, high, critical.</summary>
    [Required]
    [MaxLength(20)]
    [Column("severity")]
    public string Severity { get; set; } = "medium";

    /// <summary>Типичный вектор атаки (например, веб-формы, SSH).</summary>
    [MaxLength(500)]
    [Column("attack_vector")]
    public string? AttackVector { get; set; }

    /// <summary>Год первой публичной фиксации угрозы.</summary>
    [Column("first_detected_year")]
    public int? FirstDetectedYear { get; set; }

    /// <summary>Навигационное свойство к категории (1:N).</summary>
    [ForeignKey(nameof(CategoryId))]
    public virtual ThreatCategory Category { get; set; } = null!;

    /// <summary>Имя категории — вычисляемое, не хранится в БД.</summary>
    [NotMapped]
    public string CategoryName => Category?.Name ?? string.Empty;

    /// <summary>Реальные примеры атак данного типа (1:N).</summary>
    public virtual ICollection<AttackExample> AttackExamples { get; set; } = [];

    /// <summary>Связи с методами защиты через таблицу N:N.</summary>
    public virtual ICollection<ThreatMitigation> ThreatMitigations { get; set; } = [];

    /// <summary>Расширенное описание угрозы с MITRE и CVSS (1:1).</summary>
    public virtual ThreatDetail? ThreatDetail { get; set; }
}
