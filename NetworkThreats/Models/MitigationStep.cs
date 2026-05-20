using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace NetworkThreats.Models;

/// <summary>
/// Шаг реализации метода защиты с описанием действия, ОС и примером команды.
/// </summary>
[Table("mitigation_steps")]
public class MitigationStep
{
    /// <summary>Уникальный идентификатор шага.</summary>
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    [Column("id")]
    public int Id { get; set; }

    /// <summary>Идентификатор метода защиты, к которому относится шаг.</summary>
    [Column("mitigation_id")]
    public int MitigationId { get; set; }

    /// <summary>Порядковый номер шага внутри метода.</summary>
    [Column("step_order")]
    public int StepOrder { get; set; }

    /// <summary>Описание действия, которое необходимо выполнить.</summary>
    [Required]
    [Column("action")]
    [StringLength(500)]
    public string Action { get; set; } = string.Empty;

    /// <summary>Операционная система, для которой применим шаг (Windows, Linux, Все).</summary>
    [Column("applicable_os")]
    [StringLength(100)]
    public string? ApplicableOs { get; set; }

    /// <summary>Пример команды или конфигурации для выполнения шага.</summary>
    [Column("command_example")]
    [StringLength(1000)]
    public string? CommandExample { get; set; }

    /// <summary>Навигационное свойство к методу защиты (1:N).</summary>
    [ForeignKey(nameof(MitigationId))]
    public virtual MitigationMethod MitigationMethod { get; set; } = null!;

    /// <summary>Имя метода защиты — вычисляемое, не хранится в БД.</summary>
    [NotMapped]
    public string MitigationName => MitigationMethod?.Name ?? string.Empty;
}
