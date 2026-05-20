using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace NetworkThreats.Models;

/// <summary>
/// Метод защиты от угроз информационной безопасности.
/// </summary>
[Table("mitigation_methods")]
public class MitigationMethod
{
    /// <summary>Уникальный идентификатор метода защиты.</summary>
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    [Column("id")]
    public int Id { get; set; }

    /// <summary>Название метода защиты.</summary>
    [Required]
    [MaxLength(100)]
    [Column("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>Тип метода: preventive, detective, corrective.</summary>
    [Required]
    [MaxLength(50)]
    [Column("type")]
    public string Type { get; set; } = "preventive";

    /// <summary>Краткое описание принципа действия метода.</summary>
    [MaxLength(1000)]
    [Column("short_description")]
    public string? ShortDescription { get; set; }

    /// <summary>Шаги реализации метода защиты (1:N).</summary>
    public virtual ICollection<MitigationStep> MitigationSteps { get; set; } = [];

    /// <summary>Связи с угрозами через таблицу N:N.</summary>
    public virtual ICollection<ThreatMitigation> ThreatMitigations { get; set; } = [];
}
