using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace NetworkThreats.Models;

/// <summary>
/// Таблица связи N:N между угрозой и методом защиты.
/// Содержит дополнительные атрибуты связи: эффективность и примечания.
/// </summary>
[Table("threat_mitigation")]
public class ThreatMitigation
{
    /// <summary>Идентификатор угрозы (часть составного PK).</summary>
    [Column("threat_id")]
    public int ThreatId { get; set; }

    /// <summary>Идентификатор метода защиты (часть составного PK).</summary>
    [Column("mitigation_id")]
    public int MitigationId { get; set; }

    /// <summary>Эффективность метода против данной угрозы: high, medium, low.</summary>
    [Column("effectiveness")]
    [MaxLength(20)]
    public string? Effectiveness { get; set; }

    /// <summary>Примечание о применении метода к конкретной угрозе.</summary>
    [Column("notes")]
    [MaxLength(500)]
    public string? Notes { get; set; }

    /// <summary>Навигационное свойство к угрозе.</summary>
    [ForeignKey(nameof(ThreatId))]
    public virtual Threat Threat { get; set; } = null!;

    /// <summary>Навигационное свойство к методу защиты.</summary>
    [ForeignKey(nameof(MitigationId))]
    public virtual MitigationMethod MitigationMethod { get; set; } = null!;

    /// <summary>Имя угрозы — вычисляемое, не хранится в БД.</summary>
    [NotMapped]
    public string ThreatName => Threat?.Name ?? string.Empty;

    /// <summary>Имя метода защиты — вычисляемое, не хранится в БД.</summary>
    [NotMapped]
    public string MitigationName => MitigationMethod?.Name ?? string.Empty;
}
