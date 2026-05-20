using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace NetworkThreats.Models;

/// <summary>
/// Расширенное описание угрозы (1:1 к Threat).
/// ThreatId является одновременно первичным и внешним ключом.
/// </summary>
[Table("threat_details")]
public class ThreatDetail
{
    [Key]
    [Column("threat_id")]
    public int ThreatId { get; set; }

    [MaxLength(20)]
    [Column("mitre_technique_id")]
    public string? MitreTechniqueId { get; set; }

    [Column("cvss_score")]
    public double? CvssScore { get; set; }

    [MaxLength(300)]
    [Column("affected_systems")]
    public string? AffectedSystems { get; set; }

    [MaxLength(500)]
    [Column("recommended_action")]
    public string? RecommendedAction { get; set; }

    public virtual Threat Threat { get; set; } = null!;
}
