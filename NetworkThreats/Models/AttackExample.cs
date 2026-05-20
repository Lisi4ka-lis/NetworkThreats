using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace NetworkThreats.Models;

[Table("attack_examples")]
public class AttackExample
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    [Column("id")]
    public int Id { get; set; }

    [Required]
    [StringLength(150)]
    [Column("name")]
    public string Name { get; set; } = string.Empty;

    [Column("threat_id")]
    public int ThreatId { get; set; }

    [Column("year")]
    public int? Year { get; set; }

    [Column("impact_estimate")]
    [StringLength(500)]
    public string? ImpactEstimate { get; set; }

    [Column("url_reference")]
    [StringLength(500)]
    public string? UrlReference { get; set; }

    [ForeignKey(nameof(ThreatId))]
    public virtual Threat Threat { get; set; } = null!;

    [NotMapped]
    public string ThreatName => Threat?.Name ?? string.Empty;
}
