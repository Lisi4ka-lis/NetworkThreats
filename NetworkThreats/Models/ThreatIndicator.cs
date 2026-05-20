using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace NetworkThreats.Models;

[Table("threat_indicators")]
public class ThreatIndicator
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    [Column("id")]
    public int Id { get; set; }

    [Column("threat_id")]
    public int ThreatId { get; set; }

    [Required]
    [MaxLength(50)]
    [Column("indicator_type")]
    public string IndicatorType { get; set; } = "keyword";

    [Required]
    [MaxLength(500)]
    [Column("pattern")]
    public string Pattern { get; set; } = string.Empty;

    [MaxLength(300)]
    [Column("description")]
    public string? Description { get; set; }

    [MaxLength(20)]
    [Column("confidence")]
    public string Confidence { get; set; } = "medium";

    [ForeignKey(nameof(ThreatId))]
    public virtual Threat Threat { get; set; } = null!;
}
