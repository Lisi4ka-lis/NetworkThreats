using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace NetworkThreats.Models;

[Table("file_heuristics")]
public class FileHeuristic
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    [Column("id")]
    public int Id { get; set; }

    [Required]
    [MaxLength(200)]
    [Column("pattern")]
    public string Pattern { get; set; } = string.Empty;

    [Required]
    [MaxLength(50)]
    [Column("pattern_type")]
    public string PatternType { get; set; } = "string";

    [Required]
    [MaxLength(300)]
    [Column("description")]
    public string Description { get; set; } = string.Empty;

    [MaxLength(100)]
    [Column("category")]
    public string Category { get; set; } = "general";

    [MaxLength(20)]
    [Column("risk_level")]
    public string RiskLevel { get; set; } = "medium";
}
