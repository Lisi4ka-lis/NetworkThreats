using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace NetworkThreats.Models;

[Table("known_malicious_hashes")]
public class KnownMaliciousHash
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    [Column("id")]
    public int Id { get; set; }

    [Required]
    [MaxLength(64)]
    [Column("sha256")]
    public string Sha256 { get; set; } = string.Empty;

    [MaxLength(32)]
    [Column("md5")]
    public string? Md5 { get; set; }

    [Required]
    [MaxLength(150)]
    [Column("threat_name")]
    public string ThreatName { get; set; } = string.Empty;

    [MaxLength(500)]
    [Column("description")]
    public string? Description { get; set; }

    [MaxLength(20)]
    [Column("severity")]
    public string Severity { get; set; } = "high";

    [MaxLength(50)]
    [Column("file_type")]
    public string? FileType { get; set; }
}
