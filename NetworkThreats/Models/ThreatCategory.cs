using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace NetworkThreats.Models;

/// <summary>
/// Категория угроз информационной безопасности (например, Вредоносное ПО, Сетевые атаки).
/// </summary>
[Table("threat_categories")]
public class ThreatCategory
{
    /// <summary>Уникальный идентификатор категории.</summary>
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    [Column("id")]
    public int Id { get; set; }

    /// <summary>Название категории.</summary>
    [Required]
    [MaxLength(100)]
    [Column("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>Описание категории и типов входящих угроз.</summary>
    [MaxLength(500)]
    [Column("description")]
    public string? Description { get; set; }

    /// <summary>Угрозы, относящиеся к данной категории (1:N).</summary>
    public virtual ICollection<Threat> Threats { get; set; } = [];
}
