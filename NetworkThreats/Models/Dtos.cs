namespace NetworkThreats.Models;

public record ThreatDto(
    int Id,
    string Name,
    string CategoryName,
    string ShortDescription,
    string Severity,
    string? AttackVector,
    int? FirstDetectedYear,
    int CategoryId);

public record ThreatCategoryDto(
    int Id,
    string Name,
    string? Description,
    int ThreatsCount);

public record MitigationMethodDto(
    int Id,
    string Name,
    string Type,
    string? ShortDescription);

public record MatchedIndicatorDto(
    string Type,
    string Pattern,
    string? Description,
    string Confidence);

public record MatchedThreatDto(
    int ThreatId,
    string Name,
    string Severity,
    string CategoryName,
    string OverallConfidence,
    List<MatchedIndicatorDto> Indicators);

public record AnalysisResultDto(
    bool ThreatDetected,
    string Input,
    List<MatchedThreatDto> Matches);

public record SearchResultDto(
    string EntityType,
    int Id,
    string Name,
    string? Description,
    string? Badge,
    string Url);

public record HeuristicFindingDto(
    string Pattern,
    string Description,
    string Category,
    string RiskLevel);

public record FileAnalysisResultDto(
    string FileName,
    long FileSize,
    string FileExtension,
    string Sha256,
    string Md5,
    bool IsKnownMalicious,
    KnownMaliciousHash? KnownHash,
    List<HeuristicFindingDto> HeuristicFindings,
    List<string> ExtractedStrings,
    bool ThreatDetected,
    string OverallRisk);
