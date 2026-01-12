namespace DockerAnalyze.Models;

/// <summary>
/// Основной результат анализа Docker-образа
/// </summary>
public class AnalysisResult
{
    public string ImageName { get; set; } = string.Empty;
    public string ImageId { get; set; } = string.Empty;
    public DateTime AnalysisDate { get; set; } = DateTime.UtcNow;
    public FileSystemAnalysis? FileSystemAnalysis { get; set; }
    public ConfigurationAnalysis? ConfigurationAnalysis { get; set; }
    public DockerfileAnalysis? DockerfileAnalysis { get; set; }
    public LayerAnalysis? LayerAnalysis { get; set; }
    public List<VulnerabilityFinding> Vulnerabilities { get; set; } = new();
    public RiskAssessment RiskAssessment { get; set; } = new();
}

/// <summary>
/// Найденная уязвимость
/// </summary>
public class VulnerabilityFinding
{
    public string Type { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Evidence { get; set; } = string.Empty;
    public string Layer { get; set; } = string.Empty;
    public string Recommendation { get; set; } = string.Empty;
}