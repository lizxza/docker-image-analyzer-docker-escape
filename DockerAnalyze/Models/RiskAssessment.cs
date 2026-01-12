namespace DockerAnalyze.Models;

/// <summary>
/// Оценка риска Docker Escape
/// </summary>
public class RiskAssessment
{
    public int OverallRisk { get; set; }
    public string RiskLevel { get; set; } = string.Empty;
    public List<RiskFactor> RiskFactors { get; set; } = new();
    public List<string> Evidence { get; set; } = new();
    public List<string> Recommendations { get; set; } = new();
    public Dictionary<string, int> FactorWeights { get; set; } = new();
}

/// <summary>
/// Фактор риска
/// </summary>
public class RiskFactor
{
    public string Category { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public int Weight { get; set; }
    public string Evidence { get; set; } = string.Empty;
    public string Layer { get; set; } = string.Empty;
}