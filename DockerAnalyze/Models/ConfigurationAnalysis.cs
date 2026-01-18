namespace DockerAnalyze.Models;

/// <summary>
/// Результаты анализа конфигурации образа
/// </summary>
public class ConfigurationAnalysis
{
    public string? User { get; set; }
    public bool RunsAsRoot { get; set; }
    public string? Entrypoint { get; set; }
    public string? Cmd { get; set; }
    public List<string> Capabilities { get; set; } = new();
    public bool Privileged { get; set; }
    public List<string> SecurityOpts { get; set; } = new();
    public bool ReadonlyRootfs { get; set; }
    public List<ConfigurationRisk> Risks { get; set; } = new();
}

/// <summary>
/// Риск конфигурации
/// </summary>
public class ConfigurationRisk
{
    public string Type { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public int RiskWeight { get; set; }
}