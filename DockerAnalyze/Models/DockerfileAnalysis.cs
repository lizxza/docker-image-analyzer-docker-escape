namespace DockerAnalyze.Models;

/// <summary>
/// Результаты анализа Dockerfile
/// </summary>
public class DockerfileAnalysis
{
    public bool DockerfileFound { get; set; }
    public string? DockerfilePath { get; set; }
    public string? UserInstruction { get; set; }
    public List<RunInstruction> RunInstructions { get; set; } = new();
    public List<AddCopyInstruction> AddCopyInstructions { get; set; } = new();
    public List<DockerfileRisk> Risks { get; set; } = new();
    public string? AbsenceReason { get; set; }
}

/// <summary>
/// Инструкция RUN из Dockerfile
/// </summary>
public class RunInstruction
{
    public string Command { get; set; } = string.Empty;
    public int LineNumber { get; set; }
    public bool ContainsChmod { get; set; }
    public bool ContainsChown { get; set; }
    public bool ContainsMount { get; set; }
    public bool ContainsAptInstall { get; set; }
    public bool ContainsDangerousPackage { get; set; }
}

/// <summary>
/// Инструкция ADD/COPY из Dockerfile
/// </summary>
public class AddCopyInstruction
{
    public string Type { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string Destination { get; set; } = string.Empty;
    public int LineNumber { get; set; }
}

/// <summary>
/// Риск из Dockerfile
/// </summary>
public class DockerfileRisk
{
    public string Type { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public int LineNumber { get; set; }
    public int RiskWeight { get; set; }
}