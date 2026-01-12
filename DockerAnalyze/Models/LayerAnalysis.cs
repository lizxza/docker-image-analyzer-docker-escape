namespace DockerAnalyze.Models;

/// <summary>
/// Результаты анализа слоев образа
/// </summary>
public class LayerAnalysis
{
    public List<ImageLayer> Layers { get; set; } = new();
    public Dictionary<string, List<string>> LayerToRisks { get; set; } = new();
}

/// <summary>
/// Информация о слое образа
/// </summary>
public class ImageLayer
{
    public string LayerId { get; set; } = string.Empty;
    public string? ParentLayerId { get; set; }
    public long Size { get; set; }
    public DateTime Created { get; set; }
    public List<string> AddedFiles { get; set; } = new();
    public List<string> DeletedFiles { get; set; } = new();
    public List<string> ModifiedFiles { get; set; } = new();
    public List<string> Risks { get; set; } = new();
}