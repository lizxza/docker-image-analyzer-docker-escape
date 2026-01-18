using System.Text.Json;
using DockerAnalyze.Models;

namespace DockerAnalyze.Analyzers;

/// <summary>
/// Анализатор слоев Docker-образа
/// </summary>
public class LayerAnalyzer
{
    private readonly string _extractedPath;

    public LayerAnalyzer(string extractedPath)
    {
        _extractedPath = extractedPath;
    }

    /// <summary>
    /// Анализирует слои образа
    /// </summary>
    public async Task<LayerAnalysis> AnalyzeAsync(string tarPath)
    {
        var analysis = new LayerAnalysis();

        await Task.Run(() =>
        {
            string manifestPath = Path.Combine(_extractedPath, "manifest.json");
            if (File.Exists(manifestPath))
            {
                ParseManifest(manifestPath, analysis);
            }

            // Анализируем каждый слой
            foreach (var layer in analysis.Layers)
            {
                AnalyzeLayer(layer, analysis);
            }
        });

        return analysis;
    }

    /// <summary>
    /// Парсит manifest.json для получения информации о слоях
    /// </summary>
    private void ParseManifest(string manifestPath, LayerAnalysis analysis)
    {
        try
        {
            string json = File.ReadAllText(manifestPath);
            using var doc = JsonDocument.Parse(json);

            if (doc.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in doc.RootElement.EnumerateArray())
                {
                    if (item.TryGetProperty("Layers", out var layers))
                    {
                        int layerIndex = 0;
                        foreach (var layerElement in layers.EnumerateArray())
                        {
                            string layerPath = layerElement.GetString() ?? "";
                            
                            string layerId = ExtractLayerId(layerPath, layerIndex);

                            var layer = new ImageLayer
                            {
                                LayerId = layerId,
                                Size = 0,
                                Created = DateTime.MinValue
                            };

                            if (layerIndex > 0 && analysis.Layers.Count > 0)
                            {
                                layer.ParentLayerId = analysis.Layers[layerIndex - 1].LayerId;
                            }

                            analysis.Layers.Add(layer);
                            layerIndex++;
                        }
                    }

                    if (item.TryGetProperty("Config", out var config))
                    {
                        string configPath = config.GetString() ?? "";
                        ParseConfigFile(configPath, analysis);
                    }
                }
            }
        }
        catch
        {
            CreateBasicLayerStructure(analysis);
        }
    }

    /// <summary>
    /// Парсит config файл для получения информации о слоях
    /// </summary>
    private void ParseConfigFile(string configPath, LayerAnalysis analysis)
    {
        try
        {
            string fullPath = Path.Combine(_extractedPath, configPath);
            if (!File.Exists(fullPath))
                return;

            string json = File.ReadAllText(fullPath);
            using var doc = JsonDocument.Parse(json);

            var root = doc.RootElement;

            if (root.TryGetProperty("history", out var history))
            {
                ParseHistoryForRisks(history, analysis);

                int layerIndex = 0;
                foreach (var historyItem in history.EnumerateArray())
                {
                    if (layerIndex < analysis.Layers.Count)
                    {
                        var layer = analysis.Layers[layerIndex];
                        
                        if (historyItem.TryGetProperty("created", out var created))
                        {
                            if (DateTime.TryParse(created.GetString(), out DateTime createdDate))
                            {
                                layer.Created = createdDate;
                            }
                        }

                        if (historyItem.TryGetProperty("comment", out var comment))
                        {
                            string commentStr = comment.GetString() ?? "";
                            AnalyzeLayerComment(commentStr, layer);
                        }
                    }
                    layerIndex++;
                }
            }

            // Получаем размеры слоев
            if (root.TryGetProperty("rootfs", out var rootfs))
            {
                if (rootfs.TryGetProperty("diff_ids", out var diffIds))
                {
                    int diffIndex = 0;
                    foreach (var diffId in diffIds.EnumerateArray())
                    {
                        if (diffIndex < analysis.Layers.Count)
                        {
                            string diffIdStr = diffId.GetString() ?? "";
                        }
                        diffIndex++;
                    }
                }
            }
        }
        catch
        {
        }
    }

    /// <summary>
    /// Парсит историю слоев для поиска рисков
    /// </summary>
    private void ParseHistoryForRisks(JsonElement history, LayerAnalysis analysis)
    {
        int layerIndex = 0;
        foreach (var historyItem in history.EnumerateArray())
        {
            if (layerIndex < analysis.Layers.Count)
            {
                var layer = analysis.Layers[layerIndex];
                
                if (historyItem.TryGetProperty("created_by", out var createdBy))
                {
                    string? command = createdBy.GetString();
                    if (!string.IsNullOrEmpty(command))
                    {
                        AnalyzeCommandForRisks(command, layer);
                    }
                }

                if (historyItem.TryGetProperty("empty_layer", out var emptyLayer))
                {
                    bool isEmpty = emptyLayer.GetBoolean();
                    if (isEmpty)
                    {
                        layer.Risks.Add("Пустой слой (может быть использован для скрытия изменений)");
                    }
                }
            }
            layerIndex++;
        }
    }

    /// <summary>
    /// Анализирует команду создания слоя на наличие рисков
    /// </summary>
    private void AnalyzeCommandForRisks(string command, ImageLayer layer)
    {
        command = command.ToLower();

        var dangerousPatterns = new[]
        {
            ("chmod 777", "Небезопасные права доступа 777"),
            ("chmod 666", "Небезопасные права доступа 666"),
            ("chmod +s", "SetUID бит установлен"),
            ("mount ", "Команда mount в слое"),
            ("nsenter", "Утилита nsenter установлена"),
            ("rm -rf /", "Опасная команда удаления"),
            ("curl.*http://", "HTTP запрос (не HTTPS)"),
            ("wget.*http://", "HTTP запрос (не HTTPS)")
        };

        foreach (var (pattern, description) in dangerousPatterns)
        {
            if (command.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                layer.Risks.Add($"Команда создания слоя: {description}");
            }
        }

        if (command.Contains("apt install") || command.Contains("apt-get install") || command.Contains("yum install"))
        {
            var dangerousPackages = new[] { "gcc", "make", "build-essential", "python-dev" };
            foreach (var package in dangerousPackages)
            {
                if (command.Contains(package))
                {
                    layer.Risks.Add($"Установка инструментов сборки: {package}");
                }
            }
        }
    }

    /// <summary>
    /// Анализирует комментарий слоя на наличие рисков
    /// </summary>
    private void AnalyzeLayerComment(string comment, ImageLayer layer)
    {
        var riskKeywords = new[]
        {
            "chmod 777", "chmod 666", "mount", "nsenter",
            "apt install", "yum install", "apk add"
        };

        foreach (var keyword in riskKeywords)
        {
            if (comment.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                layer.Risks.Add($"Комментарий слоя содержит: {keyword}");
            }
        }
    }

    /// <summary>
    /// Извлекает ID слоя из пути
    /// </summary>
    private string ExtractLayerId(string layerPath, int index)
    {
        var parts = layerPath.Split('/', '\\');
        foreach (var part in parts)
        {
            if (part.Length >= 12)
            {
                string cleaned = part.Replace(".tar", "");
                if (System.Text.RegularExpressions.Regex.IsMatch(cleaned, @"^[a-f0-9]{12,}$"))
                {
                    return cleaned.Substring(0, 12);
                }
            }
        }

        return $"layer_{index}";
    }

    /// <summary>
    /// Анализирует конкретный слой
    /// </summary>
    private void AnalyzeLayer(ImageLayer layer, LayerAnalysis analysis)
    {
        string? layerDir = FindLayerDirectory(layer.LayerId);
        
        if (string.IsNullOrEmpty(layerDir))
            return;

        AnalyzeLayerChanges(layerDir, layer);

        if (layer.Risks.Count > 0)
        {
            analysis.LayerToRisks[layer.LayerId] = layer.Risks;
        }
    }

    /// <summary>
    /// Находит директорию слоя по ID
    /// </summary>
    private string? FindLayerDirectory(string layerId)
    {
        if (!Directory.Exists(_extractedPath))
            return null;

        foreach (var dir in Directory.GetDirectories(_extractedPath))
        {
            string dirName = Path.GetFileName(dir) ?? "";
            if (dirName.StartsWith(layerId, StringComparison.OrdinalIgnoreCase) ||
                dirName.Contains(layerId, StringComparison.OrdinalIgnoreCase))
            {
                return dir;
            }
        }

        var tarFiles = Directory.GetFiles(_extractedPath, "layer.tar", SearchOption.AllDirectories);
        if (tarFiles.Length > 0)
        {
            return Path.GetDirectoryName(tarFiles[0]);
        }

        return null;
    }

    /// <summary>
    /// Анализирует изменения в слое
    /// </summary>
    private void AnalyzeLayerChanges(string layerDir, ImageLayer layer)
    {
        string layerPath = Path.Combine(layerDir, "layer");
        
        if (!Directory.Exists(layerPath))
        {
            string tarPath = Path.Combine(layerDir, "layer.tar");
            if (File.Exists(tarPath))
            {
                return;
            }
            return;
        }

        AnalyzeFilesInLayer(layerPath, layer);
    }

    /// <summary>
    /// Анализирует файлы в слое
    /// </summary>
    private void AnalyzeFilesInLayer(string layerPath, ImageLayer layer, int depth = 0)
    {
        if (depth > 20) return;

        try
        {
            foreach (var file in Directory.GetFiles(layerPath))
            {
                string fileName = Path.GetFileName(file);
                string relativePath = Path.GetRelativePath(layerPath, file);

                layer.AddedFiles.Add(relativePath);

                if (IsDangerousFile(fileName))
                {
                    layer.Risks.Add($"Добавлен опасный файл: {relativePath}");
                }
            }

            foreach (var dir in Directory.GetDirectories(layerPath))
            {
                string dirName = Path.GetFileName(dir) ?? "";
                if (dirName == "proc" || dirName == "sys" || dirName == "dev")
                    continue;

                AnalyzeFilesInLayer(dir, layer, depth + 1);
            }
        }
        catch
        {
        }
    }

    /// <summary>
    /// Проверяет, является ли файл опасным
    /// </summary>
    private bool IsDangerousFile(string fileName)
    {
        var dangerousNames = new[]
        {
            "mount", "umount", "nsenter", "su", "sudo"
        };

        return dangerousNames.Contains(fileName, StringComparer.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Создает базовую структуру слоев если manifest не найден
    /// </summary>
    private void CreateBasicLayerStructure(LayerAnalysis analysis)
    {
        if (analysis.Layers.Count == 0)
        {
            analysis.Layers.Add(new ImageLayer
            {
                LayerId = "base",
                Created = DateTime.MinValue
            });
        }
    }
}