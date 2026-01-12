using System.Text.RegularExpressions;
using DockerAnalyze.Models;

namespace DockerAnalyze.Analyzers;

/// <summary>
/// Анализатор Dockerfile
/// </summary>
public class DockerfileAnalyzer
{
    private readonly HashSet<string> _dangerousPackages = new(StringComparer.OrdinalIgnoreCase)
    {
        "gcc", "make", "build-essential", "python-dev", "python3-dev",
        "g++", "cmake", "autoconf", "automake", "libtool"
    };

    /// <summary>
    /// Анализирует Dockerfile образа
    /// </summary>
    public async Task<DockerfileAnalysis> AnalyzeAsync(string imageName, string extractedPath)
    {
        var analysis = new DockerfileAnalysis();

        await Task.Run(() =>
        {
            string? dockerfilePath = FindDockerfile(extractedPath, imageName);

            if (dockerfilePath != null && File.Exists(dockerfilePath))
            {
                analysis.DockerfileFound = true;
                analysis.DockerfilePath = dockerfilePath;
                ParseDockerfile(dockerfilePath, analysis);
            }
            else
            {
                analysis.DockerfileFound = false;
                analysis.AbsenceReason = "Dockerfile не найден в распакованном образе. Это нормально для многих публичных образов, где Dockerfile хранится отдельно в репозитории.";
                
                analysis.Risks.Add(new DockerfileRisk
                {
                    Type = "DOCKERFILE_NOT_FOUND",
                    Description = "Dockerfile не найден в образе. Невозможно проверить историю изменений и инструкции сборки.",
                    LineNumber = 0,
                    RiskWeight = 5
                });
            }

            AnalyzeDockerfileRisks(analysis);
        });

        return analysis;
    }

    /// <summary>
    /// Ищет Dockerfile в распакованном образе
    /// </summary>
    private string? FindDockerfile(string extractedPath, string imageName)
    {
        var searchPaths = new[]
        {
            Path.Combine(extractedPath, "Dockerfile"),
            Path.Combine(extractedPath, "dockerfile"),
            Path.Combine(extractedPath, "Dockerfile.txt")
        };

        foreach (var path in searchPaths)
        {
            if (File.Exists(path))
                return path;
        }

        try
        {
            var files = Directory.GetFiles(extractedPath, "Dockerfile*", SearchOption.AllDirectories);
            if (files.Length > 0)
                return files[0];

            var layerDirs = Directory.GetDirectories(extractedPath);
            foreach (var layerDir in layerDirs)
            {
                var layerFiles = Directory.GetFiles(layerDir, "*Dockerfile*", SearchOption.AllDirectories);
                if (layerFiles.Length > 0)
                    return layerFiles[0];
            }
        }
        catch
        {
            
        }

        return null;
    }

    /// <summary>
    /// Парсит Dockerfile
    /// </summary>
    private void ParseDockerfile(string dockerfilePath, DockerfileAnalysis analysis)
    {
        try
        {
            var lines = File.ReadAllLines(dockerfilePath);
            int lineNumber = 0;

            foreach (var line in lines)
            {
                lineNumber++;
                string trimmedLine = line.Trim();

                if (string.IsNullOrWhiteSpace(trimmedLine) || trimmedLine.StartsWith('#'))
                    continue;

                if (trimmedLine.StartsWith("USER", StringComparison.OrdinalIgnoreCase))
                {
                    ParseUserInstruction(trimmedLine, lineNumber, analysis);
                }
                else if (trimmedLine.StartsWith("RUN", StringComparison.OrdinalIgnoreCase))
                {
                    ParseRunInstruction(trimmedLine, lineNumber, analysis);
                }
                else if (trimmedLine.StartsWith("ADD", StringComparison.OrdinalIgnoreCase) ||
                         trimmedLine.StartsWith("COPY", StringComparison.OrdinalIgnoreCase))
                {
                    ParseAddCopyInstruction(trimmedLine, lineNumber, analysis);
                }
            }
        }
        catch (Exception ex)
        {
            analysis.Risks.Add(new DockerfileRisk
            {
                Type = "PARSE_ERROR",
                Description = $"Ошибка при парсинге Dockerfile: {ex.Message}",
                LineNumber = 0,
                RiskWeight = 0
            });
        }
    }

    /// <summary>
    /// Парсит инструкцию USER
    /// </summary>
    private void ParseUserInstruction(string line, int lineNumber, DockerfileAnalysis analysis)
    {
        var match = Regex.Match(line, @"USER\s+(\S+)", RegexOptions.IgnoreCase);
        if (match.Success)
        {
            string user = match.Groups[1].Value;
            analysis.UserInstruction = user;

            if (user == "root" || user == "0")
            {
                analysis.Risks.Add(new DockerfileRisk
                {
                    Type = "USER_ROOT",
                    Description = $"Инструкция USER указывает на root (строка {lineNumber})",
                    LineNumber = lineNumber,
                    RiskWeight = 20
                });
            }
        }
    }

    /// <summary>
    /// Парсит инструкцию RUN
    /// </summary>
    private void ParseRunInstruction(string line, int lineNumber, DockerfileAnalysis analysis)
    {
        string command = Regex.Replace(line, @"^RUN\s+", "", RegexOptions.IgnoreCase).Trim();

        var runInstruction = new RunInstruction
        {
            Command = command,
            LineNumber = lineNumber
        };

        runInstruction.ContainsChmod = command.Contains("chmod", StringComparison.OrdinalIgnoreCase);
        runInstruction.ContainsChown = command.Contains("chown", StringComparison.OrdinalIgnoreCase);
        runInstruction.ContainsMount = command.Contains("mount", StringComparison.OrdinalIgnoreCase);
        runInstruction.ContainsAptInstall = command.Contains("apt install", StringComparison.OrdinalIgnoreCase) ||
                                           command.Contains("apt-get install", StringComparison.OrdinalIgnoreCase);

        foreach (var package in _dangerousPackages)
        {
            if (command.Contains(package, StringComparison.OrdinalIgnoreCase))
            {
                runInstruction.ContainsDangerousPackage = true;
                break;
            }
        }

        if (runInstruction.ContainsChmod)
        {
            var chmodMatch = Regex.Match(command, @"chmod\s+([0-7]{3,4})", RegexOptions.IgnoreCase);
            if (chmodMatch.Success)
            {
                string permissions = chmodMatch.Groups[1].Value;
                if (permissions.Contains("777") || permissions.Contains("666"))
                {
                    analysis.Risks.Add(new DockerfileRisk
                    {
                        Type = "INSECURE_CHMOD",
                        Description = $"Найдена инструкция chmod с небезопасными правами {permissions} (строка {lineNumber}): {command}",
                        LineNumber = lineNumber,
                        RiskWeight = 15
                    });
                }
            }
        }

        if (runInstruction.ContainsMount)
        {
            analysis.Risks.Add(new DockerfileRisk
            {
                Type = "MOUNT_COMMAND",
                Description = $"Найдена команда mount в RUN (строка {lineNumber}): {command}",
                LineNumber = lineNumber,
                RiskWeight = 25
            });
        }

        if (runInstruction.ContainsDangerousPackage)
        {
            analysis.Risks.Add(new DockerfileRisk
            {
                Type = "BUILD_TOOLS",
                Description = $"Установка инструментов сборки в RUN (строка {lineNumber}): {command}",
                LineNumber = lineNumber,
                RiskWeight = 10
            });
        }

        analysis.RunInstructions.Add(runInstruction);
    }

    /// <summary>
    /// Парсит инструкции ADD и COPY
    /// </summary>
    private void ParseAddCopyInstruction(string line, int lineNumber, DockerfileAnalysis analysis)
    {
        var match = Regex.Match(line, @"^(ADD|COPY)\s+(.+?)\s+(.+?)(?:\s+#.*)?$", RegexOptions.IgnoreCase);
        if (match.Success)
        {
            string type = match.Groups[1].Value.ToUpper();
            string source = match.Groups[2].Value.Trim();
            string destination = match.Groups[3].Value.Trim();

            analysis.AddCopyInstructions.Add(new AddCopyInstruction
            {
                Type = type,
                Source = source,
                Destination = destination,
                LineNumber = lineNumber
            });

            if (source.Contains("passwd", StringComparison.OrdinalIgnoreCase) ||
                source.Contains("shadow", StringComparison.OrdinalIgnoreCase) ||
                source.Contains("id_rsa", StringComparison.OrdinalIgnoreCase) ||
                source.Contains(".pem", StringComparison.OrdinalIgnoreCase))
            {
                analysis.Risks.Add(new DockerfileRisk
                {
                    Type = "SENSITIVE_FILE_COPY",
                    Description = $"{type} копирует потенциально чувствительный файл (строка {lineNumber}): {source}",
                    LineNumber = lineNumber,
                    RiskWeight = 20
                });
            }
        }
    }

    /// <summary>
    /// Анализирует риски в Dockerfile
    /// </summary>
    private void AnalyzeDockerfileRisks(DockerfileAnalysis analysis)
    {
        if (string.IsNullOrEmpty(analysis.UserInstruction))
        {
            analysis.Risks.Add(new DockerfileRisk
            {
                Type = "NO_USER_INSTRUCTION",
                Description = "Dockerfile не содержит инструкцию USER, образ будет запускаться от root",
                LineNumber = 0,
                RiskWeight = 20
            });
        }
    }
}