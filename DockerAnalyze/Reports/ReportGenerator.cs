using System.Text;
using System.Text.Json;
using DockerAnalyze.Models;

namespace DockerAnalyze.Reports;

/// <summary>
/// Генератор отчетов о результатах анализа
/// </summary>
public class ReportGenerator
{
    /// <summary>
    /// Выводит отчет в консоль
    /// </summary>
    public void PrintConsoleReport(AnalysisResult result)
    {
        Console.WriteLine("\n" + new string('=', 80));
        Console.WriteLine("           ОТЧЕТ ОБ АНАЛИЗЕ DOCKER-ОБРАЗА НА DOCKER ESCAPE");
        Console.WriteLine(new string('=', 80));
        Console.WriteLine();

        Console.WriteLine("ОБРАЗ:");
        Console.WriteLine($"  Имя: {result.ImageName}");
        Console.WriteLine($"  ID: {result.ImageId}");
        Console.WriteLine($"  Дата анализа: {result.AnalysisDate:yyyy-MM-dd HH:mm:ss} UTC");
        Console.WriteLine();

        Console.WriteLine("ОЦЕНКА РИСКА:");
        Console.WriteLine($"  Общий риск: {result.RiskAssessment.OverallRisk}/100");
        Console.WriteLine($"  Уровень риска: {GetRiskLevelColor(result.RiskAssessment.RiskLevel)}");
        Console.WriteLine();

        PrintRiskFactors(result);
        PrintVulnerabilities(result);
        PrintEvidence(result);
        PrintAnalysisDetails(result);
        
        if (result.Vulnerabilities.Count > 0)
        {
            Console.WriteLine($"  УЯЗВИМОСТИ:");
            var bySeverity = result.Vulnerabilities.GroupBy(v => v.Severity);
            Console.WriteLine($"    Всего найдено: {result.Vulnerabilities.Count}");
            foreach (var group in bySeverity)
            {
                Console.WriteLine($"      {group.Key}: {group.Count()}");
            }
            Console.WriteLine();
        }
        
        PrintRecommendations(result);

        Console.WriteLine(new string('=', 80));
        Console.WriteLine("Анализ завершен.");
        Console.WriteLine();
    }

    /// <summary>
    /// Выводит факторы риска
    /// </summary>
    private void PrintRiskFactors(AnalysisResult result)
    {
        Console.WriteLine("ФАКТОРЫ РИСКА:");
        Console.WriteLine(new string('-', 80));

        var factorsByCategory = result.RiskAssessment.RiskFactors
            .GroupBy(f => f.Category)
            .OrderByDescending(g => g.Sum(f => f.Weight));

        foreach (var category in factorsByCategory)
        {
            Console.WriteLine($"\n  [{category.Key}]");
            foreach (var factor in category.OrderByDescending(f => f.Weight))
            {
                string weightStr = factor.Weight >= 25 ? $"{factor.Weight}" : $"   {factor.Weight}";
                Console.WriteLine($"    {weightStr} | {factor.Description}");
                if (!string.IsNullOrEmpty(factor.Evidence))
                {
                    Console.WriteLine($"         └─ Доказательство: {factor.Evidence}");
                }
                if (!string.IsNullOrEmpty(factor.Layer) && factor.Layer != "base" && factor.Layer != "combined")
                {
                    Console.WriteLine($"         └─ Слой: {factor.Layer}");
                }
            }
        }

        Console.WriteLine();
    }

    /// <summary>
    /// Выводит найденные уязвимости
    /// </summary>
    private void PrintVulnerabilities(AnalysisResult result)
    {
        if (result.Vulnerabilities.Count == 0)
            return;

        Console.WriteLine("НАЙДЕННЫЕ УЯЗВИМОСТИ И ПРОБЛЕМЫ БЕЗОПАСНОСТИ:");
        Console.WriteLine(new string('-', 80));

        var bySeverity = result.Vulnerabilities
            .GroupBy(v => v.Severity)
            .OrderByDescending(g => g.Key == "CRITICAL" ? 4 : g.Key == "HIGH" ? 3 : g.Key == "MEDIUM" ? 2 : 1);

        foreach (var severityGroup in bySeverity)
        {
            string severityIcon = severityGroup.Key switch
            {
                "CRITICAL" => "!",
                "HIGH" => "$",
                "MEDIUM" => "#",
                "LOW" => "@",
                _ => "?"
            };

            Console.WriteLine($"\n  {severityIcon} {severityGroup.Key} ({severityGroup.Count()}):");
            foreach (var vuln in severityGroup)
            {
                Console.WriteLine($"    --- {vuln.Title}");
                Console.WriteLine($"      Описание: {vuln.Description}");
                Console.WriteLine($"      Доказательство: {vuln.Evidence}");
                if (!string.IsNullOrEmpty(vuln.Layer) && vuln.Layer != "unknown")
                {
                    Console.WriteLine($"      Слой: {vuln.Layer}");
                }
                if (!string.IsNullOrEmpty(vuln.Recommendation))
                {
                    Console.WriteLine($"      Рекомендация: {vuln.Recommendation}");
                }
                Console.WriteLine();
            }
        }

        Console.WriteLine();
    }

    /// <summary>
    /// Выводит доказательства
    /// </summary>
    private void PrintEvidence(AnalysisResult result)
    {
        if (result.RiskAssessment.Evidence.Count == 0)
            return;

        Console.WriteLine("ДОКАЗАТЕЛЬСТВА:");
        Console.WriteLine(new string('-', 80));
        foreach (var evidence in result.RiskAssessment.Evidence)
        {
            Console.WriteLine($"  • {evidence}");
        }
        Console.WriteLine();
    }

    /// <summary>
    /// Выводит детали анализа
    /// </summary>
    private void PrintAnalysisDetails(AnalysisResult result)
    {
        Console.WriteLine("ДЕТАЛИ АНАЛИЗА:");
        Console.WriteLine(new string('-', 80));

        if (result.FileSystemAnalysis != null)
        {
            var fs = result.FileSystemAnalysis;
            Console.WriteLine($"\n  ФАЙЛОВАЯ СИСТЕМА:");
            Console.WriteLine($"    Опасных бинарников: {fs.DangerousBinaries.Count}");
            Console.WriteLine($"    SetUID/SetGID файлов: {fs.SetUidFiles.Count}");
            Console.WriteLine($"    Записываемых системных директорий: {fs.WritableDirectories.Count}");
            Console.WriteLine($"    Файлов с небезопасными правами: {fs.InsecurePermissions.Count}");

            if (fs.PasswdShadowAnalysis != null)
            {
                var passwd = fs.PasswdShadowAnalysis;
                Console.WriteLine($"    /etc/passwd найден: {passwd.PasswdExists}");
                Console.WriteLine($"    /etc/shadow найден: {passwd.ShadowExists}");
                Console.WriteLine($"    Пользователей в passwd: {passwd.PasswdEntries.Count}");
                Console.WriteLine($"    Root пользователь: {passwd.HasRootUser}");
            }

            if (fs.DangerousBinaries.Count > 0)
            {
                Console.WriteLine($"\n    Топ-5 опасных бинарников:");
                foreach (var binary in fs.DangerousBinaries.OrderByDescending(b => b.RiskWeight).Take(5))
                {
                    Console.WriteLine($"      --- {binary.BinaryType} ({binary.RiskWeight}) - {binary.Path}");
                }
            }
        }

        if (result.ConfigurationAnalysis != null)
        {
            var config = result.ConfigurationAnalysis;
            Console.WriteLine($"\n  КОНФИГУРАЦИЯ:");
            Console.WriteLine($"    User: {config.User ?? "не указан (root)"}");
            Console.WriteLine($"    Запуск от root: {config.RunsAsRoot}");
            Console.WriteLine($"    Entrypoint: {config.Entrypoint ?? "не указан"}");
            Console.WriteLine($"    Cmd: {config.Cmd ?? "не указан"}");
            Console.WriteLine($"    Capabilities: {config.Capabilities.Count}");
            Console.WriteLine($"    Privileged: {config.Privileged}");
            Console.WriteLine($"    ReadonlyRootfs: {config.ReadonlyRootfs}");
            Console.WriteLine($"    SecurityOpts: {config.SecurityOpts.Count}");
            Console.WriteLine($"    Рисков конфигурации: {config.Risks.Count}");
        }

        if (result.DockerfileAnalysis != null)
        {
            var dockerfile = result.DockerfileAnalysis;
            Console.WriteLine($"\n  DOCKERFILE:");
            Console.WriteLine($"    Найден: {dockerfile.DockerfileFound}");
            if (dockerfile.DockerfileFound)
            {
                Console.WriteLine($"    Путь: {dockerfile.DockerfilePath}");
                Console.WriteLine($"    USER инструкция: {dockerfile.UserInstruction ?? "не найдена"}");
                Console.WriteLine($"    RUN инструкций: {dockerfile.RunInstructions.Count}");
                Console.WriteLine($"    ADD/COPY инструкций: {dockerfile.AddCopyInstructions.Count}");
            }
            else
            {
                Console.WriteLine($"    Причина: {dockerfile.AbsenceReason}");
            }
            Console.WriteLine($"    Рисков в Dockerfile: {dockerfile.Risks.Count}");
        }

        if (result.LayerAnalysis != null)
        {
            var layers = result.LayerAnalysis;
            Console.WriteLine($"\n  СЛОИ:");
            Console.WriteLine($"    Всего слоев: {layers.Layers.Count}");
            foreach (var layer in layers.Layers.Take(5))
            {
                Console.WriteLine($"      --- {layer.LayerId} (создан: {layer.Created:yyyy-MM-dd}, рисков: {layer.Risks.Count})");
            }
            if (layers.Layers.Count > 5)
            {
                Console.WriteLine($"      ... и еще {layers.Layers.Count - 5} слоев");
            }
        }

        Console.WriteLine();
    }

    /// <summary>
    /// Выводит рекомендации
    /// </summary>
    private void PrintRecommendations(AnalysisResult result)
    {
        if (result.RiskAssessment.Recommendations.Count == 0)
            return;

        Console.WriteLine("РЕКОМЕНДАЦИИ ПО СНИЖЕНИЮ РИСКА:");
        Console.WriteLine(new string('-', 80));
        int index = 1;
        foreach (var recommendation in result.RiskAssessment.Recommendations)
        {
            Console.WriteLine($"  {index}. {recommendation}");
            index++;
        }
        Console.WriteLine();
    }

    /// <summary>
    /// Получает цветной вывод уровня риска
    /// </summary>
    private string GetRiskLevelColor(string level)
    {
        return level switch
        {
            "Low" => "@ Low",
            "Medium" => "# Medium",
            "High" => "$ High",
            "Critical" => "! Critical",
            _ => level
        };
    }

    /// <summary>
    /// Сохраняет отчет в JSON файл
    /// </summary>
    public async Task SaveJsonReportAsync(AnalysisResult result, string outputPath)
    {
        var options = new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };

        var report = new
        {
            ImageName = result.ImageName,
            ImageId = result.ImageId,
            AnalysisDate = result.AnalysisDate,
            RiskAssessment = new
            {
                OverallRisk = result.RiskAssessment.OverallRisk,
                RiskLevel = result.RiskAssessment.RiskLevel,
                RiskFactors = result.RiskAssessment.RiskFactors.Select(f => new
                {
                    f.Category,
                    f.Description,
                    f.Weight,
                    f.Evidence,
                    f.Layer
                }),
                Evidence = result.RiskAssessment.Evidence,
                Recommendations = result.RiskAssessment.Recommendations
            },
            FileSystemAnalysis = result.FileSystemAnalysis != null ? new
            {
                DangerousBinariesCount = result.FileSystemAnalysis.DangerousBinaries.Count,
                DangerousBinaries = result.FileSystemAnalysis.DangerousBinaries.Select(b => new
                {
                    b.Path,
                    b.BinaryType,
                    b.Layer,
                    b.Permissions,
                    b.RiskWeight
                }),
                SetUidFilesCount = result.FileSystemAnalysis.SetUidFiles.Count,
                SetUidFiles = result.FileSystemAnalysis.SetUidFiles.Select(s => new
                {
                    s.Path,
                    s.IsSetUid,
                    s.IsSetGid,
                    s.Layer,
                    s.Permissions
                }),
                WritableDirectoriesCount = result.FileSystemAnalysis.WritableDirectories.Count,
                WritableDirectories = result.FileSystemAnalysis.WritableDirectories.Select(w => new
                {
                    w.Path,
                    w.Layer,
                    w.IsSystemDirectory
                }),
                InsecurePermissionsCount = result.FileSystemAnalysis.InsecurePermissions.Count,
                InsecurePermissions = result.FileSystemAnalysis.InsecurePermissions.Select(i => new
                {
                    i.Path,
                    i.Permissions,
                    i.Layer,
                    i.IsWorldWritable,
                    i.IsWorldReadable
                }),
                PasswdShadowAnalysis = result.FileSystemAnalysis.PasswdShadowAnalysis != null ? new
                {
                    result.FileSystemAnalysis.PasswdShadowAnalysis.PasswdExists,
                    result.FileSystemAnalysis.PasswdShadowAnalysis.ShadowExists,
                    result.FileSystemAnalysis.PasswdShadowAnalysis.HasRootUser,
                    result.FileSystemAnalysis.PasswdShadowAnalysis.HasRootWithoutPassword,
                    result.FileSystemAnalysis.PasswdShadowAnalysis.Layer,
                    UsersCount = result.FileSystemAnalysis.PasswdShadowAnalysis.PasswdEntries.Count
                } : null
            } : null,
            Vulnerabilities = result.Vulnerabilities.Select(v => new
            {
                v.Type,
                v.Severity,
                v.Title,
                v.Description,
                v.Evidence,
                v.Layer,
                v.Recommendation
            }),
            ConfigurationAnalysis = result.ConfigurationAnalysis != null ? new
            {
                result.ConfigurationAnalysis.User,
                result.ConfigurationAnalysis.RunsAsRoot,
                result.ConfigurationAnalysis.Entrypoint,
                result.ConfigurationAnalysis.Cmd,
                CapabilitiesCount = result.ConfigurationAnalysis.Capabilities.Count,
                Capabilities = result.ConfigurationAnalysis.Capabilities,
                result.ConfigurationAnalysis.Privileged,
                SecurityOptsCount = result.ConfigurationAnalysis.SecurityOpts.Count,
                SecurityOpts = result.ConfigurationAnalysis.SecurityOpts,
                result.ConfigurationAnalysis.ReadonlyRootfs,
                RisksCount = result.ConfigurationAnalysis.Risks.Count,
                Risks = result.ConfigurationAnalysis.Risks.Select(r => new
                {
                    r.Type,
                    r.Description,
                    r.RiskWeight
                })
            } : null,
            DockerfileAnalysis = result.DockerfileAnalysis != null ? new
            {
                result.DockerfileAnalysis.DockerfileFound,
                result.DockerfileAnalysis.DockerfilePath,
                result.DockerfileAnalysis.UserInstruction,
                RunInstructionsCount = result.DockerfileAnalysis.RunInstructions.Count,
                AddCopyInstructionsCount = result.DockerfileAnalysis.AddCopyInstructions.Count,
                RisksCount = result.DockerfileAnalysis.Risks.Count,
                Risks = result.DockerfileAnalysis.Risks.Select(r => new
                {
                    r.Type,
                    r.Description,
                    r.LineNumber,
                    r.RiskWeight
                }),
                result.DockerfileAnalysis.AbsenceReason
            } : null,
            LayerAnalysis = result.LayerAnalysis != null ? new
            {
                LayersCount = result.LayerAnalysis.Layers.Count,
                Layers = result.LayerAnalysis.Layers.Select(l => new
                {
                    l.LayerId,
                    l.ParentLayerId,
                    l.Size,
                    l.Created,
                    AddedFilesCount = l.AddedFiles.Count,
                    DeletedFilesCount = l.DeletedFiles.Count,
                    ModifiedFilesCount = l.ModifiedFiles.Count,
                    RisksCount = l.Risks.Count,
                    Risks = l.Risks
                })
            } : null
        };

        string json = JsonSerializer.Serialize(report, options);
        await File.WriteAllTextAsync(outputPath, json, Encoding.UTF8);
        
        Console.WriteLine($"[+] JSON отчет сохранен: {outputPath}");
    }
}