using DockerAnalyze.Models;

namespace DockerAnalyze.RiskEngine;

/// <summary>
/// Движок оценки рисков Docker Escape с контекстной моделью
/// </summary>
public class RiskEngine
{
    /// <summary>
    /// Вычисляет общую оценку риска на основе всех данных анализа
    /// </summary>
    public RiskAssessment AssessRisk(AnalysisResult analysis)
    {
        var assessment = new RiskAssessment
        {
            RiskFactors = new List<RiskFactor>(),
            Evidence = new List<string>(),
            Recommendations = new List<string>(),
            FactorWeights = new Dictionary<string, int>()
        };

        CollectFileSystemRisks(analysis, assessment);
        CollectConfigurationRisks(analysis, assessment);
        CollectDockerfileRisks(analysis, assessment);
        CollectLayerRisks(analysis, assessment);
        CollectVulnerabilityRisks(analysis, assessment);

        AssessCombinationRisks(analysis, assessment);

        assessment.OverallRisk = CalculateOverallRisk(assessment);
        assessment.RiskLevel = DetermineRiskLevel(assessment.OverallRisk);

        GenerateRecommendations(analysis, assessment);

        return assessment;
    }

    /// <summary>
    /// Собирает факторы риска из анализа файловой системы
    /// </summary>
    private void CollectFileSystemRisks(AnalysisResult analysis, RiskAssessment assessment)
    {
        if (analysis.FileSystemAnalysis == null)
            return;

        var fs = analysis.FileSystemAnalysis;

        foreach (var binary in fs.DangerousBinaries)
        {
            assessment.RiskFactors.Add(new RiskFactor
            {
                Category = "FILE_SYSTEM",
                Description = $"Обнаружен опасный бинарник: {binary.BinaryType}",
                Weight = binary.RiskWeight,
                Evidence = $"Путь: {binary.Path}, Права: {binary.Permissions}",
                Layer = binary.Layer
            });

            assessment.Evidence.Add($"{binary.BinaryType} найден в {binary.Path} (слой: {binary.Layer})");
        }

        foreach (var setUidFile in fs.SetUidFiles)
        {
            int weight = (setUidFile.IsSetUid ? 15 : 0) + (setUidFile.IsSetGid ? 10 : 0);
            
            assessment.RiskFactors.Add(new RiskFactor
            {
                Category = "FILE_SYSTEM",
                Description = $"SetUID/SetGID файл: {setUidFile.Path}",
                Weight = weight,
                Evidence = $"SetUID: {setUidFile.IsSetUid}, SetGID: {setUidFile.IsSetGid}, Права: {setUidFile.Permissions}",
                Layer = setUidFile.Layer
            });
        }

        foreach (var writableDir in fs.WritableDirectories)
        {
            assessment.RiskFactors.Add(new RiskFactor
            {
                Category = "FILE_SYSTEM",
                Description = $"Записываемая системная директория: {writableDir.Path}",
                Weight = 20,
                Evidence = $"Директория {writableDir.Path} доступна для записи",
                Layer = writableDir.Layer
            });

            assessment.Evidence.Add($"Writable системная директория: {writableDir.Path}");
        }

        foreach (var insecurePerm in fs.InsecurePermissions)
        {
            int weight = insecurePerm.IsWorldWritable ? 15 : 8;
            
            assessment.RiskFactors.Add(new RiskFactor
            {
                Category = "FILE_SYSTEM",
                Description = $"Небезопасные права доступа: {insecurePerm.Permissions}",
                Weight = weight,
                Evidence = $"Файл: {insecurePerm.Path}, Права: {insecurePerm.Permissions}",
                Layer = insecurePerm.Layer
            });
        }

        if (fs.PasswdShadowAnalysis != null)
        {
            var passwd = fs.PasswdShadowAnalysis;
            
            if (passwd.HasRootUser)
            {
                assessment.RiskFactors.Add(new RiskFactor
                {
                    Category = "AUTHENTICATION",
                    Description = "Найден пользователь root в /etc/passwd",
                    Weight = 10,
                    Evidence = $"Root пользователь найден в слое {passwd.Layer}",
                    Layer = passwd.Layer
                });
            }

            if (passwd.PasswdEntries.Any(e => e.Uid == 0 && string.IsNullOrEmpty(e.Shell)))
            {
                assessment.RiskFactors.Add(new RiskFactor
                {
                    Category = "AUTHENTICATION",
                    Description = "Root пользователь без shell",
                    Weight = 5,
                    Evidence = "Root пользователь не имеет shell",
                    Layer = passwd.Layer
                });
            }
        }
    }

    /// <summary>
    /// Собирает факторы риска из анализа конфигурации
    /// </summary>
    private void CollectConfigurationRisks(AnalysisResult analysis, RiskAssessment assessment)
    {
        if (analysis.ConfigurationAnalysis == null)
            return;

        var config = analysis.ConfigurationAnalysis;

        if (config.RunsAsRoot)
        {
            assessment.RiskFactors.Add(new RiskFactor
            {
                Category = "CONFIGURATION",
                Description = "Образ запускается от пользователя root",
                Weight = 20,
                Evidence = $"User: {config.User ?? "root (по умолчанию)"}",
                Layer = "base"
            });

            assessment.Evidence.Add($"Контейнер запускается от root (User: {config.User ?? "не указан"})");
        }

        foreach (var risk in config.Risks)
        {
            assessment.RiskFactors.Add(new RiskFactor
            {
                Category = "CONFIGURATION",
                Description = risk.Description,
                Weight = risk.RiskWeight,
                Evidence = $"Тип: {risk.Type}",
                Layer = "base"
            });
        }

        if (config.Privileged)
        {
            assessment.RiskFactors.Add(new RiskFactor
            {
                Category = "CONFIGURATION",
                Description = "Образ настроен для запуска в privileged режиме",
                Weight = 40,
                Evidence = "Privileged: true",
                Layer = "base"
            });
        }

        foreach (var cap in config.Capabilities.Where(IsCriticalCapability))
        {
            assessment.RiskFactors.Add(new RiskFactor
            {
                Category = "CONFIGURATION",
                Description = $"Опасная capability: {cap}",
                Weight = GetCapabilityWeight(cap),
                Evidence = $"Capability: {cap}",
                Layer = "base"
            });
        }
    }

    /// <summary>
    /// Собирает факторы риска из анализа Dockerfile
    /// </summary>
    private void CollectDockerfileRisks(AnalysisResult analysis, RiskAssessment assessment)
    {
        if (analysis.DockerfileAnalysis == null)
            return;

        var dockerfile = analysis.DockerfileAnalysis;

        if (!dockerfile.DockerfileFound)
        {
            assessment.RiskFactors.Add(new RiskFactor
            {
                Category = "DOCKERFILE",
                Description = "Dockerfile не найден в образе",
                Weight = 5,
                Evidence = dockerfile.AbsenceReason ?? "Dockerfile отсутствует",
                Layer = "unknown"
            });
        }

        foreach (var risk in dockerfile.Risks)
        {
            assessment.RiskFactors.Add(new RiskFactor
            {
                Category = "DOCKERFILE",
                Description = risk.Description,
                Weight = risk.RiskWeight,
                Evidence = $"Строка {risk.LineNumber}: {risk.Type}",
                Layer = $"dockerfile_line_{risk.LineNumber}"
            });
        }

        if (string.IsNullOrEmpty(dockerfile.UserInstruction))
        {
            assessment.Evidence.Add("Dockerfile не содержит инструкцию USER");
        }

        foreach (var run in dockerfile.RunInstructions.Where(r => r.ContainsMount))
        {
            assessment.Evidence.Add($"RUN содержит команду mount: {run.Command}");
        }
    }

    /// <summary>
    /// Собирает факторы риска из анализа слоев
    /// </summary>
    private void CollectLayerRisks(AnalysisResult analysis, RiskAssessment assessment)
    {
        if (analysis.LayerAnalysis == null)
            return;

        var layers = analysis.LayerAnalysis;

        foreach (var layer in layers.Layers)
        {
            foreach (var risk in layer.Risks)
            {
                assessment.RiskFactors.Add(new RiskFactor
                {
                    Category = "LAYER",
                    Description = risk,
                    Weight = 10,
                    Evidence = $"Слой: {layer.LayerId}",
                    Layer = layer.LayerId
                });
            }
        }
    }

    /// <summary>
    /// Собирает факторы риска из найденных уязвимостей
    /// </summary>
    private void CollectVulnerabilityRisks(AnalysisResult analysis, RiskAssessment assessment)
    {
        foreach (var vuln in analysis.Vulnerabilities)
        {
            int weight = vuln.Severity switch
            {
                "CRITICAL" => 40,
                "HIGH" => 30,
                "MEDIUM" => 20,
                "LOW" => 10,
                _ => 15
            };

            assessment.RiskFactors.Add(new RiskFactor
            {
                Category = "VULNERABILITY",
                Description = $"{vuln.Title}: {vuln.Description}",
                Weight = weight,
                Evidence = vuln.Evidence,
                Layer = vuln.Layer
            });

            assessment.Evidence.Add($"🔴 {vuln.Type}: {vuln.Title} - {vuln.Evidence}");
        }
    }

    /// <summary>
    /// Оценивает комбинационные риски (критические комбинации факторов)
    /// </summary>
    private void AssessCombinationRisks(AnalysisResult analysis, RiskAssessment assessment)
    {
        bool runsAsRoot = analysis.ConfigurationAnalysis?.RunsAsRoot ?? false;
        bool hasMount = analysis.FileSystemAnalysis?.DangerousBinaries.Any(b => b.BinaryType == "mount") ?? false;
        bool hasWritableProc = analysis.FileSystemAnalysis?.WritableDirectories.Any(d => d.Path == "/proc") ?? false;
        bool hasNsenter = analysis.FileSystemAnalysis?.DangerousBinaries.Any(b => b.BinaryType == "nsenter") ?? false;
        bool hasSetUid = analysis.FileSystemAnalysis?.SetUidFiles.Any() ?? false;

        if (runsAsRoot && hasMount && hasWritableProc)
        {
            assessment.RiskFactors.Add(new RiskFactor
            {
                Category = "COMBINATION",
                Description = "КРИТИЧЕСКАЯ КОМБИНАЦИЯ: root + mount + writable /proc",
                Weight = 35,
                Evidence = "Обнаружена критическая комбинация факторов риска",
                Layer = "combined"
            });

            assessment.Evidence.Add("КРИТИЧЕСКАЯ КОМБИНАЦИЯ: root + mount + writable /proc");
        }

        if (runsAsRoot && hasNsenter)
        {
            assessment.RiskFactors.Add(new RiskFactor
            {
                Category = "COMBINATION",
                Description = "КРИТИЧЕСКАЯ КОМБИНАЦИЯ: root + nsenter",
                Weight = 30,
                Evidence = "Root пользователь имеет доступ к nsenter",
                Layer = "combined"
            });

            assessment.Evidence.Add("КРИТИЧЕСКАЯ КОМБИНАЦИЯ: root + nsenter");
        }

        if (runsAsRoot && hasSetUid && hasMount)
        {
            assessment.RiskFactors.Add(new RiskFactor
            {
                Category = "COMBINATION",
                Description = "КРИТИЧЕСКАЯ КОМБИНАЦИЯ: root + SetUID + mount",
                Weight = 32,
                Evidence = "Комбинация root, SetUID файлов и mount",
                Layer = "combined"
            });
        }

        bool hasWritableSys = analysis.FileSystemAnalysis?.WritableDirectories.Any(d => d.Path == "/sys") ?? false;
        if (runsAsRoot && hasWritableSys)
        {
            assessment.RiskFactors.Add(new RiskFactor
            {
                Category = "COMBINATION",
                Description = "КРИТИЧЕСКАЯ КОМБИНАЦИЯ: root + writable /sys",
                Weight = 28,
                Evidence = "Root с доступом к записи в /sys",
                Layer = "combined"
            });
        }

        if (runsAsRoot && hasMount && hasSetUid)
        {
            assessment.RiskFactors.Add(new RiskFactor
            {
                Category = "COMBINATION",
                Description = "КРИТИЧЕСКАЯ КОМБИНАЦИЯ: mount + SetUID + root",
                Weight = 30,
                Evidence = "Все компоненты для потенциального Docker Escape",
                Layer = "combined"
            });
        }
    }

    /// <summary>
    /// Вычисляет общий риск (0-100)
    /// </summary>
    private int CalculateOverallRisk(RiskAssessment assessment)
    {
        if (assessment.RiskFactors.Count == 0)
            return 0;

        int baseScore = assessment.RiskFactors.Sum(f => f.Weight);

        int maxPossibleBaseRisk = 300;
        int normalizedBaseRisk = Math.Min(100, (baseScore * 70) / maxPossibleBaseRisk);
        int factorCountBonus = Math.Min(15, assessment.RiskFactors.Count * 1);

        bool hasCriticalCombination = assessment.RiskFactors
            .Any(f => f.Category == "COMBINATION" && f.Weight >= 30);

        int combinationBonus = hasCriticalCombination ? 10 : 0;
        int finalRisk = normalizedBaseRisk + factorCountBonus + combinationBonus;

        return Math.Min(100, finalRisk);
    }

    /// <summary>
    /// Определяет уровень риска по числовому значению
    /// </summary>
    private string DetermineRiskLevel(int risk)
    {
        return risk switch
        {
            < 30 => "Low",
            < 60 => "Medium",
            < 80 => "High",
            _ => "Critical"
        };
    }

    /// <summary>
    /// Генерирует рекомендации по снижению риска
    /// </summary>
    private void GenerateRecommendations(AnalysisResult analysis, RiskAssessment assessment)
    {
        var recommendations = new List<string>();

        if (analysis.ConfigurationAnalysis?.RunsAsRoot == true)
        {
            recommendations.Add("Использовать непривилегированного пользователя: Добавьте инструкцию USER в Dockerfile с непривилегированным UID");
        }

        if (analysis.FileSystemAnalysis?.DangerousBinaries.Any(b => b.BinaryType == "mount") == true)
        {
            recommendations.Add("Удалить утилиту mount: Если она не требуется, удалите её из образа для снижения риска");
        }

        if (analysis.FileSystemAnalysis?.DangerousBinaries.Any(b => b.BinaryType == "nsenter") == true)
        {
            recommendations.Add("Удалить утилиту nsenter: Это критически опасная утилита для Docker Escape");
        }

        if (analysis.FileSystemAnalysis?.WritableDirectories.Any() == true)
        {
            recommendations.Add("Использовать readonly rootfs: Запускайте контейнер с флагом --read-only для предотвращения изменений файловой системы");
        }

        if (analysis.FileSystemAnalysis?.SetUidFiles.Any() == true)
        {
            recommendations.Add("Удалить SetUID/SetGID биты: Убедитесь, что в образе нет файлов с SetUID/SetGID битами, если они не требуются");
        }

        if (analysis.FileSystemAnalysis?.InsecurePermissions.Any() == true)
        {
            recommendations.Add("Исправить права доступа: Убедитесь, что нет файлов с правами 777 или 666");
        }

        if (analysis.DockerfileAnalysis?.DockerfileFound == false)
        {
            recommendations.Add("Добавить Dockerfile: Храните Dockerfile в репозитории для прозрачности процесса сборки");
        }

        if (analysis.Vulnerabilities.Any(v => v.Type == "SECRET_LEAK"))
        {
            recommendations.Add("КРИТИЧНО: Найдены секреты в образе. Немедленно ротируйте все найденные ключи и токены");
            recommendations.Add("Использовать Docker secrets или внешние системы управления секретами (HashiCorp Vault, AWS Secrets Manager)");
        }

        if (analysis.Vulnerabilities.Any(v => v.Type == "SENSITIVE_FILE"))
        {
            recommendations.Add("Удалить чувствительные файлы (сертификаты, ключи) из образа. Используйте volume mounts или secrets");
        }

        if (analysis.Vulnerabilities.Any(v => v.Severity == "CRITICAL" || v.Severity == "HIGH"))
        {
            recommendations.Add("Найдены критические уязвимости высокого уровня. Образ НЕ рекомендуется использовать в продакшене до исправления");
        }

        if (assessment.OverallRisk >= 70)
        {
            recommendations.Add("КРИТИЧЕСКИЙ РИСК: Требуется немедленный пересмотр конфигурации образа перед использованием в продакшене");
        }

        if (analysis.Vulnerabilities.Count > 0)
        {
            recommendations.Add("Регулярно сканировать образы на уязвимости: Используйте Trivy, Clair или Snyk для поиска известных CVE в установленных пакетах");
        }

        recommendations.Add("Использовать минимальный базовый образ: Предпочитайте alpine или distroless образы для уменьшения поверхности атаки");
        recommendations.Add("Регулярно обновлять образы: Используйте актуальные версии базовых образов с исправлениями уязвимостей");
        recommendations.Add("Использовать multi-stage builds: Удаляйте инструменты сборки из финального образа");
        recommendations.Add("Применять принцип минимальных привилегий: Запускайте контейнеры от непривилегированных пользователей");

        assessment.Recommendations = recommendations.Distinct().ToList();
    }

    /// <summary>
    /// Проверяет, является ли capability критической
    /// </summary>
    private bool IsCriticalCapability(string capability)
    {
        var criticalCaps = new[]
        {
            "CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_RAWIO",
            "CAP_SYS_PTRACE", "CAP_DAC_OVERRIDE"
        };

        return criticalCaps.Contains(capability.ToUpper());
    }

    /// <summary>
    /// Получает вес риска для capability
    /// </summary>
    private int GetCapabilityWeight(string capability)
    {
        return capability.ToUpper() switch
        {
            "CAP_SYS_ADMIN" => 30,
            "CAP_SYS_MODULE" => 35,
            "CAP_SYS_RAWIO" => 25,
            "CAP_SYS_PTRACE" => 20,
            "CAP_DAC_OVERRIDE" => 25,
            _ => 15
        };
    }
}