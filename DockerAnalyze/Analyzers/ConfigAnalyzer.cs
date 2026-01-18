using System.Diagnostics;
using System.Text.Json;
using DockerAnalyze.Models;

namespace DockerAnalyze.Analyzers;

/// <summary>
/// Анализатор конфигурации Docker-образа
/// </summary>
public class ConfigAnalyzer
{
    /// <summary>
    /// Анализирует конфигурацию образа через docker inspect
    /// </summary>
    public async Task<ConfigurationAnalysis> AnalyzeAsync(string imageName)
    {
        var analysis = new ConfigurationAnalysis();

        try
        {
            string inspectJson = await GetInspectJsonAsync(imageName);
            
            if (string.IsNullOrWhiteSpace(inspectJson))
            {
                analysis.Risks.Add(new ConfigurationRisk
                {
                    Type = "INSPECT_FAILED",
                    Description = "Не удалось получить конфигурацию образа",
                    RiskWeight = 0
                });
                return analysis;
            }

            using var doc = JsonDocument.Parse(inspectJson);
            var root = doc.RootElement;

            if (root.ValueKind == JsonValueKind.Array && root.GetArrayLength() > 0)
            {
                var imageConfig = root[0];
                ParseImageConfig(imageConfig, analysis);
            }

            CalculateConfigurationRisks(analysis);

        }
        catch (Exception ex)
        {
            analysis.Risks.Add(new ConfigurationRisk
            {
                Type = "ANALYSIS_ERROR",
                Description = $"Ошибка при анализе конфигурации: {ex.Message}",
                RiskWeight = 0
            });
        }

        return analysis;
    }

    /// <summary>
    /// Получает JSON конфигурации образа через docker inspect
    /// </summary>
    private async Task<string> GetInspectJsonAsync(string imageName)
    {
        var processInfo = new ProcessStartInfo
        {
            FileName = "docker",
            Arguments = $"inspect {imageName}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(processInfo);
        if (process == null)
            throw new Exception("Не удалось запустить docker inspect");

        await process.WaitForExitAsync();

        if (process.ExitCode != 0)
        {
            string error = await process.StandardError.ReadToEndAsync();
            throw new Exception($"Ошибка docker inspect: {error}");
        }

        return await process.StandardOutput.ReadToEndAsync();
    }

    /// <summary>
    /// Парсит конфигурацию образа из JSON
    /// </summary>
    private void ParseImageConfig(JsonElement imageConfig, ConfigurationAnalysis analysis)
    {
        if (imageConfig.TryGetProperty("Config", out var config))
        {
            if (config.TryGetProperty("User", out var user))
            {
                analysis.User = user.GetString();
                analysis.RunsAsRoot = string.IsNullOrEmpty(analysis.User) || 
                                     analysis.User == "0" || 
                                     analysis.User == "root";
            }
            else
            {
                analysis.RunsAsRoot = true;
            }

            if (config.TryGetProperty("Entrypoint", out var entrypoint))
            {
                if (entrypoint.ValueKind == JsonValueKind.Array)
                {
                    analysis.Entrypoint = string.Join(" ", entrypoint.EnumerateArray().Select(e => e.GetString() ?? ""));
                }
                else
                {
                    analysis.Entrypoint = entrypoint.GetString();
                }
            }

            if (config.TryGetProperty("Cmd", out var cmd))
            {
                if (cmd.ValueKind == JsonValueKind.Array)
                {
                    analysis.Cmd = string.Join(" ", cmd.EnumerateArray().Select(e => e.GetString() ?? ""));
                }
                else
                {
                    analysis.Cmd = cmd.GetString();
                }
            }
        }

        if (imageConfig.TryGetProperty("ContainerConfig", out var containerConfig))
        {
            if (containerConfig.TryGetProperty("User", out var containerUser))
            {
                string? containerUserStr = containerUser.GetString();
                if (!string.IsNullOrEmpty(containerUserStr))
                {
                    analysis.User = containerUserStr;
                    analysis.RunsAsRoot = containerUserStr == "0" || containerUserStr == "root";
                }
            }
        }
    }

    /// <summary>
    /// Вычисляет риски на основе конфигурации
    /// </summary>
    private void CalculateConfigurationRisks(ConfigurationAnalysis analysis)
    {
        if (analysis.RunsAsRoot)
        {
            analysis.Risks.Add(new ConfigurationRisk
            {
                Type = "ROOT_USER",
                Description = "Образ запускается от пользователя root по умолчанию",
                RiskWeight = 20
            });
        }

        if (!analysis.ReadonlyRootfs)
        {
            analysis.Risks.Add(new ConfigurationRisk
            {
                Type = "WRITABLE_ROOTFS",
                Description = "Root файловая система может быть изменена (не readonly)",
                RiskWeight = 15
            });
        }

        foreach (var cap in analysis.Capabilities)
        {
            if (IsDangerousCapability(cap))
            {
                analysis.Risks.Add(new ConfigurationRisk
                {
                    Type = "DANGEROUS_CAPABILITY",
                    Description = $"Найдена опасная capability: {cap}",
                    RiskWeight = GetCapabilityRiskWeight(cap)
                });
            }
        }

        foreach (var secOpt in analysis.SecurityOpts)
        {
            if (IsDangerousSecurityOpt(secOpt))
            {
                analysis.Risks.Add(new ConfigurationRisk
                {
                    Type = "DANGEROUS_SECURITY_OPT",
                    Description = $"Найдена опасная security опция: {secOpt}",
                    RiskWeight = 10
                });
            }
        }
    }

    /// <summary>
    /// Проверяет, является ли capability опасной
    /// </summary>
    private bool IsDangerousCapability(string capability)
    {
        var dangerousCaps = new[]
        {
            "CAP_SYS_ADMIN",
            "CAP_SYS_MODULE",
            "CAP_SYS_RAWIO",
            "CAP_SYS_PTRACE",
            "CAP_SYS_TIME",
            "CAP_SYS_TTY_CONFIG",
            "CAP_MKNOD",
            "CAP_SYS_CHROOT",
            "CAP_SYS_BOOT",
            "CAP_SYS_NICE",
            "CAP_DAC_OVERRIDE",
            "CAP_DAC_READ_SEARCH"
        };

        return dangerousCaps.Contains(capability.ToUpper());
    }

    /// <summary>
    /// Определяет вес риска для capability
    /// </summary>
    private int GetCapabilityRiskWeight(string capability)
    {
        return capability.ToUpper() switch
        {
            "CAP_SYS_ADMIN" => 30,
            "CAP_SYS_MODULE" => 35,
            "CAP_SYS_RAWIO" => 25,
            "CAP_SYS_PTRACE" => 20,
            "CAP_DAC_OVERRIDE" => 25,
            "CAP_SYS_CHROOT" => 15,
            _ => 15
        };
    }

    /// <summary>
    /// Проверяет, является ли security опция опасной
    /// </summary>
    private bool IsDangerousSecurityOpt(string secOpt)
    {
        return secOpt.Contains("unconfined", StringComparison.OrdinalIgnoreCase) ||
               secOpt.Contains("privileged", StringComparison.OrdinalIgnoreCase);
    }
}