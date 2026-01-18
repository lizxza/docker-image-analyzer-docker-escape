using System.Diagnostics;
using System.Text.Json;
using DockerAnalyze.Models;

namespace DockerAnalyze.Analyzers;

/// <summary>
/// Основной анализатор для работы с Docker образами через CLI
/// </summary>
public class ImageAnalyzer
{
    private readonly string _tempDirectory;
    private readonly ConfigAnalyzer _configAnalyzer;
    private readonly DockerfileAnalyzer _dockerfileAnalyzer;
    private string? _extractedPath;

    public ImageAnalyzer()
    {
        _tempDirectory = Path.Combine(Path.GetTempPath(), $"docker_analyze_{Guid.NewGuid()}");
        Directory.CreateDirectory(_tempDirectory);
        _extractedPath = null;
        
        _configAnalyzer = new ConfigAnalyzer();
        _dockerfileAnalyzer = new DockerfileAnalyzer();
    }

    /// <summary>
    /// Анализирует Docker-образ по имени или ID
    /// </summary>
    public async Task<AnalysisResult> AnalyzeImageAsync(string imageName)
    {
        Console.WriteLine($"[*] Начинаю анализ образа: {imageName}");
        
        var result = new AnalysisResult
        {
            ImageName = imageName,
            AnalysisDate = DateTime.UtcNow
        };

        try
        {
            if (!await ImageExistsAsync(imageName))
            {
                throw new Exception($"Образ '{imageName}' не найден локально. Выполните: docker pull {imageName}");
            }

            result.ImageId = await GetImageIdAsync(imageName);
            Console.WriteLine($"ID образа: {result.ImageId}");

            Console.WriteLine("Сохраняю образ в архив...");
            string tarPath = await SaveImageAsync(imageName);
            Console.WriteLine($"Образ сохранен: {tarPath}");

            Console.WriteLine("Распаковываю архив...");
            _extractedPath = await ExtractTarAsync(tarPath);
            Console.WriteLine("Архив распакован");

            Console.WriteLine("Анализирую конфигурацию образа...");
            result.ConfigurationAnalysis = await _configAnalyzer.AnalyzeAsync(imageName);
            Console.WriteLine("Анализ конфигурации завершен");

            var fileSystemAnalyzer = new FileSystemAnalyzer(_extractedPath);
            var layerAnalyzer = new LayerAnalyzer(_extractedPath);

            Console.WriteLine("Анализирую слои образа...");
            result.LayerAnalysis = await layerAnalyzer.AnalyzeAsync(tarPath);
            Console.WriteLine("Анализ слоев завершен");

            Console.WriteLine("Анализирую файловую систему...");
            result.FileSystemAnalysis = await fileSystemAnalyzer.AnalyzeAsync();
            Console.WriteLine("Анализ файловой системы завершен");

            Console.WriteLine("Ищу Dockerfile...");
            result.DockerfileAnalysis = await _dockerfileAnalyzer.AnalyzeAsync(imageName, _extractedPath);
            Console.WriteLine("Анализ Dockerfile завершен");

            Console.WriteLine("Анализирую уязвимости и ищу потенциальные проблемы безопасности...");
            var vulnerabilityAnalyzer = new VulnerabilityAnalyzer(_extractedPath);
            result.Vulnerabilities = await vulnerabilityAnalyzer.AnalyzeAsync(result.FileSystemAnalysis);
            Console.WriteLine($"Найдено уязвимостей: {result.Vulnerabilities.Count}");

        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ошибка при анализе: {ex.Message}");
            throw;
        }
        finally
        {
            Cleanup();
        }

        return result;
    }

    /// <summary>
    /// Проверяет существование образа
    /// </summary>
    private async Task<bool> ImageExistsAsync(string imageName)
    {
        try
        {
            var processInfo = new ProcessStartInfo
            {
                FileName = "docker",
                Arguments = $"images {imageName} --format json",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(processInfo);
            if (process == null) return false;

            await process.WaitForExitAsync();
            string output = await process.StandardOutput.ReadToEndAsync();

            return !string.IsNullOrWhiteSpace(output);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Получает ID образа
    /// </summary>
    private async Task<string> GetImageIdAsync(string imageName)
    {
        var processInfo = new ProcessStartInfo
        {
            FileName = "docker",
            Arguments = $"images {imageName} --format \"{{{{.ID}}}}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(processInfo);
        if (process == null)
            throw new Exception("Не удалось запустить docker images");

        await process.WaitForExitAsync();
        string output = await process.StandardOutput.ReadToEndAsync();

        if (string.IsNullOrWhiteSpace(output))
            throw new Exception("Не удалось получить ID образа");

        return output.Trim().Split('\n')[0];
    }

    /// <summary>
    /// Сохраняет образ в tar архив
    /// </summary>
    private async Task<string> SaveImageAsync(string imageName)
    {
        string tarPath = Path.Combine(_tempDirectory, "image.tar");
        
        var processInfo = new ProcessStartInfo
        {
            FileName = "docker",
            Arguments = $"save {imageName} -o \"{tarPath}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var process = Process.Start(processInfo);
        if (process == null)
            throw new Exception("Не удалось запустить docker save");

        await process.WaitForExitAsync();

        if (process.ExitCode != 0)
        {
            string error = await process.StandardError.ReadToEndAsync();
            throw new Exception($"Ошибка docker save: {error}");
        }

        if (!File.Exists(tarPath))
            throw new Exception("Файл образа не был создан");

        return tarPath;
    }

    /// <summary>
    /// Распаковывает tar архив
    /// </summary>
    private async Task<string> ExtractTarAsync(string tarPath)
    {
        string extractPath = Path.Combine(_tempDirectory, "extracted");
        Directory.CreateDirectory(extractPath);

        var processInfo = new ProcessStartInfo
        {
            FileName = "tar",
            Arguments = $"-xf \"{tarPath}\" -C \"{extractPath}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        try
        {
            using var process = Process.Start(processInfo);
            if (process != null)
            {
                await process.WaitForExitAsync();
                if (process.ExitCode == 0)
                {
                    return extractPath;
                }
            }
        }
        catch
        {
        }
        
        await ExtractTarManuallyAsync(tarPath, extractPath);
        return extractPath;
    }

    /// <summary>
    /// Ручная распаковка tar архива через System.Formats.Tar (.NET 9)
    /// </summary>
    private async Task ExtractTarManuallyAsync(string tarPath, string extractPath)
    {
        await Task.Run(() =>
        {
            using var fileStream = File.OpenRead(tarPath);
            using var tarReader = new System.Formats.Tar.TarReader(fileStream);

            System.Formats.Tar.TarEntry? entry;
            while ((entry = tarReader.GetNextEntry()) != null)
            {
                if (entry.EntryType == System.Formats.Tar.TarEntryType.RegularFile ||
                    entry.EntryType == System.Formats.Tar.TarEntryType.Directory)
                {
                    string targetPath = Path.Combine(extractPath, entry.Name.Replace('/', Path.DirectorySeparatorChar));
                    string? directory = Path.GetDirectoryName(targetPath);
                    if (!string.IsNullOrEmpty(directory))
                    {
                        Directory.CreateDirectory(directory);
                    }

                    if (entry.EntryType == System.Formats.Tar.TarEntryType.RegularFile && entry.DataStream != null)
                    {
                        using var entryStream = File.Create(targetPath);
                        entry.DataStream.CopyTo(entryStream);
                    }
                    else if (entry.EntryType == System.Formats.Tar.TarEntryType.Directory)
                    {
                        Directory.CreateDirectory(targetPath);
                    }
                }
            }
        });
    }

    /// <summary>
    /// Очистка временных файлов
    /// </summary>
    private void Cleanup()
    {
        try
        {
            if (Directory.Exists(_tempDirectory))
            {
                Directory.Delete(_tempDirectory, true);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Предупреждение: не удалось удалить временные файлы: {ex.Message}");
        }
    }

    /// <summary>
    /// Получает путь к распакованным файлам
    /// </summary>
    public string? GetExtractedPath()
    {
        return _extractedPath;
    }
}