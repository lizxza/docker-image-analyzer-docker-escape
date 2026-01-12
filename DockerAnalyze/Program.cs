using DockerAnalyze.Analyzers;
using DockerAnalyze.RiskEngine;
using DockerAnalyze.Reports;

namespace DockerAnalyze;

internal class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("╔════════════════════════════════════════════════════════════════════════════╗");
        Console.WriteLine("║     Docker Escape Risk Analyzer - Анализатор рисков Docker Escape          ║");
        Console.WriteLine("╚════════════════════════════════════════════════════════════════════════════╝");
        Console.WriteLine();

        if (args.Length == 0)
        {
            PrintUsage();
            return;
        }

        string imageName = args[0];
        string? outputJsonPath = args.Length > 1 ? args[1] : "report.json";

        try
        {
            if (!await CheckDockerAvailableAsync())
            {
                Console.WriteLine("ОШИБКА: Docker не найден или недоступен");
                Console.WriteLine("Убедитесь, что Docker установлен и запущен, и команда 'docker' доступна в PATH");
                return;
            }

            var analyzer = new ImageAnalyzer();
            
            Console.WriteLine($"Запуск анализа образа: {imageName}\n");
            
            var analysisResult = await analyzer.AnalyzeImageAsync(imageName);

            Console.WriteLine("\nЗапущена оценка рисков");
            var riskEngine = new RiskEngine.RiskEngine();
            analysisResult.RiskAssessment = riskEngine.AssessRisk(analysisResult);
            Console.WriteLine("Оценка рисков завершена");

            Console.WriteLine("\nНачата генерация отчета\n");
            
            var reportGenerator = new ReportGenerator();
            reportGenerator.PrintConsoleReport(analysisResult);
            
            await reportGenerator.SaveJsonReportAsync(analysisResult, outputJsonPath);

            Console.WriteLine();
            Console.WriteLine("----------------------------------------------------------------------------");
            Console.WriteLine($"ИТОГОВЫЙ РЕЗУЛЬТАТ:");
            Console.WriteLine($"  Образ: {imageName}");
            Console.WriteLine($"  Общий риск: {analysisResult.RiskAssessment.OverallRisk}/100");
            Console.WriteLine($"  Уровень: {analysisResult.RiskAssessment.RiskLevel}");
            Console.WriteLine($"  Факторов риска найдено: {analysisResult.RiskAssessment.RiskFactors.Count}");
            Console.WriteLine($"  JSON отчет: {Path.GetFullPath(outputJsonPath)}");
            Console.WriteLine("----------------------------------------------------------------------------");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"\nКРИТИЧЕСКАЯ ОШИБКА: {ex.Message}");
            Console.WriteLine($"\nДетали: {ex}");
            
            if (ex.InnerException != null)
            {
                Console.WriteLine($"\nВнутренняя ошибка: {ex.InnerException.Message}");
            }
            
            Environment.ExitCode = 1;
        }
    }

    /// <summary>
    /// Выводит справку по использованию
    /// </summary>
    private static void PrintUsage()
    {
        Console.WriteLine("ИСПОЛЬЗОВАНИЕ:");
        Console.WriteLine("  DockerAnalyze.exe <image_name> [output_json_path]");
        Console.WriteLine();
        Console.WriteLine("ПАРАМЕТРЫ:");
        Console.WriteLine("  image_name        Имя или ID Docker-образа для анализа");
        Console.WriteLine("  output_json_path  (опционально) Путь для сохранения JSON отчета");
        Console.WriteLine("                    По умолчанию: report.json");
        Console.WriteLine();
        Console.WriteLine("ПРИМЕРЫ:");
        Console.WriteLine("  DockerAnalyze.exe nginx:latest");
        Console.WriteLine("  DockerAnalyze.exe alpine:3.18 report.json");
        Console.WriteLine("  DockerAnalyze.exe ubuntu:22.04 ./reports/ubuntu-analysis.json");
        Console.WriteLine();
        Console.WriteLine("ПРИМЕЧАНИЯ:");
        Console.WriteLine("  - Образ должен быть загружен локально (docker pull <image>)");
        Console.WriteLine("  - Анализ выполняется ДО запуска контейнера");
        Console.WriteLine("  - Инструмент НЕ эксплуатирует уязвимости, только анализирует риски");
        Console.WriteLine("  - Требуется доступ к Docker CLI и команде 'docker'");
    }

    /// <summary>
    /// Проверяет доступность Docker
    /// </summary>
    private static async Task<bool> CheckDockerAvailableAsync()
    {
        try
        {
            var processInfo = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "docker",
                Arguments = "--version",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = System.Diagnostics.Process.Start(processInfo);
            if (process == null)
                return false;

            await process.WaitForExitAsync();
            return process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }
}