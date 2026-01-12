# DOCKER IMAGE ANALYZER
Инструмент статического анализа docker image, предназначенный для выявления скрытых конфигурационных предпосылок к атакам класса docker escape ещё до запуска контейнера.

![Logotype](https://avatars.mds.yandex.net/i?id=5bb211517d5e83fdd653c073504330408c8800de-7065709-images-thumbs&n=13g)

# Архитектура
```
DockerAnalyze/
├── Models/
│   ├── AnalysisResult.cs             # Основной результат анализа
│   ├── FileSystemAnalysis.cs         # Результаты анализа файловой системы
│   ├── ConfigurationAnalysis.cs      # Результаты анализа конфигурации
│   ├── DockerfileAnalysis.cs         # Результаты анализа Dockerfile
│   ├── LayerAnalysis.cs              # Результаты анализа слоев
│   └── RiskAssessment.cs             # Оценка рисков
│
├── Analyzers/                        # Анализаторы
│   ├── ImageAnalyzer.cs              # Основной анализатор (docker CLI)
│   ├── FileSystemAnalyzer.cs         # Анализ файловой системы
│   ├── ConfigAnalyzer.cs             # Анализ конфигурации (docker inspect)
│   ├── DockerfileAnalyzer.cs         # Парсинг Dockerfile
│   ├── LayerAnalyzer.cs              # Анализ слоев образа
│   └── VulnerabilityAnalyzer.cs      # Поиск уязвимостей и секретов
│
├── RiskEngine/                       # Движок оценки рисков
│   └── RiskEngine.cs                 # Контекстная модель рисков
│
├── Reports/                          # Генераторы отчетов
│   └── ReportGenerator.cs            # Консольный и JSON отчеты
│
└── Program.cs                        # Точка входа
```

# Поток работы
1. **ImageAnalyzer** получает образ через docker save и распаковывает его
2. **ConfigAnalyzer** анализирует конфигурацию через docker inspect
3. **FileSystemAnalyzer** сканирует файловую систему на наличие опасных файлов
4. **DockerfileAnalyzer** ищет и парсит Dockerfile
5. **LayerAnalyzer** анализирует каждый слой образа отдельно
6. **VulnerabilityAnalyzer** выполняет поиск уязвимостей, секретов и проблем безопасности
7. **RiskEngine** вычисляет контекстные риски на основе всех данных, включая найденные уязвимости
8. **ReportGenerator** создает детальные отчеты в консоль и JSON

# Использование
### Требования

- .NET 9.0 SDK
- Docker CLI (команда `docker` должна быть доступна в PATH)
- Docker образ должен быть загружен локально

### Сборка

```bash
dotnet build
```

### Запуск

```bash
dotnet run -- <image_name> [output_json_path]
```

Параметры:
   image_name - имя или ID Docker-образа для анализа
   output_json_path - путь для сохранения JSON отчета (по умолчанию: report.json)
