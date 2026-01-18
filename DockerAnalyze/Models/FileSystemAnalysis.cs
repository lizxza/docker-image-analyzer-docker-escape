namespace DockerAnalyze.Models;

/// <summary>
/// Результаты анализа файловой системы образа
/// </summary>
public class FileSystemAnalysis
{
    public List<DangerousBinary> DangerousBinaries { get; set; } = new();
    public List<SetUidFile> SetUidFiles { get; set; } = new();
    public List<WritableDirectory> WritableDirectories { get; set; } = new();
    public List<InsecurePermission> InsecurePermissions { get; set; } = new();
    public PasswdShadowAnalysis? PasswdShadowAnalysis { get; set; }
}

/// <summary>
/// Опасная утилита, найденная в образе
/// </summary>
public class DangerousBinary
{
    public string Path { get; set; } = string.Empty;
    public string BinaryType { get; set; } = string.Empty;
    public string Layer { get; set; } = string.Empty;
    public string Permissions { get; set; } = string.Empty;
    public int RiskWeight { get; set; }
}

/// <summary>
/// Файл с SetUID/SetGID битами
/// </summary>
public class SetUidFile
{
    public string Path { get; set; } = string.Empty;
    public bool IsSetUid { get; set; }
    public bool IsSetGid { get; set; }
    public string Layer { get; set; } = string.Empty;
    public string Permissions { get; set; } = string.Empty;
}

/// <summary>
/// Записываемая директория, которая должна быть read-only
/// </summary>
public class WritableDirectory
{
    public string Path { get; set; } = string.Empty;
    public string Layer { get; set; } = string.Empty;
    public bool IsSystemDirectory { get; set; }
}

/// <summary>
/// Небезопасные права доступа (777, 666)
/// </summary>
public class InsecurePermission
{
    public string Path { get; set; } = string.Empty;
    public string Permissions { get; set; } = string.Empty;
    public string Layer { get; set; } = string.Empty;
    public bool IsWorldWritable { get; set; }
    public bool IsWorldReadable { get; set; }
}

/// <summary>
/// Анализ /etc/passwd и /etc/shadow
/// </summary>
public class PasswdShadowAnalysis
{
    public bool PasswdExists { get; set; }
    public bool ShadowExists { get; set; }
    public List<PasswdEntry> PasswdEntries { get; set; } = new();
    public bool HasRootWithoutPassword { get; set; }
    public bool HasRootUser { get; set; }
    public string Layer { get; set; } = string.Empty;
}

/// <summary>
/// Запись из /etc/passwd
/// </summary>
public class PasswdEntry
{
    public string Username { get; set; } = string.Empty;
    public int Uid { get; set; }
    public int Gid { get; set; }
    public string Home { get; set; } = string.Empty;
    public string Shell { get; set; } = string.Empty;
}