using DockerAnalyze.Models;
using System.Diagnostics;

namespace DockerAnalyze.Analyzers;

/// <summary>
/// Анализатор файловой системы Docker-образа
/// </summary>
public class FileSystemAnalyzer
{
    private readonly string _extractedPath;
    private readonly HashSet<string> _dangerousBinaries = new(StringComparer.OrdinalIgnoreCase)
{
    "mount", "umount", "nsenter", "setcap", "capsh", "chroot",
    
    "su", "sudo", "pkexec", "doas", "newgrp", "sg",
    
    "bash", "sh", "zsh", "ksh", "csh", "tcsh", "dash",
    
    "gcc", "g++", "make", "cmake", "autoconf", "automake", "ld",
    "cc", "clang", "go", "rustc", "cargo", "javac", "mvn", "gradle",
    
    "curl", "wget", "nc", "netcat", "ncat", "socat", "telnet",
    "ssh", "scp", "sftp", "ftp", "tftp", "rsync",
    "nmap", "tcpdump", "wireshark", "tshark", "ettercap",
    
    "python", "python2", "python3", "perl", "ruby", "php",
    "node", "npm", "npx", "deno", "lua",
    
    "dd", "rm", "chmod", "chown", "chattr", "lsattr",
    
    "gdb", "strace", "ltrace", "objdump", "readelf", "strings",
    "radare2", "r2", "cutter", "ghidra",
    
    "openssl", "gpg", "gnupg", "ssh-keygen",
    
    "ps", "top", "htop", "lsof", "fuser", "ss", "netstat",
    "ip", "ifconfig", "route", "arp", "iptables", "nft",
    "dmesg", "journalctl", "systemctl", "service",
    
    "kill", "killall", "pkill", "timeout", "nice", "renice",
    "taskset", "chrt", "ionice",
    
    "docker", "podman", "runc", "crun", "containerd", "ctr",
    "kubernetes", "kubectl", "helm", "skaffold",
    
    "apt", "apt-get", "yum", "dnf", "apk", "pacman", "pip",
    "npm", "gem", "cpan", "composer",
    
    "vi", "vim", "nano", "emacs", "ed", "sed", "awk",
    "tar", "gzip", "bzip2", "xz", "zip", "unzip",
    
    "insmod", "rmmod", "modprobe", "depmod", "lsmod",
    "sysctl", "dmesg", "kdump", "kexec",
    
    "setenforce", "getenforce", "sestatus", "aa-status",
    
    "date", "timedatectl", "hwclock", "ntpdate",
    
    "mkfs", "fsck", "tune2fs", "resize2fs", "debugfs",
    
    "useradd", "usermod", "userdel", "groupadd", "groupmod",
    "passwd", "chpasswd", "vipw", "vigr",
    
    "crontab", "at", "batch", "wall", "write", "mesg"
};

    private readonly HashSet<string> _systemDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        "/proc", "/sys", "/dev", "/etc"
    };

    public FileSystemAnalyzer(string extractedPath)
    {
        _extractedPath = extractedPath;
    }

    ///// <summary>
    ///// Находит директории слоев
    ///// </summary>
    private List<string> FindLayerDirectories()
    {
        var layerDirs = new List<string>();

        if (!Directory.Exists(_extractedPath))
            return layerDirs;

        foreach (var dir in Directory.GetDirectories(_extractedPath))
        {
            string dirName = Path.GetFileName(dir) ?? "";
            if (dirName.Length >= 64 && System.Text.RegularExpressions.Regex.IsMatch(dirName, @"^[a-f0-9]{64}$"))
            {
                layerDirs.Add(dir);
            }
            if (File.Exists(Path.Combine(dir, "layer.tar")))
            {
                layerDirs.Add(dir);
            }
        }

        return layerDirs;
    }

    public async Task<FileSystemAnalysis> AnalyzeAsync()
    {
        var analysis = new FileSystemAnalysis();

        await Task.Run(() =>
        {
            var layerDirs = FindLayerDirectories();

            foreach (var layerDir in layerDirs)
            {
                string layerId = Path.GetFileName(layerDir) ?? "unknown";

                string layerRoot = ExtractLayerIfNeeded(layerDir, layerId);

                if (Directory.Exists(layerDir))
                {
                    AnalyzeLayer(layerDir, layerId, analysis);
                }
            }

            AnalyzeManifest(analysis);

            analysis.PasswdShadowAnalysis = AnalyzePasswdShadow();
        });

        return analysis;
    }

    /// <summary>
    /// Распаковывает layer.tar если нужно
    /// </summary>
    private string ExtractLayerIfNeeded(string layerDir, string layerId)
    {
        string tarPath = Path.Combine(layerDir, "layer.tar");
        string layerRoot = Path.Combine(layerDir, "layer");

        if (File.Exists(tarPath) && !Directory.Exists(layerRoot))
        {
            Directory.CreateDirectory(layerRoot);

            try
            {
                using var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "tar",
                        Arguments = $"-xf \"{tarPath}\" -C \"{layerRoot}\"",
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    ExtractTarManually(tarPath, layerRoot);
                }
            }
            catch
            {
                ExtractTarManually(tarPath, layerRoot);
            }
        }

        return layerRoot;
    }

    /// <summary>
    /// Распаковка tar вручную (для Windows без tar)
    /// </summary>
    private void ExtractTarManually(string tarPath, string extractPath)
    {
        try
        {
            using var fileStream = File.OpenRead(tarPath);
            using var tarReader = new System.Formats.Tar.TarReader(fileStream);

            System.Formats.Tar.TarEntry? entry;
            while ((entry = tarReader.GetNextEntry()) != null)
            {
                if (entry.EntryType == System.Formats.Tar.TarEntryType.RegularFile)
                {
                    string targetPath = Path.Combine(extractPath,
                        entry.Name.Replace('/', Path.DirectorySeparatorChar));

                    string? directory = Path.GetDirectoryName(targetPath);
                    if (!string.IsNullOrEmpty(directory))
                    {
                        Directory.CreateDirectory(directory);
                    }

                    if (entry.DataStream != null)
                    {
                        using var entryStream = File.Create(targetPath);
                        entry.DataStream.CopyTo(entryStream);
                    }
                }
                else if (entry.EntryType == System.Formats.Tar.TarEntryType.Directory)
                {
                    string targetPath = Path.Combine(extractPath,
                        entry.Name.Replace('/', Path.DirectorySeparatorChar));
                    Directory.CreateDirectory(targetPath);
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[!] Ошибка распаковки {tarPath}: {ex.Message}");
        }
    }

    /// <summary>
    /// Анализирует один слой
    /// </summary>
    private void AnalyzeLayer(string layerRoot, string layerId, FileSystemAnalysis analysis)
    {
        foreach (var binary in _dangerousBinaries)
        {
            SearchBinary(layerRoot, binary, layerId, analysis);
        }

        FindSetUidFiles(layerRoot, layerId, analysis);
        FindWritableDirectories(layerRoot, layerId, analysis);
        FindInsecurePermissions(layerRoot, layerId, analysis);
    }

    /// <summary>
    /// Ищет опасный бинарник в файловой системе
    /// </summary>
    private void SearchBinary(string root, string binaryName, string layerId, FileSystemAnalysis analysis)
    {
        var searchPaths = new[]
        {
            Path.Combine(root, "usr", "bin", binaryName),
            Path.Combine(root, "bin", binaryName),
            Path.Combine(root, "usr", "local", "bin", binaryName),
            Path.Combine(root, "sbin", binaryName),
            Path.Combine(root, "usr", "sbin", binaryName)
        };

        foreach (var path in searchPaths)
        {
            if (File.Exists(path))
            {
                var fileInfo = new FileInfo(path);
                string permissions = GetUnixPermissions(fileInfo);

                int riskWeight = GetBinaryRiskWeight(binaryName);

                analysis.DangerousBinaries.Add(new DangerousBinary
                {
                    Path = NormalizePath(path, root),
                    BinaryType = binaryName,
                    Layer = layerId,
                    Permissions = permissions,
                    RiskWeight = riskWeight
                });
            }
        }

        try
        {
            if (Directory.Exists(root))
            {
                SearchBinaryRecursive(root, binaryName, layerId, analysis, root);
            }
        }
        catch
        {
        }
    }

    /// <summary>
    /// Рекурсивный поиск бинарника
    /// </summary>
    private void SearchBinaryRecursive(string directory, string binaryName, string layerId,
        FileSystemAnalysis analysis, string rootPath, int depth = 0)
    {
        if (depth > 10) return;

        try
        {
            foreach (var file in Directory.GetFiles(directory))
            {
                string fileName = Path.GetFileName(file);
                if (string.Equals(fileName, binaryName, StringComparison.OrdinalIgnoreCase))
                {
                    var fileInfo = new FileInfo(file);
                    string permissions = GetUnixPermissions(fileInfo);
                    int riskWeight = GetBinaryRiskWeight(binaryName);

                    analysis.DangerousBinaries.Add(new DangerousBinary
                    {
                        Path = NormalizePath(file, rootPath),
                        BinaryType = binaryName,
                        Layer = layerId,
                        Permissions = permissions,
                        RiskWeight = riskWeight
                    });
                }
            }

            foreach (var dir in Directory.GetDirectories(directory))
            {
                string dirName = Path.GetFileName(dir) ?? "";
                if (dirName == "proc" || dirName == "sys" || dirName == "dev")
                    continue;

                SearchBinaryRecursive(dir, binaryName, layerId, analysis, rootPath, depth + 1);
            }
        }
        catch
        {
        }
    }

    /// <summary>
    /// Определяет вес риска для бинарника
    /// </summary>
    private int GetBinaryRiskWeight(string binaryName)
    {
        return binaryName.ToLower() switch
        {
            "mount" or "umount" => 35,
            "nsenter" => 35,
            "setcap" => 30,
            "chroot" => 30,
            "docker" or "podman" => 30,
            "runc" or "crun" => 30,

            "su" or "sudo" => 28,
            "pkexec" => 28,
            "ssh" => 25,
            "scp" => 25,
            "nmap" => 26,
            "tcpdump" => 26,

            "gcc" or "g++" => 20,
            "make" => 18,
            "python" or "python3" => 16,
            "perl" => 16,
            "php" => 16,
            "curl" or "wget" => 15,
            "nc" or "netcat" => 18,
            "socat" => 22,

            "bash" or "sh" => 12,
            "vim" or "nano" => 10,
            "tar" => 10,
            "gzip" => 8,

            "gdb" => 15,
            "strace" => 12,
            "objdump" => 10,

            "ps" or "top" => 8,
            "lsof" => 8,
            "netstat" => 8,

            _ => 10
        };
    }

    /// <summary>
    /// Ищет SetUID/SetGID файлы
    /// </summary>
    private void FindSetUidFiles(string root, string layerId, FileSystemAnalysis analysis)
    {
        try
        {
            FindSetUidFilesRecursive(root, layerId, analysis, root);
        }
        catch
        {
        }
    }

    /// <summary>
    /// Рекурсивный поиск SetUID/SetGID файлов
    /// </summary>
    private void FindSetUidFilesRecursive(string directory, string layerId,
        FileSystemAnalysis analysis, string rootPath, int depth = 0)
    {
        if (depth > 15) return;

        try
        {
            foreach (var file in Directory.GetFiles(directory))
            {
                var fileInfo = new FileInfo(file);

                string permissions = GetUnixPermissions(fileInfo);

                if (TryParseUnixPermissions(permissions, out bool isSetUid, out bool isSetGid))
                {
                    if (isSetUid || isSetGid)
                    {
                        analysis.SetUidFiles.Add(new SetUidFile
                        {
                            Path = NormalizePath(file, rootPath),
                            IsSetUid = isSetUid,
                            IsSetGid = isSetGid,
                            Layer = layerId,
                            Permissions = permissions
                        });
                    }
                }
            }

            foreach (var dir in Directory.GetDirectories(directory))
            {
                FindSetUidFilesRecursive(dir, layerId, analysis, rootPath, depth + 1);
            }
        }
        catch
        {
        }
    }

    /// <summary>
    /// Ищет writable системные директории
    /// </summary>
    private void FindWritableDirectories(string root, string layerId, FileSystemAnalysis analysis)
    {
        foreach (var sysDir in _systemDirectories)
        {
            string dirPath = Path.Combine(root, sysDir.TrimStart('/'));
            if (Directory.Exists(dirPath))
            {
                var dirInfo = new DirectoryInfo(dirPath);
                string permissions = GetUnixPermissions(dirInfo);

                if (IsWritable(permissions))
                {
                    analysis.WritableDirectories.Add(new WritableDirectory
                    {
                        Path = sysDir,
                        Layer = layerId,
                        IsSystemDirectory = true
                    });
                }
            }
        }
    }

    /// <summary>
    /// Ищет файлы с небезопасными правами доступа (777, 666)
    /// </summary>
    private void FindInsecurePermissions(string root, string layerId, FileSystemAnalysis analysis, int depth = 0)
    {
        if (depth > 15) return;

        try
        {
            foreach (var file in Directory.GetFiles(root))
            {
                var fileInfo = new FileInfo(file);
                string permissions = GetUnixPermissions(fileInfo);

                if (TryParseUnixPermissions(permissions, out _, out _, out bool isWorldWritable, out bool isWorldReadable))
                {
                    if (isWorldWritable || (isWorldReadable && permissions.Contains("666")))
                    {
                        analysis.InsecurePermissions.Add(new InsecurePermission
                        {
                            Path = NormalizePath(file, root),
                            Permissions = permissions,
                            Layer = layerId,
                            IsWorldWritable = isWorldWritable,
                            IsWorldReadable = isWorldReadable
                        });
                    }
                }
            }

            foreach (var dir in Directory.GetDirectories(root))
            {
                string dirName = Path.GetFileName(dir) ?? "";
                if (dirName == "proc" || dirName == "sys" || dirName == "dev")
                    continue;

                FindInsecurePermissions(dir, layerId, analysis, depth + 1);
            }
        }
        catch
        {
        }
    }

    /// <summary>
    /// Анализирует /etc/passwd и /etc/shadow
    /// </summary>
    private PasswdShadowAnalysis? AnalyzePasswdShadow()
    {
        var analysis = new PasswdShadowAnalysis { Layer = "unknown" };

        var layerDirs = FindLayerDirectories();

        foreach (var layerDir in layerDirs)
        {
            string layerId = Path.GetFileName(layerDir) ?? "unknown";
            string layerRoot = Path.Combine(layerDir, "layer");

            if (!Directory.Exists(layerRoot))
                continue;

            string passwdPath = Path.Combine(layerRoot, "etc", "passwd");
            string shadowPath = Path.Combine(layerRoot, "etc", "shadow");

            if (File.Exists(passwdPath))
            {
                analysis.PasswdExists = true;
                analysis.Layer = layerId;

                ParsePasswdFile(passwdPath, analysis);
            }

            if (File.Exists(shadowPath))
            {
                analysis.ShadowExists = true;
                analysis.Layer = layerId;
            }
        }

        return analysis.PasswdExists || analysis.ShadowExists ? analysis : null;
    }

    /// <summary>
    /// Парсит /etc/passwd файл
    /// </summary>
    private void ParsePasswdFile(string passwdPath, PasswdShadowAnalysis analysis)
    {
        try
        {
            var lines = File.ReadAllLines(passwdPath);

            foreach (var line in lines)
            {
                if (string.IsNullOrWhiteSpace(line) || line.StartsWith('#'))
                    continue;

                var parts = line.Split(':');
                if (parts.Length >= 7)
                {
                    string username = parts[0];
                    string passwordHash = parts[1];
                    int uid = int.TryParse(parts[2], out int u) ? u : -1;
                    int gid = int.TryParse(parts[3], out int g) ? g : -1;
                    string home = parts[5];
                    string shell = parts[6];

                    analysis.PasswdEntries.Add(new PasswdEntry
                    {
                        Username = username,
                        Uid = uid,
                        Gid = gid,
                        Home = home,
                        Shell = shell
                    });

                    if (uid == 0)
                    {
                        analysis.HasRootUser = true;
                        if (string.IsNullOrEmpty(passwordHash) || passwordHash == "*" || passwordHash == "!")
                        {
                            analysis.HasRootWithoutPassword = false;
                        }
                        else
                        {
                            analysis.HasRootWithoutPassword = false;
                        }
                    }
                }
            }
        }
        catch
        {
        }
    }

    /// <summary>
    /// Анализирует manifest.json для определения структуры слоев
    /// </summary>
    private void AnalyzeManifest(FileSystemAnalysis analysis)
    {
        string manifestPath = Path.Combine(_extractedPath, "manifest.json");
        if (File.Exists(manifestPath))
        {
            try
            {
                var manifestJson = File.ReadAllText(manifestPath);
            }
            catch
            {
            }
        }
    }

    /// <summary>
    /// Получает Unix-права доступа из FileInfo (упрощенная версия)
    /// </summary>
    private string GetUnixPermissions(FileSystemInfo info)
    {
        bool isReadOnly = (info.Attributes & FileAttributes.ReadOnly) != 0;
        return "644";
    }

    /// <summary>
    /// Пытается распарсить Unix права доступа
    /// </summary>
    private bool TryParseUnixPermissions(string permissions, out bool isSetUid, out bool isSetGid,
        out bool isWorldWritable, out bool isWorldReadable)
    {
        isSetUid = false;
        isSetGid = false;
        isWorldWritable = false;
        isWorldReadable = false;

        if (string.IsNullOrEmpty(permissions))
            return false;

        if (permissions.Length >= 3)
        {
            string numeric = permissions.Length > 3 ? permissions.Substring(permissions.Length - 3) : permissions;

            if (numeric.Length == 3 && int.TryParse(numeric, out int perm))
            {
                int others = perm % 10;
                isWorldReadable = (others & 4) != 0;
                isWorldWritable = (others & 2) != 0;
            }

            if (permissions.Length == 4)
            {
                char special = permissions[0];
                isSetUid = special == '4';
                isSetGid = special == '2';
            }
        }

        if (permissions.Contains("rwxrwxrwx") || permissions.Contains("777"))
        {
            isWorldWritable = true;
            isWorldReadable = true;
        }

        return true;
    }

    private bool TryParseUnixPermissions(string permissions, out bool isSetUid, out bool isSetGid)
    {
        return TryParseUnixPermissions(permissions, out isSetUid, out isSetGid, out _, out _);
    }

    /// <summary>
    /// Проверяет, является ли путь writable
    /// </summary>
    private bool IsWritable(string permissions)
    {
        if (permissions.Contains("777") || permissions.Contains("rwxrwxrwx"))
            return true;

        if (TryParseUnixPermissions(permissions, out _, out _, out bool isWorldWritable, out _))
        {
            return isWorldWritable;
        }

        return false;
    }

    /// <summary>
    /// Нормализует путь относительно корня образа
    /// </summary>
    private string NormalizePath(string fullPath, string rootPath)
    {
        if (fullPath.StartsWith(rootPath, StringComparison.OrdinalIgnoreCase))
        {
            string relative = fullPath.Substring(rootPath.Length);
            return relative.Replace('\\', '/').TrimStart('/');
        }
        return fullPath.Replace('\\', '/');
    }
}