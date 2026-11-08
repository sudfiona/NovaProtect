using System.Text.Json;
using System.Text.Json.Serialization;
using NovaProtect.UI.Models;

namespace NovaProtect.UI.Services;

public static class ProjectStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static async Task SaveProjectAsync(string path, ProtectionOptions options)
    {
        var project = new ProtectionProject
        {
            SavedAt = DateTimeOffset.Now,
            Options = options
        };
        await WriteAsync(path, project);
    }

    public static async Task<ProtectionProject> LoadProjectAsync(string path)
    {
        await using var stream = File.OpenRead(path);
        var project = await JsonSerializer.DeserializeAsync<ProtectionProject>(stream, JsonOptions);
        if (project is null) throw new InvalidDataException("项目文件为空或格式无效");
        if (project.SchemaVersion is < 1 or > ProductInfo.ProjectSchemaVersion)
            throw new InvalidDataException($"不支持的项目 SchemaVersion {project.SchemaVersion}；当前版本支持 1..{ProductInfo.ProjectSchemaVersion}");
        if (project.SchemaVersion == 1)
        {
            MigrateV1(project);
            project.SchemaVersion = ProductInfo.ProjectSchemaVersion;
            project.Product = ProductInfo.Name;
            project.ProductVersion = ProductInfo.Version;
        }

        // A project written before schema 3 has no evasion/environment blocks, and
        // an explicit "evasion": null would deserialize to null even though the
        // property is non-nullable. Both paths must land on a usable object,
        // otherwise opening an older project crashes the page that reads it.
        project.Options.Evasion ??= new EvasionOptions();
        project.Options.Environment ??= new EnvironmentGateOptions();
        return project;
    }

    public static async Task<string> SaveBuildPlanAsync(BuildPlan plan, string stage = "manual")
    {
        stage = SafeSegment(stage);
        plan.Stage = stage;
        plan.PersistedAt = DateTimeOffset.Now;
        var output = string.IsNullOrWhiteSpace(plan.OutputPath) ? plan.InputPath : plan.OutputPath;
        var historyDirectory = BuildHistoryDirectory();
        var latestPath = string.IsNullOrWhiteSpace(output)
            ? Path.Combine(historyDirectory, $"{plan.PlanId}.novaprotect-build.json")
            : output + ".novaprotect-build.json";
        var primaryPath = stage == "prebuild" && !string.IsNullOrWhiteSpace(output)
            ? output + ".novaprotect-prebuild.json"
            : latestPath;
        await WriteAsync(primaryPath, plan);
        if (!string.Equals(primaryPath, latestPath, StringComparison.OrdinalIgnoreCase))
            await WriteAsync(latestPath, plan);

        var shortId = plan.PlanId.Length > 12 ? plan.PlanId[..12] : plan.PlanId;
        var historyPath = Path.Combine(historyDirectory,
            $"{DateTime.Now:yyyyMMdd-HHmmss-fff}-{shortId}-{stage}-{Path.GetFileName(latestPath)}");
        if (!string.Equals(primaryPath, historyPath, StringComparison.OrdinalIgnoreCase))
            await WriteAsync(historyPath, plan);
        return primaryPath;
    }

    private static async Task WriteAsync<T>(string path, T value)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
        await using var stream = File.Create(path);
        await JsonSerializer.SerializeAsync(stream, value, JsonOptions);
    }

    private static string BuildHistoryDirectory()
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "NovaProtect", "build-history");
        Directory.CreateDirectory(path);
        return path;
    }

    private static string SafeSegment(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return "manual";
        var invalid = Path.GetInvalidFileNameChars();
        return new string(value.Trim().Select(character => invalid.Contains(character) ? '-' : character).ToArray());
    }

    private static void MigrateV1(ProtectionProject project)
    {
        project.Options.VirtualFiles ??= [];
        project.Options.ObjectRules ??= [];
        foreach (var rule in project.Options.ObjectRules)
        {
            if (string.IsNullOrWhiteSpace(rule.Source) || string.Equals(rule.Source, "NovaPack SDK marker", StringComparison.Ordinal))
                rule.Source = ProductInfo.MarkerSource;
            if (string.IsNullOrWhiteSpace(rule.DetectorVersion) || string.Equals(rule.DetectorVersion, "novapack-sdk-marker-v1", StringComparison.Ordinal))
                rule.DetectorVersion = ProductInfo.MarkerDetectorVersion;
        }
    }
}

