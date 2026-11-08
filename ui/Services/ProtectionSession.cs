using System.Text.Json;
using NovaProtect.UI.Models;

namespace NovaProtect.UI.Services;

/// <summary>
/// Process-wide state for the settings that live on their own page but are used
/// by a run started from another page.
///
/// Evasion and the environment gate are edited on 对抗与规避, while the run is
/// started from 保护项目. Without a shared holder the two pages would each need a
/// copy and one of them would silently lose the user's edits. Persisting to
/// <c>%LOCALAPPDATA%</c> means the choice survives a restart, which is what users
/// expect from a global preference as opposed to a per-project one.
/// </summary>
public static class ProtectionSession
{
    private static readonly object Gate = new();
    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    private static EvasionOptions _evasion = new();
    private static EnvironmentGateOptions _environment = new();
    private static bool _loaded;

    public static event EventHandler? Changed;

    public static EvasionOptions Evasion
    {
        get { EnsureLoaded(); lock (Gate) return _evasion.Clone(); }
        set
        {
            if (value is null) return;
            lock (Gate) _evasion = value.Clone();
            Save();
            Changed?.Invoke(null, EventArgs.Empty);
        }
    }

    public static EnvironmentGateOptions Environment
    {
        get { EnsureLoaded(); lock (Gate) return _environment.Clone(); }
        set
        {
            if (value is null) return;
            lock (Gate) _environment = value.Clone();
            Save();
            Changed?.Invoke(null, EventArgs.Empty);
        }
    }

    /// <summary>
    /// Apply both at once so a single edit does not fire two change events and
    /// write the file twice.
    /// </summary>
    public static void Set(EvasionOptions evasion, EnvironmentGateOptions environment)
    {
        lock (Gate)
        {
            if (evasion is not null) _evasion = evasion.Clone();
            if (environment is not null) _environment = environment.Clone();
        }
        Save();
        Changed?.Invoke(null, EventArgs.Empty);
    }

    public static void Reset()
    {
        lock (Gate)
        {
            _evasion = new EvasionOptions();
            _environment = new EnvironmentGateOptions();
        }
        Save();
        Changed?.Invoke(null, EventArgs.Empty);
    }

    private static string SettingsPath =>
        Path.Combine(
            System.Environment.GetFolderPath(System.Environment.SpecialFolder.LocalApplicationData),
            "NovaProtect",
            "evasion.json");

    private sealed class Payload
    {
        public int SchemaVersion { get; set; } = 1;
        public EvasionOptions? Evasion { get; set; }
        public EnvironmentGateOptions? Environment { get; set; }
    }

    private static void EnsureLoaded()
    {
        lock (Gate)
        {
            if (_loaded) return;
            _loaded = true;
            try
            {
                if (!File.Exists(SettingsPath)) return;
                // A corrupt or hand-edited file must not stop the application
                // from starting; fall back to engine defaults instead.
                var payload = JsonSerializer.Deserialize<Payload>(File.ReadAllText(SettingsPath), Json);
                if (payload is null) return;
                if (payload.Evasion is not null) _evasion = payload.Evasion;
                if (payload.Environment is not null) _environment = payload.Environment;
            }
            catch (Exception ex)
            {
                ClientDiagnosticLog.Error("读取规避设置失败，改用默认值", ex);
            }
        }
    }

    private static void Save()
    {
        Payload payload;
        lock (Gate) payload = new Payload { Evasion = _evasion.Clone(), Environment = _environment.Clone() };
        try
        {
            var path = SettingsPath;
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            // Write-then-replace so a crash mid-write cannot leave a truncated
            // file that the next start would refuse to parse.
            var temporary = path + ".tmp";
            File.WriteAllText(temporary, JsonSerializer.Serialize(payload, Json));
            File.Move(temporary, path, true);
        }
        catch (Exception ex)
        {
            ClientDiagnosticLog.Error("保存规避设置失败", ex);
        }
    }
}
