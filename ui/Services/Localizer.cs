namespace NovaProtect.UI.Services;

/// <summary>Languages the client UI can be shown in.</summary>
public enum UiLanguage
{
    ChineseSimplified = 0,
    English = 1
}

/// <summary>
/// Client UI language.
///
/// Every page carries its Chinese text inline, so the Chinese string *is* the
/// key: <see cref="T"/> maps it to English through <see cref="LocalizerStrings"/>.
/// This is the same "Chinese source as the key" convention the website uses, and
/// it means a page body needs no marker of any kind to become translatable —
/// <c>Localizer.VisualTree.cs</c> walks the visual tree after the page loads and
/// rewrites whatever it recognises.
///
/// Text the walker cannot see — strings built in code, interpolated messages,
/// values pushed into item templates — is translated at the call site with
/// <see cref="T"/> and <see cref="F"/>. A miss returns the input unchanged, so an
/// entry not yet in the table renders as its Chinese original instead of a blank
/// or a raw key.
///
/// This half of the class is deliberately free of WinUI types: the headless
/// planner smoke test compiles it straight from the UI tree, so the strings it
/// asserts on are the ones the client actually ships.
/// </summary>
public static partial class Localizer
{
    private static bool _loaded;
    private static UiLanguage _language = UiLanguage.ChineseSimplified;

    /// <summary>Raised after the language changed, so the shell can re-apply.</summary>
    public static event EventHandler? Changed;

    public static UiLanguage Language
    {
        get
        {
            EnsureLoaded();
            return _language;
        }
    }

    public static void SetLanguage(UiLanguage language)
    {
        EnsureLoaded();
        if (_language == language) return;
        _language = language;
        Persist(language);
        Changed?.Invoke(null, EventArgs.Empty);
    }

    /// <summary>Translate one Chinese source string.</summary>
    public static string T(string? source)
    {
        if (string.IsNullOrEmpty(source)) return source ?? string.Empty;
        EnsureLoaded();
        return Render(source);
    }

    /// <summary>
    /// Translate a Chinese template and fill in its arguments. Templates use the
    /// <c>{0}</c>, <c>{1}</c> … form of <see cref="string.Format(string,object?[])"/>,
    /// and the placeholders survive translation because the table is keyed on the
    /// whole template.
    /// </summary>
    public static string F(string template, params object?[] args)
    {
        var translated = T(template);
        return args.Length == 0 ? translated : string.Format(translated, args);
    }

    // ---- symbolic aliases -------------------------------------------------

    /// <summary>
    /// Shell chrome addresses some labels by name instead of by their Chinese
    /// text: the navigation buttons carry a glyph in <c>Tag</c>, the status strip
    /// is written from a route table, and the theme chips keep the theme id in
    /// <c>Tag</c>, so none of them has an inline string to key on. Each alias
    /// resolves to the Chinese source and then goes through the same table as
    /// everything else, which keeps one source of truth per string.
    ///
    /// A key missing from this map is returned verbatim by <see cref="Get"/>, so
    /// every key the shell asks for must be listed here.
    /// </summary>
    private static readonly Dictionary<string, string> Aliases = new(StringComparer.Ordinal)
    {
        ["nav.workspace"] = "工作台",
        ["app.tagline"] = "代码保护工作台",
        ["status.ready"] = "就绪",
        ["status.loadfailed"] = "页面加载失败",

        ["nav.protect"] = "保护项目",
        ["nav.evasion"] = "对抗与规避",
        ["nav.inspect"] = "检查工具",
        ["nav.activity"] = "运行记录",
        ["nav.changelog"] = "更新日志",
        ["nav.settings"] = "设置",

        ["hint.protect"] = "选择目标、调整策略、构建受保护版本",
        ["hint.evasion"] = "静态特征清洗、动态探测与内核探针",
        ["hint.inspect"] = "读取 PE 信息、水印与虚拟文件清单",
        ["hint.activity"] = "本机保存的保护运行历史",
        ["hint.changelog"] = "与 GitHub Releases 同步的版本记录",
        ["hint.settings"] = "外观、语言、更新与数据目录",

        ["theme.glass"] = "玻璃",
        ["theme.pop"] = "波普",
        ["theme.lab"] = "实验室",
        ["settings.theme.glass"] = "液态玻璃（默认）",
        ["settings.theme.pop"] = "新波普",
        ["settings.theme.lab"] = "暗色实验室",
        ["lang.zh"] = "简体中文",
        ["lang.en"] = "英语",

        ["status.preparing"] = "正在准备保护管线…"
    };

    /// <summary>Translate a symbolic key. Unknown keys pass through unchanged so a
    /// stale alias shows up as itself instead of blanking a label.</summary>
    public static string Get(string key)
        => T(Aliases.TryGetValue(key, out var source) ? source : key);

    private static string Render(string source)
        => _language == UiLanguage.English
            ? (LocalizerStrings.En.TryGetValue(source, out var english) ? english : source)
            : source;

    // ---- persistence ------------------------------------------------------

    private static string SettingsPath =>
        System.IO.Path.Combine(
            System.Environment.GetFolderPath(System.Environment.SpecialFolder.LocalApplicationData),
            "NovaProtect",
            "ui-language.txt");

    private static void EnsureLoaded()
    {
        if (_loaded) return;
        _loaded = true;
        try
        {
            var path = SettingsPath;
            if (!System.IO.File.Exists(path)) return;
            var saved = System.IO.File.ReadAllText(path).Trim();
            _language = string.Equals(saved, "en", StringComparison.OrdinalIgnoreCase)
                ? UiLanguage.English
                : UiLanguage.ChineseSimplified;
        }
        catch (Exception ex)
        {
            // A bad preference must not stop the client from starting.
            ClientDiagnosticLog.Error("读取界面语言失败，改用简体中文", ex);
            _language = UiLanguage.ChineseSimplified;
        }
    }

    private static void Persist(UiLanguage language)
    {
        try
        {
            var path = SettingsPath;
            System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
            System.IO.File.WriteAllText(path, language == UiLanguage.English ? "en" : "zh-Hans");
        }
        catch (Exception ex)
        {
            ClientDiagnosticLog.Error("保存界面语言失败", ex);
        }
    }
}
