using System.IO;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace NovaProtect.UI;

/// <summary>
/// Visual themes: black hole / glass / pop / lab (AGENTS.md).
///
///   玻璃 glass — 冷雾液态铬：冰蓝薰衣草、半透霜玻璃、全息渐变、软大圆角、人文细体。
///   波普 pop   — 热浪海报：珊瑚/柠檬/品红平涂、2px 黑色描边、直角、Bahnschrift 粗黑体。
///   实验室 lab — 深空终端：黑紫底、磷光绿+紫外、发丝线、Cascadia Mono 数据等宽。
///
/// Update rules (why they look the way they do):
/// - Brushes mutate **in place** across the top-level dictionary and both theme
///   dictionaries. StaticResource consumers captured brush objects at parse
///   time; swapping in a new object leaves them frozen on the old theme.
/// - Value tokens (radii, fonts, border thickness, glow colors) are replaced,
///   then RequestedTheme is moved at the end of Apply so every ThemeResource
///   reference re-resolves. The move is one assignment when the polarity
///   changes and a bounce only when it does not (glass <-> pop), because a
///   redundant cross-polarity hop repaints the tree and shows as a flash.
/// </summary>
public static class NovaTheme
{
    public const string BlackHole = "blackhole";
    public const string Glass = "glass";
    public const string Pop = "pop";
    public const string Lab = "lab";

    public static string Current { get; private set; } = BlackHole;
    public static event EventHandler? Changed;

    private static string PreferencePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "NovaProtect", "ui-theme.txt");

    /// <summary>Last theme actually pushed into the visual tree, so a repeat
    /// Apply (startup re-entry, a picker echoing the live theme) costs nothing
    /// instead of repainting the whole tree twice.</summary>
    private static string? _appliedTheme;

    public static string Normalize(string? theme) => theme?.Trim().ToLowerInvariant() switch
    {
        Glass => Glass,
        Pop => Pop,
        Lab => Lab,
        _ => BlackHole,
    };

    /// <summary>Apply the saved theme or the default without writing a preference.</summary>
    public static void Restore(FrameworkElement root)
    {
        string? saved = null;
        try
        {
            var path = PreferencePath;
            if (File.Exists(path)) saved = File.ReadAllText(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Services.ClientDiagnosticLog.Error("UI theme restore failed", ex);
        }
        Apply(root, saved);
    }

    /// <summary>Apply an explicit user choice and remember it for the next launch.</summary>
    public static void Select(FrameworkElement root, string theme)
    {
        var selection = Normalize(theme);
        Apply(root, selection);
        try
        {
            var path = PreferencePath;
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.WriteAllText(path, selection);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Services.ClientDiagnosticLog.Error("UI theme save failed", ex);
        }
    }

    public static void Apply(FrameworkElement root, string? theme)
    {
        if (root is null) throw new ArgumentNullException(nameof(root));
        theme = Normalize(theme);
        Current = theme;
        if (theme == _appliedTheme) return;

        // Keep the established palettes below intact when switching away from Black Hole.
        if (theme == BlackHole)
            ApplyBlackHolePalette();
        else
            ApplyClassicPalette(theme);

        // Value tokens are replaced, not mutated. RequestedTheme invalidates ThemeResource
        // references. A bounce is needed only when both themes have the same polarity.
        var target = theme is Lab or BlackHole ? ElementTheme.Dark : ElementTheme.Light;
        if (root.RequestedTheme == target)
            root.RequestedTheme = target == ElementTheme.Dark ? ElementTheme.Light : ElementTheme.Dark;
        root.RequestedTheme = target;
        _appliedTheme = theme;
        Changed?.Invoke(null, EventArgs.Empty);
    }

    private static void ApplyClassicPalette(string theme)
    {
        // ---- surfaces & ink -------------------------------------------------
        Set("NovaGlassCardBrush", theme == Pop ? "#FAF6F0" : theme == Lab ? "#C71A1233" : "#B3FFFFFF");
        Set("NovaPageBgBrush", theme == Pop ? "#FFF4E8" : theme == Lab ? "#0A0714" : "#EDF2F9");
        Set("NovaInkBrush", theme == Pop ? "#1A1208" : theme == Lab ? "#E8E4F5" : "#1E2A3D");
        Set("NovaInk2Brush", theme == Pop ? "#6B3B1E" : theme == Lab ? "#9A8FC0" : "#5B6B82");
        Set("NovaVeilBrush", theme == Pop ? "#B3FFF4E8" : theme == Lab ? "#B30A0714" : "#B3E9F0FA");
        Set("NovaGlassInputBrush", theme == Pop ? "#FFFFFF" : theme == Lab ? "#1AFFFFFF" : "#CCE6F2");
        Set("NovaGlassInputBorderBrush", theme == Pop ? "#1A1208" : theme == Lab ? "#3A2E63" : "#7A90A8");
        Set("NovaTitleDividerBrush", theme == Pop ? "#331A1208" : theme == Lab ? "#229A8FC0" : "#14000000");

        // ---- accents & badges ----------------------------------------------
        Set("NovaAccentBrush", theme == Pop ? "#FF5A3C" : theme == Lab ? "#39FF88" : "#4F8CFF");
        Set("NovaOnAccentFgBrush", theme == Lab ? "#0A0714" : "#FFFFFF");
        Set("NovaBadgeBrush", theme == Pop ? "#FFC53D" : theme == Lab ? "#2239FF88" : "#334F8CFF");
        Set("NovaBadgeBorderBrush", theme == Pop ? "#1A1208" : theme == Lab ? "#4039FF88" : "#4D4F8CFF");
        Set("NovaBadgeSuccessBrush", theme == Pop ? "#2FBF71" : theme == Lab ? "#224ADE80" : "#1F16A34A");
        Set("NovaBadgeSuccessBorderBrush", theme == Pop ? "#1A1208" : theme == Lab ? "#404ADE80" : "#3316A34A");
        Set("NovaBadgeMutedBrush", theme == Pop ? "#FFE8D2" : theme == Lab ? "#225B4E8A" : "#1F7488B2");
        Set("NovaBadgeMutedBorderBrush", theme == Pop ? "#1A1208" : theme == Lab ? "#335B4E8A" : "#337488B2");

        // ---- console ---------------------------------------------------------
        Set("NovaConsoleBrush", theme == Pop ? "#FFFFFF" : theme == Lab ? "#FF0D0A18" : "#B3FFFFFF");
        Set("NovaConsoleTextBrush", theme == Pop ? "#1A1208" : theme == Lab ? "#6BFF9E" : "#22304A");
        Set("NovaConsoleStrokeBrush", theme == Pop ? "#1A1208" : theme == Lab ? "#3339FF88" : "#66FFFFFF");

        // ---- theme chips ------------------------------------------------------
        Set("NovaThemeChipTrackBrush", theme == Pop ? "#221A1208" : theme == Lab ? "#2239FF88" : "#227488B2");
        Set("NovaThemeChipOnBrush", theme == Pop ? "#FF5A3C" : theme == Lab ? "#39FF88" : "#4F8CFF");
        Set("NovaThemeChipOnFgBrush", theme == Pop ? "#FFFFFF" : theme == Lab ? "#0A0714" : "#FFFFFF");
        Set("NovaThemeChipOffFgBrush", theme == Pop ? "#8A4B2A" : theme == Lab ? "#9A8FC0" : "#7C869B");
        Set("NovaThemeChipOffBgBrush", theme == Pop ? "#FFFDF7" : theme == Lab ? "#140E26" : "#00000000");
        Set("NovaThemeChipOffBorderBrush", theme == Pop ? "#1A1208" : theme == Lab ? "#2E224E" : "#337488B2");

        // ---- WinUI control overrides ------------------------------------------
        Set("ControlFillColorDefaultBrush", theme == Pop ? "#FFFFFF" : theme == Lab ? "#1A2440" : "#66F2F6FB");
        Set("ControlFillColorSecondaryBrush", theme == Pop ? "#FFE8D2" : theme == Lab ? "#222A4E" : "#99FFFFFF");
        Set("ControlStrokeColorDefaultBrush", theme == Pop ? "#1A1208" : theme == Lab ? "#2E224E" : "#59708C");
        Set("CardBackgroundFillColorDefaultBrush", theme == Pop ? "#FFFFFF" : theme == Lab ? "#C71A1233" : "#B3FFFFFF");
        Set("CardStrokeColorDefaultBrush", theme == Pop ? "#1A1208" : theme == Lab ? "#2E224E" : "#66FFFFFF");
        Set("AccentFillColorDefaultBrush", theme == Pop ? "#FF5A3C" : theme == Lab ? "#39FF88" : "#4F8CFF");

        // ---- borders: frost gradient / poster keyline / neon hairline ----------
        SetGradient("NovaGlassCardBorderBrush",
            theme == Pop ? Flat("#1A1208") : theme == Lab ? Flat("#2E224E")
            : Stops((255, 255, 255, 0.0), (217, 230, 248, 0.5), (175, 198, 236, 1.0)));
        SetGradient("NovaGlassCardHoverBorderBrush",
            theme == Pop ? Flat("#FF5A3C") : theme == Lab ? Flat("#39FF88")
            : Stops((255, 255, 255, 0.0), (200, 221, 255, 0.45), (139, 107, 255, 1.0)));
        SetGradient("NovaPageBackdropBrush",
            theme == Pop ? Stops((255, 253, 247, 0.0), (255, 244, 232, 0.45), (255, 232, 210, 1.0))
            : theme == Lab ? Stops((20, 14, 38, 0.0), (10, 7, 20, 0.45), (6, 4, 16, 1.0))
            : Stops((251, 253, 255, 0.0), (237, 242, 249, 0.45), (228, 235, 247, 1.0)));
        SetGradient("NovaAccentGradientBrush",
            theme == Pop ? Stops((255, 90, 60, 0.0), (232, 51, 110, 0.5), (255, 197, 61, 1.0))
            : theme == Lab ? Stops((57, 255, 136, 0.0), (34, 211, 238, 0.55), (124, 92, 255, 1.0))
            : Stops((127, 216, 255, 0.0), (79, 140, 255, 0.55), (139, 107, 255, 1.0)));
        SetGradient("NovaGradTextBrush",
            theme == Pop ? Flat("#1A1208")
            : theme == Lab ? Stops((57, 255, 136, 0.0), (90, 220, 190, 0.5), (124, 92, 255, 1.0))
            : Stops((127, 216, 255, 0.0), (79, 140, 255, 0.5), (139, 107, 255, 1.0)));

        // ---- aurora orbs: cold holo / heat wave / nebula -------------------------
        SetColor("NovaGlowBlueCoreColor", theme == Pop ? "#B3FFB3A0" : theme == Lab ? "#665B8CFF" : "#B34A8CFF");
        SetColor("NovaGlowBlueEdgeColor", theme == Pop ? "#00FFB3A0" : theme == Lab ? "#005B8CFF" : "#003B82E8");
        SetColor("NovaGlowCyanCoreColor", theme == Pop ? "#99FFD9A0" : theme == Lab ? "#5539FF88" : "#9938C6D9");
        SetColor("NovaGlowCyanEdgeColor", theme == Pop ? "#00FFD9A0" : theme == Lab ? "#0039FF88" : "#002BB8CC");
        SetColor("NovaGlowVioletCoreColor", theme == Pop ? "#B3FF8FB8" : theme == Lab ? "#557C5CFF" : "#B37C5CFF");
        SetColor("NovaGlowVioletEdgeColor", theme == Pop ? "#00FF8FB8" : theme == Lab ? "#007C5CFF" : "#006A4FE8");
        SetColor("NovaGlowRoseCoreColor", theme == Pop ? "#80FF6B4A" : theme == Lab ? "#33B84AE0" : "#80FF8FB0");
        SetColor("NovaGlowRoseEdgeColor", theme == Pop ? "#00FF6B4A" : theme == Lab ? "#00B84AE0" : "#00FF8FB0");

        // ---- shape language ------------------------------------------------------
        SetRadius("CardCornerRadius", theme == Pop ? 15 : theme == Lab ? 12 : 22);
        SetRadius("CardCompactCornerRadius", theme == Pop ? 12 : theme == Lab ? 9 : 14);
        SetRadius("ControlCornerRadius", theme == Pop ? 9 : theme == Lab ? 7 : 12);
        SetRadius("ButtonCornerRadius", theme == Pop ? 10 : theme == Lab ? 8 : 12);
        SetRadius("PillCornerRadius", theme == Pop ? 11 : theme == Lab ? 9 : 12);
        SetRadius("ChipCornerRadius", theme == Pop ? 9 : theme == Lab ? 7 : 10);
        SetRadius("NovaThemeChipTrackCornerRadius", theme == Pop ? 13 : theme == Lab ? 11 : 15);
        SetRadius("NovaIconTileCornerRadius", theme == Pop ? 12 : theme == Lab ? 10 : 15);
        Set("NovaIconTileBrush", theme == Pop ? "#FFE2D6" : theme == Lab ? "#1CFF88B8" : "#D9E9FF");
        Set("NovaIconTileBorderBrush", theme == Pop ? "#B66653" : theme == Lab ? "#665FFD9B" : "#8DACD8");
        Set("NovaIconGlyphBrush", theme == Pop ? "#8F3126" : theme == Lab ? "#A8F5C5" : "#254F99");
        Set("NovaNavSelectionBrush", theme == Pop ? "#FFF0E9" : theme == Lab ? "#262039" : "#ECF4FF");
        SetThickness("NovaCardBorderThickness", theme == Pop ? 2 : 1);
        SetThickness("NovaControlBorderThickness", theme == Pop ? 2 : 1);

        // ---- type language --------------------------------------------------------
        // The era lives in the display/data faces; body prose stays humanist for
        // readability (full-era body type was the dross).
        SetFont("NovaDisplayFontFamily", theme == Pop ? "Bahnschrift" : theme == Lab ? "Cascadia Mono" : "Segoe UI Variable Display");
        SetFont("NovaBodyFontFamily", "Segoe UI Variable Text");
        SetFont("NovaDataFontFamily", theme == Pop ? "Bahnschrift" : theme == Lab ? "Cascadia Mono" : "Segoe UI Variable Text");

        // Restore the standard Light/Dark interaction colors after leaving Black Hole.
        Set("ControlFillColorTertiaryBrush", theme == Lab ? "#3322D3EE" : "#662E7CF6");
        Set("AccentFillColorSecondaryBrush", theme == Lab ? "#3322D3EE" : "#402E7CF6");
        Set("AccentFillColorTertiaryBrush", theme == Lab ? "#4D22D3EE" : "#662E7CF6");
    }

    private static void ApplyBlackHolePalette()
    {
        const string voidColor = "#050506";
        const string accent = "#C3C6C9";
        const string onAccent = "#151617";
        const string stroke = "#3B3B40";
        const string surface = "#F0121214";
        const string mutedInk = "#B5B7BA";

        // Black and charcoal surfaces leave the color in the disk and interaction accents.
        Set("NovaGlassCardBrush", surface);
        Set("NovaPageBgBrush", voidColor);
        Set("NovaInkBrush", "#EFF0F1");
        Set("NovaInk2Brush", mutedInk);
        Set("NovaVeilBrush", "#F0050506");
        Set("NovaGlassInputBrush", "#1B1B1E");
        Set("NovaGlassInputBorderBrush", stroke);
        Set("NovaTitleDividerBrush", "#55AAADB0");

        Set("NovaAccentBrush", accent);
        Set("NovaOnAccentFgBrush", onAccent);
        Set("NovaBadgeBrush", "#355F6265");
        Set("NovaBadgeBorderBrush", "#88989B9E");
        Set("NovaBadgeSuccessBrush", "#224ADE80");
        Set("NovaBadgeSuccessBorderBrush", "#664ADE80");
        Set("NovaBadgeMutedBrush", "#296F7275");
        Set("NovaBadgeMutedBorderBrush", "#557E8184");

        Set("NovaConsoleBrush", "#F20B0B0D");
        Set("NovaConsoleTextBrush", "#D6D8DA");
        Set("NovaConsoleStrokeBrush", "#807A7D80");

        Set("NovaThemeChipTrackBrush", "#48595B5D");
        Set("NovaThemeChipOnBrush", accent);
        Set("NovaThemeChipOnFgBrush", onAccent);
        Set("NovaThemeChipOffFgBrush", mutedInk);
        Set("NovaThemeChipOffBgBrush", "#1B1B1E");
        Set("NovaThemeChipOffBorderBrush", stroke);

        Set("ControlFillColorDefaultBrush", "#1B1B1E");
        Set("ControlFillColorSecondaryBrush", "#242427");
        Set("ControlFillColorTertiaryBrush", "#2E2E32");
        Set("ControlStrokeColorDefaultBrush", stroke);
        Set("CardBackgroundFillColorDefaultBrush", surface);
        Set("CardStrokeColorDefaultBrush", stroke);
        Set("AccentFillColorDefaultBrush", accent);
        Set("AccentFillColorSecondaryBrush", "#DADCDD");
        Set("AccentFillColorTertiaryBrush", "#A8ABAE");

        SetGradient("NovaGlassCardBorderBrush",
            Stops((107, 110, 113, 0.0), (65, 67, 70, 0.48), (46, 47, 49, 1.0)));
        SetGradient("NovaGlassCardHoverBorderBrush",
            Stops((187, 191, 194, 0.0), (128, 131, 134, 0.52), (161, 140, 108, 1.0)));
        SetGradient("NovaPageBackdropBrush",
            Stops((8, 8, 9, 0.0), (4, 4, 5, 0.50), (10, 10, 12, 1.0)));
        SetGradient("NovaAccentGradientBrush",
            Stops((221, 224, 226, 0.0), (179, 182, 185, 0.50), (195, 172, 136, 1.0)));
        SetGradient("NovaGradTextBrush",
            Stops((241, 242, 243, 0.0), (201, 204, 207, 0.55), (218, 197, 165, 1.0)));

        SetColor("NovaGlowBlueCoreColor", "#08A8AAAD");
        SetColor("NovaGlowBlueEdgeColor", "#00A8AAAD");
        SetColor("NovaGlowCyanCoreColor", "#06CED0D2");
        SetColor("NovaGlowCyanEdgeColor", "#00CED0D2");
        SetColor("NovaGlowVioletCoreColor", "#0886888A");
        SetColor("NovaGlowVioletEdgeColor", "#0086888A");
        SetColor("NovaGlowRoseCoreColor", "#06C3AC88");
        SetColor("NovaGlowRoseEdgeColor", "#00C3AC88");

        SetRadius("CardCornerRadius", 19);
        SetRadius("CardCompactCornerRadius", 13);
        SetRadius("ControlCornerRadius", 10);
        SetRadius("ButtonCornerRadius", 11);
        SetRadius("PillCornerRadius", 14);
        SetRadius("ChipCornerRadius", 10);
        SetRadius("NovaThemeChipTrackCornerRadius", 14);
        SetRadius("NovaIconTileCornerRadius", 14);
        Set("NovaIconTileBrush", "#252628");
        Set("NovaIconTileBorderBrush", "#5B5955");
        Set("NovaIconGlyphBrush", "#D6C09D");
        Set("NovaNavSelectionBrush", "#303133");
        SetThickness("NovaCardBorderThickness", 1.5);
        SetThickness("NovaControlBorderThickness", 1);
        SetFont("NovaDisplayFontFamily", "Cambria");
        SetFont("NovaBodyFontFamily", "Segoe UI Variable Text");
        SetFont("NovaDataFontFamily", "Consolas");
    }

    // ---- resource mutation helpers -----------------------------------------

    private static void Set(string key, string argb)
    {
        var color = Parse(argb);
        MutateBrushes(key, brush =>
        {
            if (brush is SolidColorBrush solid) { solid.Color = color; return true; }
            return false;
        }, () => new SolidColorBrush(color));
    }

    private static void SetGradient(string key, (byte r, byte g, byte b, double o)[] stops)
    {
        MutateBrushes(key, brush =>
        {
            if (brush is not LinearGradientBrush grad) return false;
            grad.GradientStops.Clear();
            foreach (var s in stops)
                grad.GradientStops.Add(new GradientStop { Color = C((s.r, s.g, s.b)), Offset = s.o });
            return true;
        }, () =>
        {
            var brush = new LinearGradientBrush
            {
                StartPoint = new Windows.Foundation.Point(0, 0),
                EndPoint = new Windows.Foundation.Point(1, 1),
            };
            foreach (var s in stops)
                brush.GradientStops.Add(new GradientStop { Color = C((s.r, s.g, s.b)), Offset = s.o });
            return brush;
        });
    }

    private static void SetColor(string key, string argb)
    {
        var color = Parse(argb);
        MutateValues(key, _ => color);
    }

    private static void SetRadius(string key, double uniform)
    {
        MutateValues(key, _ => new CornerRadius(uniform));
    }

    private static void SetThickness(string key, double uniform)
    {
        MutateValues(key, _ => new Thickness(uniform));
    }

    private static void SetFont(string key, string family)
    {
        MutateValues(key, _ => new FontFamily(family));
    }

    // The palette lives in a merged dictionary. Visit both of its theme
    // dictionaries directly rather than mutating only the currently resolved copy.
    private static IEnumerable<ResourceDictionary> PaletteDictionaries(ResourceDictionary dictionary)
    {
        yield return dictionary;
        foreach (var name in new[] { "Light", "Dark" })
        {
            if (dictionary.ThemeDictionaries.TryGetValue(name, out var value) &&
                value is ResourceDictionary themed)
                yield return themed;
        }
        foreach (var merged in dictionary.MergedDictionaries)
        {
            if (merged is Microsoft.UI.Xaml.Controls.XamlControlsResources) continue;
            foreach (var nested in PaletteDictionaries(merged)) yield return nested;
        }
    }

    private static void MutateValues(string key, Func<object, object> build)
    {
        var app = Application.Current;
        if (app is null) return;
        foreach (var dictionary in PaletteDictionaries(app.Resources))
        {
            if (dictionary.Keys.Contains(key))
            {
                // WinUI accepts value overrides on the inline application dictionary.
                // A dictionary loaded through Source only permits in-place brush changes.
                app.Resources[key] = build(dictionary[key]);
                return;
            }
        }
    }

    private static void MutateBrushes(string key, Func<Brush, bool> mutate, Func<Brush> create)
    {
        var app = Application.Current;
        if (app is null) return;
        var mutated = false;
        foreach (var dictionary in PaletteDictionaries(app.Resources))
        {
            if (dictionary.Keys.Contains(key) && dictionary[key] is Brush brush)
                mutated |= mutate(brush);
        }
        if (!mutated) app.Resources[key] = create();
    }

    private static (byte r, byte g, byte b, double o)[] Stops(
        (byte r, byte g, byte b, double o) a,
        (byte r, byte g, byte b, double o) b,
        (byte r, byte g, byte b, double o) c) => new[] { a, b, c };

    private static (byte r, byte g, byte b, double o)[] Flat(string argb)
    {
        var color = Parse(argb);
        (byte r, byte g, byte b, double o) stop = (color.R, color.G, color.B, 0.0);
        return new[] { stop, stop with { o = 0.5 }, stop with { o = 1.0 } };
    }

    private static Color Parse(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new ArgumentException("color required", nameof(value));

        value = value.Trim().TrimStart('#');
        if (value.Length is not (6 or 8) || !IsHex(value))
            throw new FormatException("invalid color: " + value);

        var a = byte.MaxValue;
        if (value.Length == 8)
        {
            a = Convert.ToByte(value[..2], 16);
            value = value[2..];
        }

        return Color.FromArgb(
            a,
            Convert.ToByte(value[..2], 16),
            Convert.ToByte(value[2..4], 16),
            Convert.ToByte(value[4..6], 16));
    }

    private static bool IsHex(string s)
    {
        foreach (var c in s)
        {
            var ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!ok) return false;
        }
        return true;
    }

    private static Color C((byte r, byte g, byte b) v) => Color.FromArgb(255, v.r, v.g, v.b);
}
