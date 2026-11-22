using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace NovaProtect.UI;

/// <summary>
/// Visual themes: glass / pop / lab — three unmistakable worlds (AGENTS.md).
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
///   then RequestedTheme is nudged through the opposite value at the end of
///   Apply so every ThemeResource reference re-resolves.
/// </summary>
public static class NovaTheme
{
    public const string Glass = "glass";
    public const string Pop = "pop";
    public const string Lab = "lab";

    public static string Current { get; private set; } = Glass;

    public static string Normalize(string? theme) => theme switch
    {
        Pop => Pop,
        Lab => Lab,
        _ => Glass,
    };

    public static void Apply(FrameworkElement root, string theme)
    {
        if (root is null) throw new ArgumentNullException(nameof(root));
        theme = Normalize(theme);
        Current = theme;

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
        SetRadius("CardCornerRadius", theme == Pop ? 2 : theme == Lab ? 4 : 22);
        SetRadius("CardCompactCornerRadius", theme == Pop ? 2 : theme == Lab ? 4 : 14);
        SetRadius("ControlCornerRadius", theme == Pop ? 2 : theme == Lab ? 2 : 12);
        SetRadius("ButtonCornerRadius", theme == Pop ? 2 : theme == Lab ? 2 : 12);
        SetRadius("PillCornerRadius", theme == Pop ? 2 : theme == Lab ? 2 : 12);
        SetRadius("ChipCornerRadius", theme == Pop ? 2 : theme == Lab ? 2 : 10);
        // Track is a soft rounded rect (website: glass 12 / pop 4 / lab 6), not a 999 pill.
        SetRadius("NovaThemeChipTrackCornerRadius", theme == Pop ? 4 : theme == Lab ? 6 : 12);
        SetThickness("NovaCardBorderThickness", theme == Pop ? 2 : 1);
        SetThickness("NovaControlBorderThickness", theme == Pop ? 2 : 1);

        // ---- type language --------------------------------------------------------
        // The era lives in the display/data faces; body prose stays humanist for
        // readability (full-era body type was the dross).
        SetFont("NovaDisplayFontFamily", theme == Pop ? "Bahnschrift" : theme == Lab ? "Cascadia Mono" : "Segoe UI Variable Display");
        SetFont("NovaBodyFontFamily", "Segoe UI Variable Text");
        SetFont("NovaDataFontFamily", theme == Pop ? "Bahnschrift" : theme == Lab ? "Cascadia Mono" : "Segoe UI Variable Text");

        // Value tokens are replaced, not mutated; nudge RequestedTheme through
        // the opposite pole so every ThemeResource (radii/fonts/thickness in
        // style setters) re-resolves even when glass<->pop keeps the same
        // Light/Dark polarity.
        var target = theme == Lab ? ElementTheme.Dark : ElementTheme.Light;
        root.RequestedTheme = target == ElementTheme.Dark ? ElementTheme.Light : ElementTheme.Dark;
        root.RequestedTheme = target;
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

    // Replace value-type tokens in the top-level dictionary and both theme
    // dictionaries so whichever copy a ThemeResource resolves against is the
    // current theme's value.
    private static void MutateValues(string key, Func<object, object> build)
    {
        var app = Application.Current;
        if (app is null) return;
        if (app.Resources.TryGetValue(key, out var cur))
            app.Resources[key] = build(cur);
        foreach (var dk in new[] { "Light", "Dark" })
        {
            if (app.Resources.ThemeDictionaries.TryGetValue(dk, out var d) &&
                d is ResourceDictionary dict && dict.TryGetValue(key, out var v))
                dict[key] = build(v);
        }
    }

    // Walk every place a brush can be cached - the top-level dictionary and
    // both theme dictionaries - and mutate each matching brush in place.
    private static void MutateBrushes(string key, Func<Brush, bool> mutate, Func<Brush> create)
    {
        var app = Application.Current;
        if (app is null) return;
        var mutated = false;
        if (app.Resources.TryGetValue(key, out var top) && top is Brush topBrush)
            mutated |= mutate(topBrush);
        foreach (var dk in new[] { "Light", "Dark" })
        {
            if (app.Resources.ThemeDictionaries.TryGetValue(dk, out var d) &&
                d is ResourceDictionary dict && dict.TryGetValue(key, out var v) && v is Brush themeBrush)
                mutated |= mutate(themeBrush);
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
