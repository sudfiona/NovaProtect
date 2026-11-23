using System.Runtime.CompilerServices;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Media;

namespace NovaProtect.UI.Services;

/// <summary>
/// The WinUI half of <see cref="Localizer"/>: everything that has to walk a live
/// element tree. Split out from the string table so the headless planner smoke
/// test can compile the translation core without a WinUI reference.
/// </summary>
public static partial class Localizer
{
    // ---- page wiring ------------------------------------------------------

    /// <summary>
    /// Keep one page translated for the life of the window.
    ///
    /// Translation has to run after the page loaded (there is no visual tree
    /// before that) and again on every language change. The subscription is
    /// attached in Loaded and dropped in Unloaded rather than once in the
    /// constructor, so a page that is not navigation-cached — a new instance per
    /// visit — does not leave a handler pointing at a discarding instance on a
    /// static event.
    ///
    /// <paramref name="refresh"/> runs before the walk: pages that build text in
    /// code re-run their own label refresh first, which rewrites the Chinese
    /// sources, and the walk then renders whichever language is current. Without
    /// that order a language change would leave the code-built lines in the
    /// previous language.
    /// </summary>
    public static void Attach(FrameworkElement page, Action? refresh = null)
    {
        void OnChanged(object? sender, EventArgs e)
        {
            refresh?.Invoke();
            ApplyTo(page);
        }

        page.Loaded += (_, _) =>
        {
            Changed -= OnChanged;
            Changed += OnChanged;
            refresh?.Invoke();
            ApplyTo(page);
        };
        page.Unloaded += (_, _) => Changed -= OnChanged;
    }

    // ---- visual-tree application ------------------------------------------

    /// <summary>
    /// What we last wrote onto one slot of one element, plus the source it came
    /// from. Kept beside the element (weakly) instead of in a XAML property so a
    /// page can be translated without touching its markup.
    ///
    /// <see cref="Rendered"/> is what makes re-application safe: when the live
    /// value no longer matches what we wrote, someone else now owns it, so it is
    /// re-derived rather than clobbered.
    /// </summary>
    private sealed class SlotState
    {
        public string? Source;
        public string? Rendered;
    }

    private static readonly ConditionalWeakTable<DependencyObject, Dictionary<string, SlotState>>
        States = new();

    /// <summary>
    /// Rewrite every recognised string under <paramref name="root"/>. Call it
    /// after the page has loaded: the visual tree does not exist earlier.
    /// </summary>
    public static void ApplyTo(DependencyObject? root)
    {
        if (root is null) return;
        ApplyOne(root);
        var count = VisualTreeHelper.GetChildrenCount(root);
        for (var i = 0; i < count; i++) ApplyTo(VisualTreeHelper.GetChild(root, i));
    }

    private static void ApplyOne(DependencyObject node)
    {
        // Text surfaces whose content can be a plain string.
        switch (node)
        {
            case TextBlock text:
                Slot(text, "text", text.Text, v => text.Text = v);
                foreach (var inline in text.Inlines)
                {
                    if (inline is Run run) Slot(run, "text", run.Text, v => run.Text = v);
                }
                break;

            case Button button when button.Content is string s:
                Slot(button, "text", s, v => button.Content = v);
                break;

            case HyperlinkButton link when link.Content is string s:
                Slot(link, "text", s, v => link.Content = v);
                break;

            case CheckBox check when check.Content is string s:
                Slot(check, "text", s, v => check.Content = v);
                break;

            case RadioButton radio when radio.Content is string s:
                Slot(radio, "text", s, v => radio.Content = v);
                break;

            case ComboBoxItem item when item.Content is string s:
                Slot(item, "text", s, v => item.Content = v);
                break;

            case NavigationViewItem nav when nav.Content is string s:
                Slot(nav, "text", s, v => nav.Content = v);
                break;

            case ToggleMenuFlyoutItem toggle:
                Slot(toggle, "text", toggle.Text, v => toggle.Text = v);
                break;

            case MenuFlyoutItem menu:
                Slot(menu, "text", menu.Text, v => menu.Text = v);
                break;

            case AppBarButton appBar:
                Slot(appBar, "text", appBar.Label, v => appBar.Label = v);
                break;

            case InfoBar bar:
                Slot(bar, "title", bar.Title, v => bar.Title = v);
                Slot(bar, "message", bar.Message, v => bar.Message = v);
                break;

            case Expander expander when expander.Header is string s:
                Slot(expander, "header", s, v => expander.Header = v);
                break;

            case ToggleSwitch toggle:
                if (toggle.Header is string h) Slot(toggle, "header", h, v => toggle.Header = v);
                if (toggle.OnContent is string on) Slot(toggle, "oncontent", on, v => toggle.OnContent = v);
                if (toggle.OffContent is string off) Slot(toggle, "offcontent", off, v => toggle.OffContent = v);
                break;

            case ComboBox combo:
                if (combo.Header is string comboHeader) Slot(combo, "header", comboHeader, v => combo.Header = v);
                Slot(combo, "placeholder", combo.PlaceholderText, v => combo.PlaceholderText = v);
                break;

            case AutoSuggestBox suggest:
                if (suggest.Header is string suggestHeader) Slot(suggest, "header", suggestHeader, v => suggest.Header = v);
                Slot(suggest, "placeholder", suggest.PlaceholderText, v => suggest.PlaceholderText = v);
                break;

            case TextBox textBox:
                if (textBox.Header is string textHeader) Slot(textBox, "header", textHeader, v => textBox.Header = v);
                Slot(textBox, "placeholder", textBox.PlaceholderText, v => textBox.PlaceholderText = v);
                break;

            case PasswordBox password:
                if (password.Header is string passwordHeader) Slot(password, "header", passwordHeader, v => password.Header = v);
                Slot(password, "placeholder", password.PlaceholderText, v => password.PlaceholderText = v);
                break;

            case NumberBox number:
                if (number.Header is string numberHeader) Slot(number, "header", numberHeader, v => number.Header = v);
                Slot(number, "placeholder", number.PlaceholderText, v => number.PlaceholderText = v);
                break;

            case Slider slider when slider.Header is string sliderHeader:
                Slot(slider, "header", sliderHeader, v => slider.Header = v);
                break;
        }

        // ComboBox and RadioButtons materialise their entries inside a popup, so
        // the visual tree does not contain them while the popup is closed. Without
        // this pass every drop-down in the client kept its Chinese entries in an
        // English UI until the popup happened to be open during a walk.
        if (node is ItemsControl control) ApplyItems(control);

        // Attached text lives on any FrameworkElement, so it needs its own pass
        // rather than one case per control type.
        if (node is FrameworkElement element)
        {
            if (ToolTipService.GetToolTip(element) is string tooltip)
                Slot(element, "tooltip", tooltip, v => ToolTipService.SetToolTip(element, v));

            var autoName = AutomationProperties.GetName(element);
            if (!string.IsNullOrEmpty(autoName))
                Slot(element, "automationname", autoName, v => AutomationProperties.SetName(element, v));
        }
    }

    /// <summary>
    /// Translate the entries of an items control. Only string-bearing containers
    /// are touched: a data-bound list such as the function table holds model
    /// objects, and those are localised by their own properties instead.
    /// </summary>
    private static void ApplyItems(ItemsControl control)
    {
        var count = control.Items.Count;
        for (var i = 0; i < count; i++)
        {
            switch (control.Items[i])
            {
                case ComboBoxItem item when item.Content is string s:
                    Slot(item, "text", s, v => item.Content = v);
                    break;
                case RadioButton radio when radio.Content is string r:
                    Slot(radio, "text", r, v => radio.Content = v);
                    break;
                case ToggleMenuFlyoutItem toggle:
                    Slot(toggle, "text", toggle.Text, v => toggle.Text = v);
                    break;
            }
        }
    }

    /// <summary>
    /// Translate one slot of one element. Writes only when the rendered value
    /// differs from what is live, so a page that is already correct is not
    /// rebuilt on every pass.
    /// </summary>
    private static void Slot(DependencyObject owner, string slot, string? current, Action<string> write)
    {
        var value = current ?? string.Empty;
        var map = States.GetOrCreateValue(owner);
        if (!map.TryGetValue(slot, out var state))
        {
            state = new SlotState();
            map[slot] = state;
        }

        if (state.Rendered is not null && string.Equals(state.Rendered, value, StringComparison.Ordinal))
        {
            // Still the value we wrote: re-render it for the current language.
            var refreshed = Render(state.Source!);
            if (!string.Equals(value, refreshed, StringComparison.Ordinal))
            {
                write(refreshed);
                state.Rendered = refreshed;
            }
            return;
        }

        // Someone else has set this slot since our last write. Adopt it only if
        // it is text we can translate and restore afterwards.
        if (!LooksTranslatable(value))
        {
            map.Remove(slot);
            return;
        }

        state.Source = value;
        var rendered = Render(value);
        state.Rendered = rendered;
        if (!string.Equals(value, rendered, StringComparison.Ordinal)) write(rendered);
    }

    /// <summary>
    /// Whether a live value is worth adopting. Chinese characters are the signal:
    /// they are the only strings the table can act on, and adopting anything else
    /// would mean holding a claim on text we cannot restore.
    /// </summary>
    private static bool LooksTranslatable(string? value)
    {
        if (string.IsNullOrEmpty(value)) return false;
        foreach (var ch in value)
        {
            if (ch is >= '\u4e00' and <= '\u9fff') return true;
        }
        return false;
    }
}
