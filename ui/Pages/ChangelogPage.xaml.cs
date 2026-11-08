using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using NovaProtect.UI.Models;
using NovaProtect.UI.Services;

namespace NovaProtect.UI.Pages;

/// <summary>
/// The client's change log.
///
/// Live data comes from GitHub Releases, but the page never depends on the
/// network to be useful: on any failure it shows <see cref="ChangelogFallback"/>
/// and says so, instead of an empty list that looks like a bug.
/// </summary>
public sealed partial class ChangelogPage : Page
{
    private bool _loaded;

    public ChangelogPage()
    {
        InitializeComponent();
    }

    protected override void OnNavigatedTo(Microsoft.UI.Xaml.Navigation.NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        // Show the baked list immediately so the page is never blank while the
        // request is in flight, then upgrade to the live one when it arrives.
        if (!_loaded)
        {
            _loaded = true;
            ShowFallback("正在读取 GitHub 发布历史…", InfoBarSeverity.Informational);
        }
        _ = RefreshAsync();
    }

    private async Task RefreshAsync()
    {
        BusyRing.IsActive = true;
        RefreshButton.IsEnabled = false;
        try
        {
            var feed = await UpdateClient.Shared.ListReleasesAsync();
            if (feed.Error is not null)
            {
                ShowFallback(feed.Error, InfoBarSeverity.Warning);
                return;
            }
            Render(feed.Releases);
            StatusBar.IsOpen = false;
        }
        finally
        {
            BusyRing.IsActive = false;
            RefreshButton.IsEnabled = true;
        }
    }

    private void ShowFallback(string reason, InfoBarSeverity severity)
    {
        Render(ChangelogFallback.Releases);
        StatusBar.Severity = severity;
        StatusBar.Title = "显示的是随程序打包的版本记录";
        StatusBar.Message = reason + " 联网后按「刷新」可读取完整发布历史。";
        StatusBar.IsOpen = true;
    }

    private void Render(IReadOnlyList<ClientReleaseNote> releases)
    {
        var rows = releases.Select(note => new ReleaseRow(
            string.Equals(note.Version, ProductInfo.Version, StringComparison.Ordinal),
            $"v{note.Version}",
            TitleText(note),
            NoteText(note),
            PublishedText(note),
            note.PageUrl)).ToList();

        ReleaseList.ItemsSource = rows;
        EmptyCard.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>
    /// GitHub release names are optional and are very often just the version
    /// again, which would render as "v2.3.33  2.3.33" next to the badge.
    /// </summary>
    private static string TitleText(ClientReleaseNote note)
    {
        var title = note.Title.Trim();
        if (title.Length == 0 ||
            string.Equals(title, note.Version, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(title, "v" + note.Version, StringComparison.OrdinalIgnoreCase))
            return $"NovaProtect {note.Version}";
        return title;
    }

    /// <summary>
    /// Release bodies are Markdown. Rendering raw HTML would let a release body
    /// inject markup into the application, and a full Markdown renderer is a lot
    /// of dependency for a change log, so the few constructs that actually appear
    /// (headings, bullets, bold, code) are flattened to readable plain text.
    /// </summary>
    private static string NoteText(ClientReleaseNote note)
    {
        var lines = note.Notes.Replace("\r\n", "\n").Split('\n');
        var output = new List<string>(lines.Length);
        var inFence = false;
        foreach (var raw in lines)
        {
            var line = raw.TrimEnd();
            var trimmed = line.TrimStart();
            if (trimmed.StartsWith("```", StringComparison.Ordinal))
            {
                inFence = !inFence;
                continue;
            }
            if (trimmed.Length == 0)
            {
                output.Add(string.Empty);
                continue;
            }
            if (inFence)
            {
                // Code blocks in release notes are usually short snippets or
                // ASCII tables; keep the text, drop the fence.
                output.Add("  " + line);
                continue;
            }
            if (trimmed.StartsWith("#", StringComparison.Ordinal))
            {
                output.Add(trimmed.TrimStart('#').Trim());
                continue;
            }
            // Markdown table: join the cells, drop the |---| separator row.
            if (trimmed.StartsWith("|", StringComparison.Ordinal))
            {
                var cells = trimmed.Trim('|').Split('|', StringSplitOptions.TrimEntries);
                if (cells.All(cell => cell.Length == 0 || cell.All(ch => ch is '-' or ':')))
                    continue;
                output.Add("· " + string.Join(" · ", cells.Where(cell => cell.Length > 0).Select(Strip)));
                continue;
            }
            if (trimmed is "---" or "***" or "___") continue;
            if (trimmed.StartsWith("- ", StringComparison.Ordinal) || trimmed.StartsWith("* ", StringComparison.Ordinal))
            {
                output.Add("· " + Strip(trimmed[2..]));
                continue;
            }
            output.Add(Strip(trimmed));
        }

        // Collapse runs of blank lines so the card does not get tall gaps.
        var collapsed = new List<string>(output.Count);
        foreach (var line in output)
        {
            if (line.Length == 0 && collapsed.Count > 0 && collapsed[^1].Length == 0) continue;
            collapsed.Add(line);
        }

        // Some releases carry a multi-screen write-up. Showing all of it turns one
        // card into the whole page, so keep a readable preview and let the link
        // below the card carry the reader to the full text.
        const int previewLines = 16;
        if (collapsed.Count > previewLines)
        {
            var preview = collapsed.Take(previewLines).ToList();
            while (preview.Count > 0 && preview[^1].Length == 0) preview.RemoveAt(preview.Count - 1);
            preview.Add($"…（共 {collapsed.Count} 行，完整说明见下方 GitHub 链接）");
            return string.Join("\n", preview);
        }

        return string.Join("\n", collapsed).Trim();
    }

    /// <summary>Drop Markdown emphasis and inline-code markers, keep the text.</summary>
    private static string Strip(string value) =>
        value.Replace("**", string.Empty)
             .Replace("__", string.Empty)
             .Replace("`", string.Empty);

    private static string PublishedText(ClientReleaseNote note)
    {
        if (string.IsNullOrWhiteSpace(note.PublishedAt)) return note.Prerelease ? "预发布" : string.Empty;
        return DateTimeOffset.TryParse(note.PublishedAt, out var when)
            ? when.ToLocalTime().ToString("yyyy-MM-dd")
            : note.PublishedAt!;
    }

    private async void Refresh_Click(object sender, RoutedEventArgs e)
    {
        StatusBar.IsOpen = false;
        await RefreshAsync();
    }

    /// <summary>Row shape for the item template.</summary>
    public sealed record ReleaseRow(
        bool IsCurrent, string VersionLabel, string Title, string Notes, string PublishedLabel, string? PageUrl)
    {
        public Visibility CurrentBadgeVisibility => IsCurrent ? Visibility.Visible : Visibility.Collapsed;

        public Visibility LinkVisibility =>
            string.IsNullOrWhiteSpace(PageUrl) ? Visibility.Collapsed : Visibility.Visible;
    }
}
