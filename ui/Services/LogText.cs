using System.Text;

namespace NovaProtect.UI.Services;

/// <summary>
/// Length limits for the read-only log-style text boxes (构建日志 / 审计输出 /
/// 检查结果).
///
/// A protection run streams progress lines far faster than a person can read, and
/// a tool dump such as <c>-info</c> on a large PE can be tens of thousands of
/// lines. Left unbounded the box becomes impossible to scroll, and every flush
/// re-assigns an ever-growing string to a TextBox. Both are bounded here: the
/// kept window is the *most recent* output, with an explicit notice saying how
/// much was dropped so a truncated box never looks like a complete log.
/// </summary>
internal static class LogText
{
    /// <summary>Lines kept while a build is streaming progress.</summary>
    internal const int StreamLines = 800;

    /// <summary>Lines kept for a one-shot tool dump (PE info, audit verdict).</summary>
    internal const int DumpLines = 400;

    /// <summary>Character ceiling, so one pathological line cannot win.</summary>
    internal const int MaxChars = 120_000;

    /// <summary>
    /// Keep at most <paramref name="maxLines"/> trailing lines and
    /// <see cref="MaxChars"/> trailing characters of <paramref name="text"/>.
    /// Returns the input unchanged when it is already inside both limits.
    /// </summary>
    internal static string Tail(string? text, int maxLines)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;

        var kept = text;
        var droppedLines = 0;

        var lineCount = 1;
        foreach (var c in kept)
            if (c == '\n') lineCount++;

        if (maxLines > 0 && lineCount > maxLines)
        {
            var toSkip = lineCount - maxLines;
            var index = 0;
            var seen = 0;
            while (seen < toSkip && index < kept.Length)
            {
                if (kept[index] == '\n') seen++;
                index++;
            }
            droppedLines = seen;
            kept = kept[index..];
        }

        var droppedChars = 0;
        if (kept.Length > MaxChars)
        {
            droppedChars = kept.Length - MaxChars;
            kept = kept[^MaxChars..];
        }

        if (droppedLines == 0 && droppedChars == 0) return kept;

        // The omission notice is client chrome, so it follows the UI language. The
        // trimmed body below it is tool output and is left untouched.
        var note = new StringBuilder();
        note.Append(Localizer.T("… 已省略"));
        if (droppedLines > 0) note.Append(Localizer.F("较早的 {0} 行", droppedLines));
        if (droppedLines > 0 && droppedChars > 0) note.Append(Localizer.T("、"));
        if (droppedChars > 0) note.Append(Localizer.F("{0} 个字符", droppedChars));
        note.Append(Localizer.T("，仅保留最近内容 …\n"));

        return note.Append(kept).ToString();
    }
}
