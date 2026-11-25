using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace NovaProtect.UI.Services;

public sealed record ClientUpdateInfo(
    string ClientVersion,
    string WebsiteVersion,
    string FileName,
    long Size,
    string Sha256,
    Uri DownloadUri,
    string MinimumClientVersion,
    bool ForceUpdate,
    string ReleaseNotes,
    string? PublishedAt,
    bool IsNewer,
    bool IsRequired);

public sealed record ClientUpdateResult(ClientUpdateInfo? Update, string? Error);

/// <summary>
/// One row of the change log. Deliberately not <see cref="ClientUpdateInfo"/>:
/// older releases may lack an installer asset or a digest, and a change log
/// entry is still worth showing when the download is not.
/// </summary>
public sealed record ClientReleaseNote(
    string Version,
    string Title,
    string Notes,
    string? PublishedAt,
    bool Prerelease,
    string? PageUrl = null,
    string Label = "")
{
    /// <summary>
    /// The version as the change log shows it: <c>v3.2.5</c> for a plain tag and
    /// <c>v3.2.5-beta</c> when the tag carries a channel suffix. The bare
    /// <see cref="Version"/> stays numeric so it can still be compared with
    /// <see cref="Models.ProductInfo.Version"/> and used in file names.
    /// </summary>
    public string DisplayVersion => Label.Length == 0 ? $"v{Version}" : $"v{Version}-{Label}";
}

public sealed record ClientReleaseFeed(IReadOnlyList<ClientReleaseNote> Releases, string? Error);

public sealed record DownloadedUpdate(string FilePath, ClientUpdateInfo Update);

public sealed record UpdateDownloadResult(DownloadedUpdate? Download, string? Error);

/// <summary>
/// The website has no user accounts or memberships. This client only checks
/// the public release endpoint and downloads the published installer.
/// </summary>
public sealed class UpdateClient : IDisposable
{
    private const int MaxJsonResponseBytes = 256 * 1024;
    private const long MaxUpdateBytes = 1024L * 1024L * 1024L;
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan DownloadTimeout = TimeSpan.FromMinutes(10);
    private static readonly Lazy<UpdateClient> Lazy = new(() => new UpdateClient());
    private static readonly Regex VersionPattern = new(@"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    // Semver's pre-release identifier grammar, minus its leading separator. Dots
    // and dashes are allowed inside a label ("rc.1", "beta-hotfix.2"); '+', '_'
    // and whitespace are not, so a label can never be spliced into a file name or
    // a download URL as anything but a plain token.
    private static readonly Regex LabelPattern = new(@"^[0-9A-Za-z][0-9A-Za-z.\-]*$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    // PHP's default trim() character list, verbatim: space, tab, LF, CR, NUL and
    // vertical tab. Nothing else is stripped, and the website parser strips the
    // same set, so both readers agree on which tags are well formed.
    private static readonly char[] TagTrimChars = [' ', '\t', '\n', '\r', '\0', '\v'];
    private static readonly Regex InstallerPattern = new(@"^NovaProtect-Setup-(\d+\.\d+\.\d+)\.exe$", RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private readonly HttpClient _http;
    private readonly object _stateGate = new();
    private bool _updateRequired;

    public event EventHandler? StateChanged;

    private UpdateClient()
        : this(new Uri(Models.ProductInfo.GitHubApiBase, UriKind.Absolute))
    {
    }

    // Tests compile this same source and can target a loopback website or inject
    // transport faults. The application only uses Shared and its fixed HTTPS URL.
    internal UpdateClient(Uri baseAddress, HttpMessageHandler? handler = null)
    {
        if (!baseAddress.IsAbsoluteUri || (!string.Equals(baseAddress.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) && !baseAddress.IsLoopback))
            throw new ArgumentException("更新服务地址必须是 HTTPS，测试时允许回环地址。", nameof(baseAddress));

        _http = new HttpClient(handler ?? new HttpClientHandler
        {
            UseCookies = false,
            // GitHub answers asset downloads with a 302 to its object host, so
            // redirects are followed manually and every hop is host-checked.
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.All
        })
        {
            BaseAddress = baseAddress,
            // An explicit CTS below covers headers and streamed response bodies.
            Timeout = Timeout.InfiniteTimeSpan
        };
        _http.DefaultRequestHeaders.UserAgent.ParseAdd($"NovaProtect/{Models.ProductInfo.Version}");
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        _http.DefaultRequestHeaders.CacheControl = new CacheControlHeaderValue { NoCache = true, NoStore = true };
    }

    public static UpdateClient Shared => Lazy.Value;

    public bool IsUpdateRequired
    {
        get { lock (_stateGate) return _updateRequired; }
    }

    public void SetUpdateRequired(bool required)
    {
        var changed = false;
        lock (_stateGate)
        {
            changed = _updateRequired != required;
            _updateRequired = required;
        }
        if (changed) StateChanged?.Invoke(this, EventArgs.Empty);
    }

    public async Task<ClientUpdateResult> CheckForUpdateAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CreateTimeout(cancellationToken, RequestTimeout);
            var releasePath = $"repos/{Models.ProductInfo.GitHubRepository}/releases/latest";
            using var request = new HttpRequestMessage(HttpMethod.Get, releasePath);
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (!response.IsSuccessStatusCode)
            {
                if (response.StatusCode == HttpStatusCode.NotFound)
                    return new ClientUpdateResult(null, "GitHub 上还没有已发布的客户端版本。");
                var problem = await ReadProblemAsync(response, timeout.Token);
                return new ClientUpdateResult(null, problem.Message ?? EdgeResponseMessage(response) ?? "当前版本暂时无法读取。");
            }

            var root = await ReadJsonObjectAsync(response, timeout.Token);
            ClientUpdateInfo? update = null;
            string? error = null;
            if (root is null || !TryParseUpdate(root.Value, out update, out error))
                return new ClientUpdateResult(null, error ?? "GitHub 返回了无法识别的更新信息。");
            SetUpdateRequired(update!.IsRequired);
            return new ClientUpdateResult(update, null);
        }
        catch (Exception ex) when (IsTransient(ex))
        {
            return new ClientUpdateResult(null, "GitHub 暂时无法连接。");
        }
    }

    /// <summary>
    /// Read the published release list for the change log.
    ///
    /// This is a separate request from <see cref="CheckForUpdateAsync"/> on
    /// purpose: that one only wants the newest release and refuses to continue
    /// without an installer asset, while a change log should still list a release
    /// that shipped without one. Failures are reported, never thrown, so the page
    /// can fall back to its baked-in copy.
    /// </summary>
    public async Task<ClientReleaseFeed> ListReleasesAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CreateTimeout(cancellationToken, RequestTimeout);
            var path = $"repos/{Models.ProductInfo.GitHubRepository}/releases?per_page=30";
            using var request = new HttpRequestMessage(HttpMethod.Get, path);
            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (!response.IsSuccessStatusCode)
            {
                if (response.StatusCode == HttpStatusCode.NotFound)
                    return new ClientReleaseFeed([], "GitHub 上还没有已发布的版本。");
                var problem = await ReadProblemAsync(response, timeout.Token);
                return new ClientReleaseFeed([], problem.Message ?? EdgeResponseMessage(response) ?? "暂时无法读取发布历史。");
            }

            var array = await ReadJsonArrayAsync(response, timeout.Token);
            if (array is null) return new ClientReleaseFeed([], "GitHub 返回了无法识别的发布历史。");

            var notes = new List<ClientReleaseNote>();
            foreach (var element in array.Value.EnumerateArray())
            {
                if (element.ValueKind != JsonValueKind.Object) continue;
                // Drafts are invisible to everyone but the owner; showing them
                // would advertise a version nobody can download.
                if (element.TryGetProperty("draft", out var draft) && draft.ValueKind == JsonValueKind.True) continue;

                // No Trim() here: the parser owns the trim set (see TagTrimChars).
                // Trimming at the call site would use the parameterless Trim() and
                // quietly accept a tag the website refuses.
                var tag = ReadString(element, "tag_name");
                // A suffixed tag such as 3.2.5-beta is a real, published version:
                // dropping it would cut the change log off at the previous plain
                // tag and hide the release that is actually downloadable.
                if (!TryParseTag(tag, out var parsedTag)) continue;
                var version = parsedTag.Version;

                var body = ReadString(element, "body") ?? string.Empty;
                if (body.Length > 12000) body = body[..12000] + "\n…";
                var published = ReadString(element, "published_at");
                var title = ReadString(element, "name")?.Trim();
                var githubPrerelease = element.TryGetProperty("prerelease", out var pre) && pre.ValueKind == JsonValueKind.True;

                notes.Add(new ClientReleaseNote(
                    version,
                    string.IsNullOrWhiteSpace(title) ? $"NovaProtect {version}" : title,
                    string.IsNullOrWhiteSpace(body) ? "本次版本没有填写更新说明。" : body,
                    published,
                    // Either signal marks a pre-release: the channel label in the
                    // tag, or GitHub's own flag when the owner set it by hand.
                    parsedTag.Label.Length > 0 || githubPrerelease,
                    ReadString(element, "html_url"),
                    parsedTag.Label));
            }

            if (notes.Count == 0) return new ClientReleaseFeed([], "GitHub 上没有可显示的发布记录。");
            return new ClientReleaseFeed(notes, null);
        }
        catch (Exception ex) when (IsTransient(ex))
        {
            return new ClientReleaseFeed([], "GitHub 暂时无法连接。");
        }
    }

    public async Task<UpdateDownloadResult> DownloadUpdateAsync(
        ClientUpdateInfo update, IProgress<long>? progress = null, CancellationToken cancellationToken = default)
    {
        if (!TryValidateUpdate(update, _http.BaseAddress!, out var error)) return new UpdateDownloadResult(null, error);

        string? temporaryDirectory = null;
        try
        {
            using var timeout = CreateTimeout(cancellationToken, DownloadTimeout);
            using var response = await SendFollowingRedirectsAsync(update.DownloadUri, timeout.Token);
            if (response is null) return new UpdateDownloadResult(null, "更新文件地址不属于 GitHub 发布源。");
            if (response.StatusCode != HttpStatusCode.OK)
            {
                var problem = await ReadProblemAsync(response, timeout.Token);
                return new UpdateDownloadResult(null, problem.Message ?? EdgeResponseMessage(response) ?? "更新文件暂时无法下载。");
            }
            if (response.Content.Headers.ContentLength is long length && length != update.Size)
                return new UpdateDownloadResult(null, "更新文件大小与发布信息不一致。");

            temporaryDirectory = Path.Combine(Path.GetTempPath(), "NovaProtect", "updates", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(temporaryDirectory);
            var path = Path.Combine(temporaryDirectory, update.FileName);
            await using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1024 * 64, FileOptions.Asynchronous | FileOptions.SequentialScan);
            await using var stream = await response.Content.ReadAsStreamAsync(timeout.Token);
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = new byte[1024 * 1024];
            long total = 0;
            while (true)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(), timeout.Token);
                if (read == 0) break;
                total += read;
                if (total > update.Size || total > MaxUpdateBytes) throw new InvalidDataException("更新文件超过声明大小。");
                hash.AppendData(buffer, 0, read);
                await file.WriteAsync(buffer.AsMemory(0, read), timeout.Token);
                progress?.Report(total);
            }

            if (total != update.Size) throw new InvalidDataException("更新文件下载不完整。");
            var actual = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
            if (!CryptographicOperations.FixedTimeEquals(Convert.FromHexString(actual), Convert.FromHexString(update.Sha256)))
                throw new InvalidDataException("更新文件 SHA-256 校验失败。");

            return new UpdateDownloadResult(new DownloadedUpdate(path, update), null);
        }
        catch (Exception ex) when (IsTransient(ex) || ex is InvalidDataException or IOException or UnauthorizedAccessException)
        {
            if (temporaryDirectory is not null) TryDeleteDirectory(temporaryDirectory);
            return new UpdateDownloadResult(null, ex is OperationCanceledException ? "更新下载已取消。" : ex.Message);
        }
    }

    /// <summary>
    /// Follow GitHub's asset redirect chain, re-checking the host on every hop.
    /// github.com answers with a 302 to objects.githubusercontent.com; anything
    /// pointing outside those hosts is treated as a tampered download.
    /// </summary>
    private async Task<HttpResponseMessage?> SendFollowingRedirectsAsync(Uri uri, CancellationToken cancellationToken)
    {
        var current = uri;
        for (var hop = 0; hop < 5; hop++)
        {
            if (!IsAllowedDownloadUri(current)) return null;
            using var request = new HttpRequestMessage(HttpMethod.Get, current);
            var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if ((int)response.StatusCode is not (301 or 302 or 303 or 307 or 308)) return response;
            var location = response.Headers.Location;
            response.Dispose();
            if (location is null) return null;
            current = location.IsAbsoluteUri ? location : new Uri(current, location);
        }
        return null;
    }

    private static bool IsAllowedDownloadUri(Uri uri)
    {
        if (!uri.IsAbsoluteUri || !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)) return false;
        if (uri.IsLoopback) return true;
        return string.Equals(uri.Host, Models.ProductInfo.GitHubDownloadHost, StringComparison.OrdinalIgnoreCase)
            || string.Equals(uri.Host, Models.ProductInfo.GitHubObjectHost, StringComparison.OrdinalIgnoreCase)
            || uri.Host.EndsWith(".githubusercontent.com", StringComparison.OrdinalIgnoreCase);
    }

    private async Task<(string? Message, string? Code)> ReadProblemAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var root = await ReadJsonObjectAsync(response, cancellationToken);
        if (root is null) return (null, null);
        return (ReadString(root.Value, "detail") ?? ReadString(root.Value, "title"), ReadString(root.Value, "code"));
    }

    private static string? EdgeResponseMessage(HttpResponseMessage response)
    {
        if ((int)response.StatusCode == 444)
            return "CDNfly 边缘防护拦截了请求（444）。请对 /api/ 和 /download 配置最高优先级放行并关闭 JS/CC 验证。";

        var mediaType = response.Content.Headers.ContentType?.MediaType;
        if (response.IsSuccessStatusCode && string.Equals(mediaType, "text/html", StringComparison.OrdinalIgnoreCase))
            return "CDNfly 返回了人机验证页面，更新接口尚未放行。请对 /api/ 配置旁路验证。";

        return null;
    }

    private static async Task<JsonElement?> ReadJsonObjectAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var root = await ReadJsonAsync(response, cancellationToken, '{');
        return root;
    }

    private static async Task<JsonElement?> ReadJsonArrayAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var root = await ReadJsonAsync(response, cancellationToken, '[');
        return root;
    }

    /// <summary>
    /// Shared JSON body reader. <paramref name="expectedFirstByte"/> distinguishes
    /// an object endpoint from an array endpoint: a proxy that answers 200 with an
    /// HTML page must not be parsed as either.
    /// </summary>
    private static async Task<JsonElement?> ReadJsonAsync(
        HttpResponseMessage response, CancellationToken cancellationToken, char expectedFirstByte)
    {
        var mediaType = response.Content.Headers.ContentType?.MediaType;
        if (response.Content.Headers.ContentLength > MaxJsonResponseBytes) return null;

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        int read;
        while ((read = await stream.ReadAsync(chunk.AsMemory(), cancellationToken)) > 0)
        {
            if (buffer.Length + read > MaxJsonResponseBytes) return null;
            buffer.Write(chunk, 0, read);
        }

        try
        {
            var bytes = buffer.GetBuffer().AsMemory(0, checked((int)buffer.Length));
            if (bytes.Span.StartsWith(new byte[] { 0xEF, 0xBB, 0xBF })) bytes = bytes[3..];
            var isJsonMediaType = mediaType is not null && (mediaType.Equals("application/json", StringComparison.OrdinalIgnoreCase) || mediaType.EndsWith("+json", StringComparison.OrdinalIgnoreCase));
            var expected = (byte) expectedFirstByte;
            var first = (byte) 0;
            foreach (var value in bytes.Span)
            {
                if (!char.IsWhiteSpace((char) value)) { first = value; break; }
            }
            if (!isJsonMediaType && first != expected) return null;
            using var document = JsonDocument.Parse(bytes);
            var kind = expected == (byte) '[' ? JsonValueKind.Array : JsonValueKind.Object;
            return document.RootElement.ValueKind == kind ? document.RootElement.Clone() : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    /// <summary>
    /// Split a GitHub <c>tag_name</c> into the numeric version and the channel
    /// label.
    ///
    /// The updater used to require a bare three-part number, which meant every
    /// suffixed tag was treated as "not a version" and the whole release was
    /// dropped: <c>3.2.5-beta</c> disappeared from the change log and
    /// <c>/releases/latest</c> answered with the "发布标签不是三段式版本号"
    /// error, so no client was ever offered it. A <c>-beta</c> suffix must not be
    /// silently stripped either — <c>3.2.5</c> and <c>3.2.5-beta</c> are distinct
    /// releases, and losing the label would show a beta build as the plain
    /// version in the change log. So both parts are parsed and kept, and the
    /// label is surfaced (<see cref="ClientReleaseNote.Label"/>) rather than
    /// folded into the number every consumer compares and builds paths from.
    ///
    /// Order of operations matters and follows the tag contract exactly: trim,
    /// one leading <c>v</c>/<c>V</c>, drop the <c>+build</c> metadata tail, split
    /// at the first <c>-</c>, then validate the core and the label separately.
    /// </summary>
    private static bool TryParseTag(string? tag, out (string Version, string Label) parsed)
    {
        parsed = default;
        if (tag is null) return false;
        // Trim exactly the ASCII whitespace set the website parser trims. The
        // parameterless Trim() would also strip Unicode whitespace (a trailing
        // NBSP, an ideographic space), so a tag carrying one would be accepted
        // here and refused by the site — the two readers must draw the line in
        // the same place, and a tag with stray non-ASCII whitespace is malformed
        // either way.
        var value = tag.Trim(TagTrimChars);
        if (value.Length == 0) return false;
        if (value[0] is 'v' or 'V') value = value[1..];

        // Semver build metadata is informational only; no consumer of a version
        // number compares or sorts on it, and it is not part of any asset name.
        var plus = value.IndexOf('+');
        if (plus >= 0) value = value[..plus];

        // Only the first '-' separates the channel: "rc.1-x" stays one label. A
        // dash with nothing behind it ("3.2.5-") is rejected rather than read as
        // an empty label, because the two spellings would otherwise name the same
        // version while sorting and displaying differently.
        var label = string.Empty;
        var dash = value.IndexOf('-');
        if (dash >= 0)
        {
            label = value[(dash + 1)..];
            value = value[..dash];
            if (label.Length == 0) return false;
        }

        if (!VersionPattern.IsMatch(value)) return false;
        if (label.Length > 0 && !LabelPattern.IsMatch(label)) return false;
        parsed = (value, label);
        return true;
    }

    /// <summary>
    /// Parse a GitHub release object into update metadata.
    ///
    /// GitHub carries no "minimum client version" and no separate website
    /// version, so the release tag is authoritative for both, and integrity is
    /// taken from the asset's sha256 digest (or a SHA256SUMS asset) rather than
    /// from a field this server used to generate.
    /// </summary>
    private static bool TryParseUpdate(JsonElement root, out ClientUpdateInfo? update, out string? error)
    {
        update = null;
        error = null;
        if (root.TryGetProperty("draft", out var draft) && draft.ValueKind == JsonValueKind.True)
        { error = "该版本尚未发布。"; return false; }

        // No Trim() here either: TryParseTag trims exactly the characters the
        // website trims, so the two readers cannot disagree about a stray NBSP.
        var tag = ReadString(root, "tag_name");
        if (tag is null) { error = "更新信息字段不完整。"; return false; }
        // The channel label ("beta", "rc.1") is deliberately not carried into
        // clientVersion: the number is what gets compared, matched against the
        // installer name and written into file paths, and a "-beta" suffix in any
        // of those places would break comparison and asset matching. The tag is
        // still validated in full, so a malformed one is still refused.
        if (!TryParseTag(tag, out var parsedTag)) { error = "发布标签不是三段式版本号。"; return false; }
        var clientVersion = parsedTag.Version;

        var releaseNotes = ReadString(root, "body") ?? string.Empty;
        var publishedAt = ReadString(root, "published_at");
        if (releaseNotes.Length > 12000 || publishedAt?.Length > 128) { error = "更新信息格式无效。"; return false; }

        if (!root.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array)
        { error = "该版本没有附带安装包。"; return false; }

        var expectedName = $"NovaProtect-Setup-{clientVersion}.exe";
        string? fileName = null;
        string? downloadUrl = null;
        string? digest = null;
        long size = 0;
        string? checksumsUrl = null;
        foreach (var asset in assets.EnumerateArray())
        {
            if (asset.ValueKind != JsonValueKind.Object) continue;
            var name = ReadString(asset, "name");
            if (string.IsNullOrEmpty(name)) continue;
            if (string.Equals(name, "SHA256SUMS", StringComparison.OrdinalIgnoreCase))
                checksumsUrl ??= ReadString(asset, "browser_download_url");
            if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
            var url = ReadString(asset, "browser_download_url");
            if (url is null) continue;
            if (fileName is null || string.Equals(name, expectedName, StringComparison.OrdinalIgnoreCase))
            {
                fileName = name;
                downloadUrl = url;
                digest = ReadString(asset, "digest");
                size = asset.TryGetProperty("size", out var sizeValue) && sizeValue.TryGetInt64(out var parsed) ? parsed : 0;
                if (string.Equals(name, expectedName, StringComparison.OrdinalIgnoreCase)) break;
            }
        }
        if (fileName is null || downloadUrl is null) { error = "该版本没有附带安装包。"; return false; }

        var sha256 = NormalizeDigest(digest);
        if (sha256 is null)
        {
            error = "该版本未提供 SHA-256 摘要，无法校验安装包。";
            return false;
        }
        if (size < 1 || size > MaxUpdateBytes) { error = "安装包大小无效。"; return false; }
        if (!Uri.TryCreate(downloadUrl, UriKind.Absolute, out var downloadUri) || !IsAllowedDownloadUri(downloadUri))
        { error = "更新下载地址不属于 GitHub 发布源。"; return false; }

        if (!Version.TryParse(clientVersion, out var remote) || !Version.TryParse(Models.ProductInfo.Version, out var current))
        { error = "当前版本号无效。"; return false; }

        var isNewer = remote > current;
        var minimumClientVersion = clientVersion;
        update = new ClientUpdateInfo(clientVersion, clientVersion, fileName, size, sha256, downloadUri,
            minimumClientVersion, false, releaseNotes, publishedAt, isNewer, false);
        return true;
    }

    /// <summary>GitHub reports "sha256:&lt;64 hex&gt;"; anything else is unusable.</summary>
    private static string? NormalizeDigest(string? digest)
    {
        if (string.IsNullOrEmpty(digest)) return null;
        var value = digest.Contains(':') ? digest[(digest.IndexOf(':') + 1)..] : digest;
        value = value.Trim().ToLowerInvariant();
        return Regex.IsMatch(value, "^[a-f0-9]{64}$", RegexOptions.CultureInvariant) ? value : null;
    }

    private static bool TryValidateUpdate(ClientUpdateInfo update, Uri baseAddress, out string? error)
    {
        error = null;
        var fileMatch = InstallerPattern.Match(update.FileName);
        if (!VersionPattern.IsMatch(update.ClientVersion) || !VersionPattern.IsMatch(update.MinimumClientVersion) || !fileMatch.Success || !string.Equals(fileMatch.Groups[1].Value, update.ClientVersion, StringComparison.Ordinal) ||
            !Regex.IsMatch(update.Sha256, "^[a-f0-9]{64}$", RegexOptions.CultureInvariant) || update.Size < 1 || update.Size > MaxUpdateBytes ||
            update.ReleaseNotes.Length > 12000 || update.PublishedAt?.Length > 128 ||
            !update.DownloadUri.IsAbsoluteUri || !IsAllowedDownloadUri(update.DownloadUri))
        { error = "更新信息校验失败。"; return false; }
        if (!Version.TryParse(update.ClientVersion, out var remote) || !Version.TryParse(update.MinimumClientVersion, out var minimum) || minimum > remote)
        { error = "更新版本策略无效。"; return false; }
        return true;
    }

    private static string? ReadString(JsonElement root, string name) => root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    private static bool IsTransient(Exception exception) => exception is HttpRequestException or OperationCanceledException or IOException;
    private static CancellationTokenSource CreateTimeout(CancellationToken cancellationToken, TimeSpan duration) { var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken); timeout.CancelAfter(duration); return timeout; }
    private static void TryDeleteDirectory(string directory) { try { if (Directory.Exists(directory)) Directory.Delete(directory, true); } catch { /* cleanup best-effort */ } }

    public void Dispose() => _http.Dispose();
}
