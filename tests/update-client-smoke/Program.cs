using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NovaProtect.UI.Models;
using NovaProtect.UI.Services;

var passed = 0;
void Check(bool value, string name)
{
    if (!value) throw new InvalidOperationException("FAIL: " + name);
    Console.WriteLine("[ OK ] " + name);
    passed++;
}

HttpResponseMessage Response(string body, string mediaType = "application/json", HttpStatusCode status = HttpStatusCode.OK) =>
    new(status) { Content = new StringContent(body, Encoding.UTF8, mediaType) };

HttpResponseMessage Binary(byte[] content, HttpStatusCode status = HttpStatusCode.OK) =>
    new(status)
    {
        Content = new ByteArrayContent(content)
        {
            Headers = { ContentType = new MediaTypeHeaderValue("application/vnd.microsoft.portable-executable") }
        }
    };

HttpResponseMessage Redirect(Uri location) =>
    new(HttpStatusCode.Found) { Headers = { Location = location } };

var endpoint = new Uri(ProductInfo.GitHubApiBase);
var current = ProductInfo.Version;
// The forced-update fixture must stay strictly newer than the shipping client
// or the "IsNewer" assertion silently rots at every version bump.
var forcedVersion = new Version(Version.Parse(current).Major, Version.Parse(current).Minor, Version.Parse(current).Build + 1).ToString(3);
var fixtureHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("novaprotect-update-fixture"))).ToLowerInvariant();

string AssetJson(string name, long size, string? digest, string url, string? extra = null) =>
    JsonSerializer.Serialize(new
    {
        name,
        size,
        digest,
        browser_download_url = url,
        content_type = "application/octet-stream"
    });

// GitHub release object: version comes from the tag, notes from body, integrity
// from the asset digest. The tag can be overridden so a fixture can keep an
// installer asset named after the plain version while the tag carries a channel
// suffix ("v3.2.5-beta" publishing "NovaProtect-Setup-3.2.5.exe"), which is
// exactly how the real 3.2.5 BETA release is published.
string ReleaseJson(string version, string assetName, long size, string? digest, string url,
    bool draft = false, bool prerelease = false, string? body = null, string? extraAssets = null,
    string? tagName = null, string? name = null, string? publishedAt = null) =>
    "{" +
    $"\"tag_name\":{JsonSerializer.Serialize(tagName ?? $"v{version}")}," +
    $"\"name\":{JsonSerializer.Serialize(name ?? version)}," +
    "\"html_url\":\"https://github.com/o/r/releases\"," +
    $"\"draft\":{(draft ? "true" : "false")}," +
    $"\"prerelease\":{(prerelease ? "true" : "false")}," +
    $"\"published_at\":\"{publishedAt ?? "2026-10-18T00:00:00Z"}\"," +
    $"\"body\":{JsonSerializer.Serialize(body ?? "Smoke fixture release.")}," +
    "\"assets\":[" + AssetJson(assetName, size, digest, url) + (extraAssets is null ? "" : "," + extraAssets) + "]" +
    "}";

var installerUrl = $"https://github.com/o/r/releases/download/v{current}/NovaProtect-Setup-{current}.exe";
var payload = ReleaseJson(current, $"NovaProtect-Setup-{current}.exe", 4096, "sha256:" + fixtureHash, installerUrl);

using (var client = new UpdateClient(endpoint, new FakeHandler((request, _) =>
{
    Check(request.RequestUri!.AbsoluteUri.Contains("/repos/", StringComparison.Ordinal) &&
          request.RequestUri.AbsoluteUri.EndsWith("/releases/latest", StringComparison.Ordinal), "update check targets the GitHub releases API");
    Check(request.Headers.Accept.Any(value => value.MediaType == "application/vnd.github+json"), "GitHub media type is requested");
    Check(request.Headers.CacheControl is { NoStore: true, NoCache: true }, "client requests bypass cache");
    return Task.FromResult(Response(payload));
})))
{
    var result = await client.CheckForUpdateAsync();
    Check(result.Error is null && result.Update is not null, "typed current-version update metadata");
    Check(result.Update!.ClientVersion == current && !result.Update.IsNewer && !result.Update.IsRequired, "same version is not offered as an update (downgrade gate)");
    Check(result.Update.ReleaseNotes == "Smoke fixture release." && result.Update.Size == 4096, "release metadata is parsed");
    Check(result.Update.Sha256 == fixtureHash, "asset digest becomes the expected SHA-256");
    Check(result.Update.FileName == $"NovaProtect-Setup-{current}.exe", "installer name is taken from the asset");
}

using (var client = new UpdateClient(endpoint, new FakeHandler((_, _) => Task.FromResult(Response(
    ReleaseJson(forcedVersion, $"NovaProtect-Setup-{forcedVersion}.exe", 8192, "sha256:" + fixtureHash,
        $"https://github.com/o/r/releases/download/v{forcedVersion}/NovaProtect-Setup-{forcedVersion}.exe"))))))
{
    var result = await client.CheckForUpdateAsync();
    Check(result.Error is null && result.Update is { IsNewer: true }, "newer release is offered as an update");
    Check(result.Update is { ForceUpdate: false, IsRequired: false }, "GitHub carries no force-update policy, so nothing is forced");
}

// A channel-suffixed tag is still a version: /releases/latest answering
// "3.2.5-beta" must produce update metadata, with the number alone used for
// comparison, asset matching and the client version.
const string betaAsset = "NovaProtect-Setup-3.2.5.exe";
const string betaTag = "v3.2.5-beta";
using (var client = new UpdateClient(endpoint, new FakeHandler((_, _) => Task.FromResult(Response(
    ReleaseJson("3.2.5", betaAsset, 61616158, "sha256:" + fixtureHash.ToUpperInvariant(),
        "https://github.com/o/r/releases/download/v3.2.5-beta/" + betaAsset, tagName: betaTag))))))
{
    var result = await client.CheckForUpdateAsync();
    Check(result.Error is null && result.Update is not null, "suffixed tag parses as an update");
    Check(result.Update!.ClientVersion == "3.2.5", "suffixed tag yields the numeric core as the client version");
    Check(result.Update.FileName == betaAsset, "suffixed tag still matches the plain installer asset name");
    Check(result.Update.Sha256 == fixtureHash, "digest is normalized to 64 lowercase hex digits");
    Check(result.Update.IsNewer == (Version.Parse("3.2.5") > Version.Parse(ProductInfo.Version)),
        "suffixed tag compares on the numeric core only");
}

// The real 3.2.5 BETA release, field for field. A -beta tag of the version that
// is already running is not an update, so clients on 3.2.5 are not re-offered it.
const string realDigest = "cb3023baf5bed9df3058ab6d702931a5b317abb53888b0c45ca6e8c83424bdee";
const long realSize = 61616158;
using (var client = new UpdateClient(endpoint, new FakeHandler((_, _) => Task.FromResult(Response(
    ReleaseJson("3.2.5", betaAsset, realSize, "sha256:" + realDigest,
        "https://github.com/o/r/releases/download/v3.2.5-beta/" + betaAsset,
        tagName: "3.2.5-beta", name: "3.2.5-beta", publishedAt: "2026-11-23T14:05:09Z",
        body: "3.2.5 BETA — 2026-11-23（客户端界面中英文切换）"))))))
{
    var result = await client.CheckForUpdateAsync();
    Check(result.Error is null && result.Update is not null, "real 3.2.5-beta release is accepted");
    Check(result.Update!.ClientVersion == "3.2.5", "real release version is the numeric core");
    Check(result.Update.FileName == betaAsset && result.Update.Size == realSize, "real release asset name and size match");
    Check(result.Update.Sha256 == realDigest, "real release digest normalizes to the published hash");
    Check(result.Update.PublishedAt == "2026-11-23T14:05:09Z", "real release timestamp is carried");
    Check(result.Update.IsNewer == false, "a -beta tag of the running version is not an update");
}

// Surrounding ASCII whitespace is noise: the client strips the same six
// characters PHP's trim() strips, so a padded tag still resolves.
using (var client = new UpdateClient(endpoint, new FakeHandler((_, _) => Task.FromResult(Response(
    ReleaseJson("3.2.5", betaAsset, 4096, "sha256:" + fixtureHash, installerUrl, tagName: "3.2.5\v"))))))
{
    var result = await client.CheckForUpdateAsync();
    Check(result.Error is null && result.Update?.ClientVersion == "3.2.5", "surrounding ASCII whitespace in a tag is trimmed");
}

var invalid = new (string Name, string Body, HttpStatusCode Status)[]
{
    ("CDN HTML 200", "<html>Guard</html>", HttpStatusCode.OK),
    ("upstream HTML 502", "<html>Unavailable</html>", HttpStatusCode.BadGateway),
    ("redirect 302", "", HttpStatusCode.Found),
    ("invalid JSON", "{broken", HttpStatusCode.OK),
    ("array root", "[]", HttpStatusCode.OK),
    ("null root", "null", HttpStatusCode.OK),
    ("string root", "\"invalid\"", HttpStatusCode.OK),
    ("empty object", "{}", HttpStatusCode.OK),
    ("draft release", ReleaseJson(current, $"NovaProtect-Setup-{current}.exe", 1, "sha256:" + fixtureHash, installerUrl, draft: true), HttpStatusCode.OK),
    ("non-semver tag", ReleaseJson(current, $"NovaProtect-Setup-{current}.exe", 1, "sha256:" + fixtureHash, installerUrl).Replace($"v{current}", "nightly"), HttpStatusCode.OK),
    // Malformed tags must be refused even though the rest of the object is valid:
    // the channel suffix grammar is fixed, and a wrong label can never become a
    // version or reach a file name.
    ("unprefixed label tag", ReleaseJson("3.2.5", betaAsset, 4096, "sha256:" + fixtureHash, installerUrl, tagName: "nightly"), HttpStatusCode.OK),
    ("four-part tag", ReleaseJson("3.2.5", betaAsset, 4096, "sha256:" + fixtureHash, installerUrl, tagName: "3.2.5.1"), HttpStatusCode.OK),
    ("empty channel label", ReleaseJson("3.2.5", betaAsset, 4096, "sha256:" + fixtureHash, installerUrl, tagName: "3.2.5-"), HttpStatusCode.OK),
    ("illegal label character", ReleaseJson("3.2.5", betaAsset, 4096, "sha256:" + fixtureHash, installerUrl, tagName: "3.2.5-beta!"), HttpStatusCode.OK),
    ("label before the number", ReleaseJson("3.2.5", betaAsset, 4096, "sha256:" + fixtureHash, installerUrl, tagName: "release-3.2.5"), HttpStatusCode.OK),
    // The client trims exactly PHP's six trim() characters, so non-ASCII
    // whitespace is part of the tag and makes it malformed. Both readers must
    // refuse the same tags, or one of them silently loses a release.
    ("non-ASCII whitespace in tag", ReleaseJson("3.2.5", betaAsset, 4096, "sha256:" + fixtureHash, installerUrl, tagName: "3.2.5\u00A0"), HttpStatusCode.OK),
    ("form feed in tag", ReleaseJson("3.2.5", betaAsset, 4096, "sha256:" + fixtureHash, installerUrl, tagName: "3.2.5\f"), HttpStatusCode.OK),
    ("no assets array", "{\"tag_name\":\"v" + current + "\"}", HttpStatusCode.OK),
    ("no installer asset", "{\"tag_name\":\"v" + current + "\",\"assets\":[" + AssetJson("notes.txt", 5, null, "https://github.com/o/r/notes.txt") + "]}", HttpStatusCode.OK),
    ("missing digest", ReleaseJson(current, $"NovaProtect-Setup-{current}.exe", 4096, null, installerUrl), HttpStatusCode.OK),
    ("malformed digest", ReleaseJson(current, $"NovaProtect-Setup-{current}.exe", 4096, "sha256:notahash", installerUrl), HttpStatusCode.OK),
    ("bad size", ReleaseJson(current, $"NovaProtect-Setup-{current}.exe", 0, "sha256:" + fixtureHash, installerUrl), HttpStatusCode.OK),
    ("foreign download host", ReleaseJson(current, $"NovaProtect-Setup-{current}.exe", 4096, "sha256:" + fixtureHash, "https://evil.example/setup.exe"), HttpStatusCode.OK),
    ("oversized release notes", ReleaseJson(current, $"NovaProtect-Setup-{current}.exe", 4096, "sha256:" + fixtureHash, installerUrl, body: new string('x', 13000)), HttpStatusCode.OK),
    ("known oversized body", new string(' ', 300000) + payload, HttpStatusCode.OK)
};

foreach (var item in invalid)
{
    using var client = new UpdateClient(endpoint, new FakeHandler((_, _) => Task.FromResult(Response(item.Body, "application/json", item.Status))));
    var result = await client.CheckForUpdateAsync();
    Check(result.Update is null && result.Error is not null, item.Name + " fails safely");
}

// The change log feed. GitHub lists releases newest first; the client must keep
// that order, keep suffixed tags, and skip only what it cannot represent.
var feedUrl = "https://github.com/o/r/releases";
var feedPayload = "[" + string.Join(",",
    ReleaseJson("3.2.5", betaAsset, realSize, "sha256:" + realDigest,
        $"https://github.com/o/r/releases/download/v3.2.5-beta/{betaAsset}",
        tagName: "3.2.5-beta", name: "3.2.5-beta", publishedAt: "2026-11-23T14:05:09Z", prerelease: false,
        body: "3.2.5 BETA — 2026-11-23（客户端界面中英文切换）"),
    ReleaseJson("3.1.6", $"NovaProtect-Setup-3.1.6.exe", 4096, "sha256:" + fixtureHash,
        "https://github.com/o/r/releases/download/v3.1.6/NovaProtect-Setup-3.1.6.exe"),
    // A draft is visible only to the repository owner and nobody can download it.
    ReleaseJson("3.2.6", betaAsset, 4096, "sha256:" + fixtureHash, feedUrl, draft: true),
    // Not a version at all.
    ReleaseJson("3.2.5", betaAsset, 4096, "sha256:" + fixtureHash, feedUrl, tagName: "nightly"),
    // No installer: worth listing in a change log, never offered for download.
    ReleaseJson("3.1.4", "notes.txt", 5, null, "https://github.com/o/r/notes.txt")
) + "]";

using (var client = new UpdateClient(endpoint, new FakeHandler((request, _) =>
{
    Check(request.RequestUri!.AbsoluteUri.EndsWith("/releases?per_page=30", StringComparison.Ordinal), "release feed targets the GitHub releases list");
    return Task.FromResult(Response(feedPayload));
})))
{
    var feed = await client.ListReleasesAsync();
    Check(feed.Error is null && feed.Releases.Count == 3, "release feed keeps the representable releases and drops the rest");
    var head = feed.Releases[0];
    Check(head.Version == "3.2.5", "suffixed tag is listed under its numeric version");
    Check(head.Label == "beta", "suffixed tag carries its channel label");
    Check(head.DisplayVersion == "v3.2.5-beta", "change log shows the channel suffix");
    Check(head.Prerelease, "a -beta tag is a pre-release without GitHub's flag");
    Check(head.Title == "3.2.5-beta" && head.Notes.Contains("客户端界面中英文切换", StringComparison.Ordinal), "suffixed release keeps its name and notes");
    Check(head.PageUrl == feedUrl && head.PublishedAt == "2026-11-23T14:05:09Z", "html_url and timestamp are carried through");
    Check(feed.Releases[1] is { Version: "3.1.6", Label: "", Prerelease: false, DisplayVersion: "v3.1.6" }, "plain tag stays plain");
    Check(feed.Releases[2].Version == "3.1.4", "a release without an installer asset is still listed");
    Check(feed.Releases.All(note => note.Version != "3.2.6"), "draft releases are skipped");
    Check(feed.Releases.All(note => note.Version != "3.2.5" || note.Label == "beta"), "non-semver tags are skipped");
}

foreach (var (name, response) in new (string Name, Func<HttpResponseMessage> Response)[]
{
    ("empty release history", () => Response("{\"message\":\"Not Found\"}", "application/json", HttpStatusCode.NotFound)),
    ("release feed HTML 200", () => Response("<html>Guard</html>", "text/html"))
})
{
    using var client = new UpdateClient(endpoint, new FakeHandler((_, _) => Task.FromResult(response())));
    var feed = await client.ListReleasesAsync();
    Check(feed.Error is not null && feed.Releases.Count == 0, name + " is reported as an error");
}

using (var client = new UpdateClient(endpoint, new FakeHandler((_, _) => Task.FromResult(Response("{\"message\":\"Not Found\"}", "application/json", HttpStatusCode.NotFound)))))
{
    var result = await client.CheckForUpdateAsync();
    Check(result.Error is not null && result.Error.Contains("还没有已发布", StringComparison.Ordinal), "empty repository is explained");
}

using (var client = new UpdateClient(endpoint, new FakeHandler((_, _) => Task.FromResult(Response("{\"title\":42,\"detail\":[]}", "application/problem+json", HttpStatusCode.Unauthorized)))))
{
    Check((await client.CheckForUpdateAsync()).Error is not null, "wrong problem field types do not throw");
}

using (var client = new UpdateClient(endpoint, new FakeHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
{
    Content = new StreamContent(new NonSeekableStream(new MemoryStream(Encoding.UTF8.GetBytes(new string(' ', 300000) + payload))))
    { Headers = { ContentType = new MediaTypeHeaderValue("application/json") } }
}))))
{
    Check((await client.CheckForUpdateAsync()).Error is not null, "chunked oversized JSON is bounded");
}

using (var client = new UpdateClient(endpoint, new FakeHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
{
    Content = new StreamContent(new StalledStream()) { Headers = { ContentType = new MediaTypeHeaderValue("application/json") } }
}))))
using (var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(150)))
{
    Check((await client.CheckForUpdateAsync(cancellation.Token)).Error is not null, "streamed response cancellation is handled");
}

using (var client = new UpdateClient(endpoint, new FakeHandler((_, _) => throw new IOException("synthetic transport fault"))))
{
    Check((await client.CheckForUpdateAsync()).Error is not null, "transport I/O failure is handled");
    Check(!client.IsUpdateRequired, "failed check leaves no update requirement");
}

// Download path against the fake transport: size, hash and progress contract.
var installer = new byte[256 * 1024];
for (var index = 0; index < installer.Length; index++) installer[index] = (byte)(index * 31 % 251);
var installerHash = Convert.ToHexString(SHA256.HashData(installer)).ToLowerInvariant();
var downloadUri = $"https://github.com/o/r/releases/download/v{current}/NovaProtect-Setup-{current}.exe";
string DownloadJson(string sha256, long size) =>
    ReleaseJson(current, $"NovaProtect-Setup-{current}.exe", size, "sha256:" + sha256, downloadUri);

async Task<(UpdateClient Client, ClientUpdateInfo Update)> DownloadClientAsync(string json, Func<HttpRequestMessage, HttpResponseMessage> download)
{
    var client = new UpdateClient(endpoint, new FakeHandler((request, _) =>
    {
        // The metadata call goes to the GitHub API host; every other host in the
        // download chain (github.com, then the object host) is the asset fetch.
        if (request.RequestUri!.Host == endpoint.Host) return Task.FromResult(Response(json));
        return Task.FromResult(download(request));
    }));
    var checkedUpdate = await client.CheckForUpdateAsync();
    Check(checkedUpdate.Error is null && checkedUpdate.Update is not null, "download metadata parses");
    return (client, checkedUpdate.Update!);
}

{
    var (client, update) = await DownloadClientAsync(DownloadJson(installerHash, installer.Length), _ => Binary(installer));
    var progress = 0L;
    var downloaded = await client.DownloadUpdateAsync(update, new Progress<long>(value => progress = value));
    Check(downloaded.Download is not null && progress == installer.Length, "installer downloads with byte progress");
    if (downloaded.Download is not null)
    {
        string downloadedHashText;
        await using (var stream = File.OpenRead(downloaded.Download.FilePath))
        {
            downloadedHashText = Convert.ToHexString(await SHA256.HashDataAsync(stream));
        }
        Check(downloadedHashText.Equals(installerHash, StringComparison.OrdinalIgnoreCase), "downloaded installer SHA-256 matches");
        var directory = Path.GetDirectoryName(downloaded.Download.FilePath);
        File.Delete(downloaded.Download.FilePath);
        if (directory is not null && Directory.Exists(directory)) Directory.Delete(directory, true);
    }
    client.Dispose();
}

// GitHub answers an asset download with a 302 to its object host; the updater
// must follow that hop and refuse one that leaves GitHub's hosts.
{
    var objectUri = new Uri("https://objects.githubusercontent.com/asset/xyz");
    var (client, update) = await DownloadClientAsync(DownloadJson(installerHash, installer.Length), request =>
        request.RequestUri!.Host == "github.com" ? Redirect(objectUri) : Binary(installer));
    var downloaded = await client.DownloadUpdateAsync(update);
    Check(downloaded.Download is not null, "GitHub 302 to the object host is followed");    if (downloaded.Download is not null)
    {
        var directory = Path.GetDirectoryName(downloaded.Download.FilePath);
        File.Delete(downloaded.Download.FilePath);
        if (directory is not null && Directory.Exists(directory)) Directory.Delete(directory, true);
    }
    client.Dispose();
}

{
    var evil = new Uri("https://evil.example/asset/xyz");
    var (client, update) = await DownloadClientAsync(DownloadJson(installerHash, installer.Length), request =>
        request.RequestUri!.Host == "github.com" ? Redirect(evil) : Binary(installer));
    var downloaded = await client.DownloadUpdateAsync(update);
    Check(downloaded.Download is null && downloaded.Error is not null, "redirect leaving GitHub is refused");
    client.Dispose();
}

foreach (var (name, json, download) in new (string Name, string Json, Func<HttpRequestMessage, HttpResponseMessage> Download)[]
{
    ("content-length mismatch", DownloadJson(installerHash, installer.Length + 1), _ => Binary(installer)),
    ("SHA-256 mismatch", DownloadJson(new string('0', 64), installer.Length), _ => Binary(installer)),
    ("truncated chunked body", DownloadJson(installerHash, installer.Length + 16), _ => Chunked(installer)),
    ("oversized chunked body", DownloadJson(installerHash, 1024), _ => Chunked(installer))
})
{
    var (client, update) = await DownloadClientAsync(json, download);
    var downloaded = await client.DownloadUpdateAsync(update);
    Check(downloaded.Download is null && downloaded.Error is not null, name + " is rejected");
    client.Dispose();
}

// Exercise the real HttpClientHandler path against a loopback server.
using (var tcp = new TcpListener(IPAddress.Loopback, 0))
{
    tcp.Start();
    var port = ((IPEndPoint)tcp.LocalEndpoint).Port;
    tcp.Stop();
    var local = new Uri($"http://127.0.0.1:{port}/");
    using var listener = new HttpListener();
    listener.Prefixes.Add(local.ToString());
    listener.Start();
    var server = Task.Run(async () =>
    {
        for (var index = 0; index < 2; index++)
        {
            var context = await listener.GetContextAsync();
            var body = index == 0 ? payload : "{\"message\":\"unavailable\"}";
            context.Response.ContentType = "application/json";
            if (index == 1) context.Response.StatusCode = 503;
            var bytes = Encoding.UTF8.GetBytes(body);
            await context.Response.OutputStream.WriteAsync(bytes);
            context.Response.Close();
        }
    });
    using var client = new UpdateClient(local);
    var result = await client.CheckForUpdateAsync();
    Check(result.Error is null && result.Update!.ClientVersion == current, "real transport update metadata");
    Check((await client.CheckForUpdateAsync()).Error is not null, "real transport 503 is reported");
    await server.WaitAsync(TimeSpan.FromSeconds(10));
}

Console.WriteLine($"UPDATE-SMOKE-OK ({passed} checks, version {ProductInfo.Version})");

HttpResponseMessage Chunked(byte[] content, string mediaType = "application/octet-stream") =>
    new(HttpStatusCode.OK)
    {
        Content = new StreamContent(new NonSeekableStream(new MemoryStream(content)))
        {
            Headers = { ContentType = new MediaTypeHeaderValue(mediaType) }
        }
    };

sealed class FakeHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken);
}

sealed class NonSeekableStream(Stream inner) : Stream
{
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, count);
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => inner.ReadAsync(buffer, cancellationToken);
    public override void Flush() => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
}

sealed class StalledStream : Stream
{
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        await Task.Delay(Timeout.Infinite, cancellationToken);
        return 0;
    }
    public override void Flush() => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
