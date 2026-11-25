<?php
declare(strict_types=1);

/**
 * Client release data — single source: GitHub Releases.
 *
 * Render-time chain (never blanks a page):
 *   1. in-request memo
 *   2. public/data/cache/releases.json  (live fetch, TTL below)
 *   3. public/data/releases.json        (baked at package time)
 *   4. empty array
 *
 * Sync latency: the cache is revalidated every NP_RELEASES_TTL seconds
 * (default 60) with a conditional request, so a new GitHub Release shows up on
 * the next page view instead of after an hour. A 304 answer costs no rate
 * limit, which is what makes a one-minute TTL affordable on the unauthenticated
 * API quota; set NP_GITHUB_TOKEN to raise that quota from 60 to 5000 per hour.
 * After a failed fetch the cache backs off for NP_RELEASES_FAILURE_BACKOFF
 * seconds so an outage does not turn every page view into a fresh attempt.
 *
 * HTML pages send Cache-Control: no-cache so browsers/CDN do not pin a stale
 * version list.
 *
 * The site displays NO website version; every version shown is a client
 * release tag from GitHub.
 */

const NP_GITHUB_REPO = 'sudfiona/NovaProtect';
const NP_GITHUB_API = 'https://api.github.com/repos/' . NP_GITHUB_REPO . '/releases?per_page=30';
// One minute: a published Release is on the site by the next view.
// Override: setenv NP_RELEASES_TTL 15  (seconds; min 15, max 86400)
const NP_RELEASES_TTL_DEFAULT = 60;
const NP_RELEASES_TTL_MIN = 15;
const NP_RELEASES_TTL_MAX = 86400;
// GitHub unreachable (offline / rate limited / no openssl): wait this long
// before asking again instead of retrying on every request.
const NP_RELEASES_FAILURE_BACKOFF = 60;

function np_releases_ttl(): int
{
    $raw = getenv('NP_RELEASES_TTL');
    if ($raw === false || $raw === '') {
        return NP_RELEASES_TTL_DEFAULT;
    }
    $n = (int) $raw;
    if ($n < NP_RELEASES_TTL_MIN) {
        return NP_RELEASES_TTL_MIN;
    }
    if ($n > NP_RELEASES_TTL_MAX) {
        return NP_RELEASES_TTL_MAX;
    }
    return $n;
}

/**
 * @return list<array{version:string,label:string,tag:string,publishedAt:string,prerelease:bool,pageUrl:string,notes:string,assets:list<array{name:string,size:int,sha256:string,url:string}>}>
 */
function np_releases(): array
{
    static $memo = null;
    if ($memo !== null) {
        return $memo;
    }

    $cachePath = __DIR__ . '/../public/data/cache/releases.json';
    $bakedPath = __DIR__ . '/../public/data/releases.json';
    $ttl = np_releases_ttl();

    $cached = np_read_releases_file($cachePath);
    if ($cached !== null && $cached['releases'] !== [] && (time() - $cached['fetchedAt']) < $ttl) {
        return $memo = $cached['releases'];
    }

    // A recent failure is honoured before touching the network: without this a
    // blocked or rate-limited host turns every page view into a doomed request.
    if ($cached !== null && $cached['failedAt'] > 0 && (time() - $cached['failedAt']) < NP_RELEASES_FAILURE_BACKOFF) {
        return $memo = np_releases_fallback($cached, $bakedPath);
    }

    $fetched = np_fetch_github_releases($cached['etag'] ?? '');
    if ($fetched !== null && $fetched['notModified']) {
        // 304: the list did not change, so only the freshness stamp moves.
        np_write_release_cache($cachePath, $cached['releases'], $fetched['etag'], 0);
        return $memo = $cached['releases'];
    }
    if ($fetched !== null && $fetched['releases'] !== []) {
        np_write_release_cache($cachePath, $fetched['releases'], $fetched['etag'], 0);
        return $memo = $fetched['releases'];
    }

    np_write_release_cache($cachePath, $cached['releases'] ?? [], $cached['etag'] ?? '', time());
    return $memo = np_releases_fallback($cached, $bakedPath);
}

/**
 * Stale cache beats baked beats nothing.
 *
 * @param array{fetchedAt:int,etag:string,failedAt:int,releases:list<array>}|null $cached
 * @return list<array>
 */
function np_releases_fallback(?array $cached, string $bakedPath): array
{
    if ($cached !== null && $cached['releases'] !== []) {
        return $cached['releases'];
    }
    $baked = np_read_releases_file($bakedPath);
    return $baked['releases'] ?? [];
}

/** @return array{version:string,label:string,tag:string,publishedAt:string,prerelease:bool,pageUrl:string,notes:string,assets:array}|null */
function np_latest_release(): ?array
{
    $all = np_releases();
    return $all[0] ?? null;
}

/**
 * The version as the page shows it: "3.2.5" for a plain tag, "3.2.5-beta" when
 * the tag carries a channel suffix.
 *
 * The numeric part stays separate because it is what ordering, comparison and
 * the installer file name all key on; the label is display-only.
 */
function np_release_display_version(array $release): string
{
    $version = (string) ($release['version'] ?? '');
    $label = (string) ($release['label'] ?? '');
    return $label === '' ? $version : $version . '-' . $label;
}

/**
 * First installer asset of a release.
 *
 * The tag and the asset file name can disagree (historical releases did; 2.3.11
 * shipped NovaProtect-Setup-2.3.18.exe), so the asset whose name matches the
 * release version is preferred and the first .exe is the fallback — the asset
 * is what users download.
 *
 * @param array $release
 * @return array{name:string,size:int,sha256:string,url:string}|null
 */
function np_release_asset(array $release): ?array
{
    $expected = 'NovaProtect-Setup-' . (string) ($release['version'] ?? '') . '.exe';
    $fallback = null;
    foreach ($release['assets'] ?? [] as $asset) {
        $name = (string) ($asset['name'] ?? '');
        if (!preg_match('/\.exe$/i', $name)) {
            continue;
        }
        if (strcasecmp($name, $expected) === 0) {
            return $asset;
        }
        if ($fallback === null) {
            $fallback = $asset;
        }
    }
    return $fallback;
}

/** @return array{fetchedAt:int,etag:string,failedAt:int,releases:list<array>}|null */
function np_read_releases_file(string $path): ?array
{
    if (!is_file($path) || !is_readable($path)) {
        return null;
    }
    $raw = @file_get_contents($path);
    if ($raw === false || $raw === '') {
        return null;
    }
    try {
        $data = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        return null;
    }
    if (!is_array($data)) {
        return null;
    }
    // Cache files wrap the list (fetchedAt/etag/failedAt); the baked file is a
    // bare list.
    if (array_is_list($data)) {
        return ['fetchedAt' => 0, 'etag' => '', 'failedAt' => 0, 'releases' => $data];
    }
    if (isset($data['releases']) && is_array($data['releases']) && array_is_list($data['releases'])) {
        return [
            'fetchedAt' => (int) ($data['fetchedAt'] ?? 0),
            'etag' => (string) ($data['etag'] ?? ''),
            'failedAt' => (int) ($data['failedAt'] ?? 0),
            'releases' => $data['releases'],
        ];
    }
    return null;
}

/**
 * Request the published release list.
 *
 * @param string $etag ETag of the cached body; sent as If-None-Match so an
 *                     unchanged list answers 304 without consuming quota.
 * @return array{releases:list<array>,etag:string,notModified:bool}|null
 *         null means "the request told us nothing useful" (offline, rate
 *         limited, HTML error page, unparseable payload).
 */
function np_fetch_github_releases(string $etag = ''): ?array
{
    $headers = "User-Agent: NovaProtect-site/2.1\r\nAccept: application/vnd.github+json\r\n";
    // The website only reads public data, so a token is optional: it exists to
    // lift the unauthenticated 60 requests/hour ceiling on a busy site.
    $token = getenv('NP_GITHUB_TOKEN');
    if (is_string($token) && trim($token) !== '') {
        $headers .= 'Authorization: Bearer ' . trim($token) . "\r\n";
    }
    if ($etag !== '') {
        $headers .= 'If-None-Match: ' . $etag . "\r\n";
    }

    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => 8,
            'header' => $headers,
            'ignore_errors' => true,
        ],
    ]);
    $raw = @file_get_contents(NP_GITHUB_API, false, $context);
    if ($raw === false) {
        return null;
    }

    $status = 0;
    $responseEtag = '';
    foreach ($http_response_header ?? [] as $line) {
        if (preg_match('#^HTTP/\S+\s+(\d+)#', $line, $m)) {
            // Redirects repeat the status line; the last one is the real answer.
            $status = (int) $m[1];
            continue;
        }
        if (strncasecmp($line, 'ETag:', 5) === 0) {
            $responseEtag = trim(substr($line, 5));
        }
    }

    if ($status === 304) {
        return ['releases' => [], 'etag' => $responseEtag !== '' ? $responseEtag : $etag, 'notModified' => true];
    }
    if ($status !== 200) {
        return null;
    }

    try {
        $decoded = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        return null;
    }
    if (!is_array($decoded)) {
        return null;
    }
    $shaped = np_shape_releases($decoded);
    return ['releases' => $shaped, 'etag' => $responseEtag, 'notModified' => false];
}

/**
 * Split a GitHub tag into its numeric version and its channel label.
 *
 * GitHub tags are free-form, and the newest NovaProtect releases are published
 * as `3.2.5-beta`. The site used to require a bare three-part number, so that
 * tag — and every suffixed tag like it — was dropped outright: the changelog
 * silently stopped at the previous plain tag while GitHub had already moved on.
 *
 * A suffix must not simply be stripped either: `3.2.5` and `3.2.5-beta` are two
 * different releases, and folding them together would show a beta build as the
 * plain version. So the tag is split and both halves are kept — the number for
 * ordering, comparison and asset names, the label for display.
 *
 * Order of operations follows the tag contract exactly: trim, drop one leading
 * v/V, drop the `+build` metadata tail, split at the first `-`, then validate
 * the core and the label separately.
 *
 * @return array{version:string,label:string}|null
 */
function np_parse_release_tag(string $tag): ?array
{
    $value = trim($tag);
    if ($value === '') {
        return null;
    }
    if ($value[0] === 'v' || $value[0] === 'V') {
        $value = substr($value, 1);
    }

    // Semver build metadata is informational: nothing orders or compares on it
    // and it is never part of an asset name.
    $plus = strpos($value, '+');
    if ($plus !== false) {
        $value = substr($value, 0, $plus);
    }

    // Only the first '-' separates the channel, so "rc.1-x" stays one label. A
    // dash with nothing behind it ("3.2.5-") is rejected rather than read as an
    // empty label: both spellings would otherwise name the same version while
    // sorting and displaying differently.
    $label = '';
    $dash = strpos($value, '-');
    if ($dash !== false) {
        $label = substr($value, $dash + 1);
        $value = substr($value, 0, $dash);
        if ($label === '') {
            return null;
        }
    }

    if (!preg_match('/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/D', $value)) {
        return null;
    }
    if ($label !== '' && !preg_match('/^[0-9A-Za-z][0-9A-Za-z.\-]*$/D', $label)) {
        return null;
    }

    return ['version' => $value, 'label' => $label];
}

/**
 * @param list<array> $decoded GitHub /releases payload
 * @return list<array>
 */
function np_shape_releases(array $decoded): array
{
    $shaped = [];
    foreach ($decoded as $release) {
        if (!is_array($release)) {
            continue;
        }
        // Drafts are visible to the owner only; listing one would advertise a
        // version nobody can download. The client updater skips them for the
        // same reason.
        if (($release['draft'] ?? false) === true) {
            continue;
        }
        $tag = trim((string) ($release['tag_name'] ?? ''));
        $parsed = $tag === '' ? null : np_parse_release_tag($tag);
        if ($parsed === null) {
            continue;
        }

        $assets = [];
        foreach (($release['assets'] ?? []) as $asset) {
            if (!is_array($asset)) {
                continue;
            }
            $name = (string) ($asset['name'] ?? '');
            if (!preg_match('/\.exe$/i', $name)) {
                continue;
            }
            $digest = (string) ($asset['digest'] ?? '');
            $sha256 = '';
            if ($digest !== '') {
                $pos = strpos($digest, ':');
                $sha256 = strtolower($pos === false ? $digest : substr($digest, $pos + 1));
            }
            $assets[] = [
                'name' => $name,
                'size' => (int) ($asset['size'] ?? 0),
                'sha256' => $sha256,
                'url' => (string) ($asset['browser_download_url'] ?? ''),
            ];
        }

        $published = (string) ($release['published_at'] ?? '');
        $shaped[] = [
            'version' => $parsed['version'],
            'label' => $parsed['label'],
            'tag' => $tag,
            // Either signal marks a pre-release: the channel label in the tag,
            // or GitHub's own flag when the owner set it by hand.
            'prerelease' => $parsed['label'] !== '' || (bool) ($release['prerelease'] ?? false),
            'publishedAt' => $published !== '' ? substr($published, 0, 10) : '',
            'pageUrl' => (string) ($release['html_url'] ?? ''),
            'notes' => trim((string) ($release['body'] ?? '')) !== ''
                ? trim((string) ($release['body'] ?? ''))
                : '本次版本没有填写更新说明。',
            'assets' => $assets,
        ];
    }

    // Newest first by the numeric core; a plain tag outranks its own -beta on
    // the same number, then the newer publish date wins.
    usort($shaped, static function (array $a, array $b): int {
        $cmp = version_compare($b['version'], $a['version']);
        if ($cmp !== 0) {
            return $cmp;
        }
        if (($a['label'] === '') !== ($b['label'] === '')) {
            return $a['label'] === '' ? -1 : 1;
        }
        return strcmp($b['publishedAt'], $a['publishedAt']);
    });

    return $shaped;
}

/**
 * @param list<array> $releases
 * @param string $etag ETag to store for the next conditional request.
 * @param int $failedAt Unix time of a failed fetch, 0 when the write follows a
 *                      successful one (which clears any previous backoff).
 */
function np_write_release_cache(string $path, array $releases, string $etag = '', int $failedAt = 0): void
{
    $dir = dirname($path);
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    $payload = json_encode(
        [
            'fetchedAt' => $failedAt === 0 ? time() : 0,
            'failedAt' => $failedAt,
            'etag' => $etag,
            'releases' => $releases,
        ],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT
    );
    if ($payload === false) {
        return;
    }
    @file_put_contents($path, $payload . "\n", LOCK_EX);
}