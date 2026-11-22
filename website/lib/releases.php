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
 * Sync latency: NP_RELEASES_TTL (default 300s) can be overridden with the
 * NP_RELEASES_TTL env var. When the cache is older than TTL the next page
 * view hits GitHub immediately. HTML pages send Cache-Control: no-cache so
 * browsers/CDN do not pin a stale version list.
 *
 * The site displays NO website version; every version shown is a client
 * release tag from GitHub.
 */

const NP_GITHUB_REPO = 'sudfiona/NovaProtect';
const NP_GITHUB_API = 'https://api.github.com/repos/' . NP_GITHUB_REPO . '/releases?per_page=30';
// 5 minutes: new GitHub Releases show up on the next view without waiting an hour.
// Override: setenv NP_RELEASES_TTL 60  (seconds; min 15, max 86400)
const NP_RELEASES_TTL_DEFAULT = 300;

function np_releases_ttl(): int
{
    $raw = getenv('NP_RELEASES_TTL');
    if ($raw === false || $raw === '') {
        return NP_RELEASES_TTL_DEFAULT;
    }
    $n = (int) $raw;
    if ($n < 15) {
        return 15;
    }
    if ($n > 86400) {
        return 86400;
    }
    return $n;
}

/** @return list<array{version:string,publishedAt:string,prerelease:bool,pageUrl:string,notes:string,assets:list<array{name:string,size:int,sha256:string,url:string}>}> */
function np_releases(): array
{
    static $memo = null;
    if ($memo !== null) {
        return $memo;
    }

    $cache = __DIR__ . '/../public/data/cache/releases.json';
    $baked = __DIR__ . '/../public/data/releases.json';
    $ttl = np_releases_ttl();

    $cached = np_read_releases_file($cache);
    if ($cached !== null && (time() - (int) ($cached['fetchedAt'] ?? 0)) < $ttl) {
        return $memo = $cached['releases'];
    }

    $live = np_fetch_github_releases();
    if ($live !== null) {
        np_write_release_cache($cache, $live);
        return $memo = $live;
    }

    // GitHub unreachable (rate limit / offline / no openssl): stale cache beats baked beats nothing.
    if ($cached !== null) {
        return $memo = $cached['releases'];
    }
    $b = np_read_releases_file($baked);
    return $memo = $b['releases'];
}

/** @return array{version:string,publishedAt:string,prerelease:bool,pageUrl:string,notes:string,assets:array}|null */
function np_latest_release(): ?array
{
    $all = np_releases();
    return $all[0] ?? null;
}

/**
 * First installer asset of a release. The tag and the asset file name can
 * disagree (historical releases did); the asset is what users download.
 *
 * @param array $release
 * @return array{name:string,size:int,sha256:string,url:string}|null
 */
function np_release_asset(array $release): ?array
{
    foreach ($release['assets'] ?? [] as $asset) {
        if (preg_match('/\.exe$/i', $asset['name'] ?? '')) {
            return $asset;
        }
    }
    return null;
}

/** @return array{fetchedAt:int,releases:list<array>}|null */
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
    // Cache files wrap the list with fetchedAt; the baked file is a bare list.
    if (array_is_list($data)) {
        return ['fetchedAt' => 0, 'releases' => $data];
    }
    if (isset($data['releases']) && is_array($data['releases']) && array_is_list($data['releases'])) {
        return ['fetchedAt' => (int) ($data['fetchedAt'] ?? 0), 'releases' => $data['releases']];
    }
    return null;
}

/**
 * @param list<array> $releases
 * @return list<array>
 */
function np_fetch_github_releases(): ?array
{
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => 8,
            'header' => "User-Agent: NovaProtect-site/2.0\r\nAccept: application/vnd.github+json\r\n",
            'ignore_errors' => true,
        ],
    ]);
    $raw = @file_get_contents(NP_GITHUB_API, false, $context);
    if ($raw === false) {
        return null;
    }
    $status = 0;
    if (isset($http_response_header[0]) && preg_match('#HTTP/\S+\s+(\d+)#', $http_response_header[0], $m)) {
        $status = (int) $m[1];
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
    return $shaped === [] ? null : $shaped;
}

/**
 * @param list<array> $decoded GitHub /releases payload
 * @return list<array>
 */
function np_shape_releases(array $decoded): array
{
    $semver = '/^\d+\.\d+\.\d+$/';
    $shaped = [];
    foreach ($decoded as $release) {
        if (!is_array($release)) {
            continue;
        }
        $version = ltrim((string) ($release['tag_name'] ?? ''), 'v');
        if (!preg_match($semver, $version)) {
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
            'version' => $version,
            'publishedAt' => $published !== '' ? substr($published, 0, 10) : '',
            'prerelease' => (bool) ($release['prerelease'] ?? false),
            'pageUrl' => (string) ($release['html_url'] ?? ''),
            'notes' => trim((string) ($release['body'] ?? '')) !== ''
                ? trim((string) ($release['body'] ?? ''))
                : '本次版本没有填写更新说明。',
            'assets' => $assets,
        ];
    }
    // Newest first (version_compare), stable within the same request.
    usort($shaped, static fn (array $a, array $b): int => version_compare($b['version'], $a['version']));
    return $shaped;
}

/**
 * @param list<array> $releases
 */
function np_write_release_cache(string $path, array $releases): void
{
    $dir = dirname($path);
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    $payload = json_encode(
        ['fetchedAt' => time(), 'releases' => $releases],
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT
    );
    if ($payload === false) {
        return;
    }
    @file_put_contents($path, $payload . "\n", LOCK_EX);
}
