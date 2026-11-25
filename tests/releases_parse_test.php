<?php
declare(strict_types=1);

/**
 * Contract test for website/lib/releases.php.
 *
 * The website and the desktop updater share one tag contract: GitHub tags are
 * free-form, the newest NovaProtect release is tagged `3.2.5-beta`, and both
 * readers must show that release under its numeric version while keeping the
 * channel label for display. Requiring a bare `X.Y.Z` silently dropped every
 * suffixed tag from the changelog and made the download page advertise an older
 * version than the one actually published.
 *
 * Everything here is offline: the pure helpers and the cache file format are
 * exercised directly so this runs in CI and on a machine without network.
 *
 * Usage: php tests/releases_parse_test.php
 */

require dirname(__DIR__) . '/website/lib/releases.php';

$passed = 0;
$failed = 0;

function check(bool $ok, string $name): void
{
    global $passed, $failed;
    if ($ok) {
        $passed++;
        echo "[ OK ] $name\n";
    } else {
        $failed++;
        echo "[FAIL] $name\n";
    }
}

function eq(mixed $actual, mixed $expected, string $name): void
{
    global $passed, $failed;
    if ($actual === $expected) {
        $passed++;
        echo "[ OK ] $name\n";
        return;
    }
    $failed++;
    echo '[FAIL] ' . $name . ' (expected ' . var_export($expected, true) . ', got ' . var_export($actual, true) . ")\n";
}

/** @return array<string,mixed> */
function fetch_entry(string $tag, string $body = 'body', bool $prerelease = false, array $assets = [], string $published = '2026-11-23T00:00:00Z'): array
{
    return [
        'tag_name' => $tag,
        'name' => $tag,
        'draft' => false,
        'prerelease' => $prerelease,
        'published_at' => $published,
        'html_url' => 'https://github.com/sudfiona/NovaProtect/releases/tag/' . $tag,
        'body' => $body,
        'assets' => $assets,
    ];
}

function exe_asset(string $name, int $size = 123, string $digest = 'sha256:ABC', string $url = ''): array
{
    return [
        'name' => $name,
        'size' => $size,
        'digest' => $digest,
        'browser_download_url' => $url !== '' ? $url : 'https://github.com/x/' . $name,
    ];
}

// ---------------------------------------------------------------------------
// Tag parsing: what the site must accept.
// ---------------------------------------------------------------------------
echo "--- accepted tags ---\n";
foreach ([
    ['3.2.5', '3.2.5', ''],
    ['v3.2.5', '3.2.5', ''],
    ['V3.2.5', '3.2.5', ''],
    ['3.2.5-beta', '3.2.5', 'beta'],
    ['v3.2.5-beta', '3.2.5', 'beta'],
    ['3.2.5-rc.1', '3.2.5', 'rc.1'],
    ['3.2.5+build.7', '3.2.5', ''],
    ['3.2.5-beta+build.7', '3.2.5', 'beta'],
    ['3.2.5-BETA', '3.2.5', 'BETA'],
    ['3.2.5-beta-hotfix.2', '3.2.5', 'beta-hotfix.2'],
    ["  3.2.5  ", '3.2.5', ''],
    ["\t3.2.5\n", '3.2.5', ''],
    // Vertical tab is in PHP's default trim() list, so it is stripped; the C#
    // parser trims the same six characters and must agree.
    ["3.2.5\x0B", '3.2.5', ''],
    ['0.0.1', '0.0.1', ''],
] as [$tag, $version, $label]) {
    $parsed = np_parse_release_tag($tag);
    if ($parsed === null) {
        check(false, "accept '$tag'");
        continue;
    }
    eq($parsed['version'], $version, "accept '$tag' -> numeric core");
    eq($parsed['label'], $label, "accept '$tag' -> channel label");
}

// ---------------------------------------------------------------------------
// Tag parsing: what must still be refused. Nothing here may be coerced into a
// version, because a wrong version number is worse than a missing release.
// ---------------------------------------------------------------------------
echo "--- rejected tags ---\n";
foreach ([
    'nightly', '3.2', '3.2.5.1', '3.2.5-', '3.2.5-beta!', 'release-3.2.5',
    '', '   ', 'v', 'V', '03.2.5', '3.02.5', '3.2.05', '3.2.5_1', 'latest',
    '3.2.5-', '3.2.5 -beta', '-3.2.5', '3.2.5-beta rc1',
    // Non-ASCII whitespace and form feed are NOT in the trim list on either
    // side: the tag is malformed, and both readers must refuse it rather than
    // guess. These four are the exact cases where the two parsers used to
    // disagree (PHP trim() vs C# Trim()).
    "3.2.5\u{00A0}", "3.2.5\f", "3.2.5\u{3000}", "\u{00A0}3.2.5",
] as $tag) {
    check(np_parse_release_tag($tag) === null, "reject '$tag'");
}

// ---------------------------------------------------------------------------
// Shaping a GitHub payload: the suffixed release must survive, sort correctly
// and keep its label.
// ---------------------------------------------------------------------------
echo "--- shaping ---\n";
$shaped = np_shape_releases([
    fetch_entry('3.1.6', 'stable notes', false, [exe_asset('NovaProtect-Setup-3.1.6.exe')], '2026-11-22T10:00:00Z'),
    fetch_entry('3.2.5-beta', 'beta notes', false, [exe_asset('NovaProtect-Setup-3.2.5.exe')], '2026-11-23T14:05:09Z'),
    fetch_entry('nightly', 'draft-ish', false, [exe_asset('NovaProtect-Setup-1.0.0.exe')]),
    fetch_entry('3.2.5', 'plain notes', false, [exe_asset('NovaProtect-Setup-3.2.5.exe')], '2026-11-24T10:00:00Z'),
    array_merge(fetch_entry('3.3.0', 'draft'), ['draft' => true]),
]);

eq(count($shaped), 3, 'draft and non-semver entries are dropped');
eq($shaped[0]['version'], '3.2.5', 'the stable tag outranks its own -beta');
eq($shaped[0]['label'], '', 'stable tag carries no label');
eq($shaped[1]['version'], '3.2.5', 'the -beta tag keeps the same numeric version');
eq($shaped[1]['label'], 'beta', 'the -beta tag keeps its channel label');
eq($shaped[1]['tag'], '3.2.5-beta', 'the published tag is preserved for the GitHub link');
eq($shaped[1]['prerelease'], true, 'a -beta tag is a pre-release even when GitHub says otherwise');
eq($shaped[2]['version'], '3.1.6', 'older releases still sort below the newest number');
eq($shaped[2]['prerelease'], false, 'a plain tag is not a pre-release');
eq($shaped[1]['notes'], 'beta notes', 'release body becomes the notes');
eq($shaped[2]['publishedAt'], '2026-11-22', 'publish date is reduced to the calendar day');
eq($shaped[1]['assets'][0]['sha256'], 'abc', 'digest is lowercased and stripped of its algorithm prefix');
eq($shaped[1]['assets'][0]['name'], 'NovaProtect-Setup-3.2.5.exe', 'installer asset name is kept');

// GitHub's own prerelease flag must still be honoured for a plain tag.
$flagged = np_shape_releases([fetch_entry('3.4.0', 'rc', true, [exe_asset('NovaProtect-Setup-3.4.0.exe')])]);
eq($flagged[0]['prerelease'], true, "GitHub's prerelease flag marks a plain tag as pre-release");

// Empty bodies get the standing placeholder rather than an empty card.
$empty = np_shape_releases([fetch_entry('3.0.1', "  \r\n ", false, [])]);
eq($empty[0]['notes'], '本次版本没有填写更新说明。', 'a release without a body gets the placeholder');

// Release without an installer: still listed, with no assets.
eq($empty[0]['assets'], [], 'a release without assets is still shaped');

// ---------------------------------------------------------------------------
// Display version.
// ---------------------------------------------------------------------------
echo "--- display ---\n";
eq(np_release_display_version(['version' => '3.2.5', 'label' => '']), '3.2.5', 'plain display version');
eq(np_release_display_version(['version' => '3.2.5', 'label' => 'beta']), '3.2.5-beta', 'labelled display version');
eq(np_release_display_version(['version' => '3.2.5']), '3.2.5', 'display version tolerates a missing label key');

// ---------------------------------------------------------------------------
// Installer asset selection: exact name wins, first .exe is the fallback, and
// the sidecar .sha256 file is never mistaken for an installer.
// ---------------------------------------------------------------------------
echo "--- installer asset ---\n";
$preferExact = [
    'version' => '2.3.11',
    'assets' => [
        exe_asset('NovaProtect-Setup-2.3.18.exe'),
        exe_asset('NovaProtect-Setup-2.3.11.exe'),
    ],
];
eq(np_release_asset($preferExact)['name'], 'NovaProtect-Setup-2.3.11.exe', 'the asset matching the tag wins over an earlier one');

$fallback = ['version' => '2.3.11', 'assets' => [exe_asset('NovaProtect-Setup-2.3.18.exe')]];
eq(np_release_asset($fallback)['name'], 'NovaProtect-Setup-2.3.18.exe', 'a mismatched asset name is still offered');

$withSidecar = [
    'version' => '3.2.5',
    'assets' => [
        ['name' => 'NovaProtect-Setup-3.2.5.exe.sha256', 'size' => 94, 'digest' => '', 'browser_download_url' => 'https://github.com/x/sum'],
        exe_asset('NovaProtect-Setup-3.2.5.exe'),
    ],
];
eq(np_release_asset($withSidecar)['name'], 'NovaProtect-Setup-3.2.5.exe', 'the .sha256 sidecar is not taken as the installer');
check(np_release_asset(['version' => '9.9.9', 'assets' => []]) === null, 'no installer asset yields null');

// ---------------------------------------------------------------------------
// Cache file format: the live cache wraps the list with a freshness stamp, an
// ETag and a failure stamp; the baked snapshot is a bare list.
// ---------------------------------------------------------------------------
echo "--- cache format ---\n";
$dir = sys_get_temp_dir() . '/np-releases-test-' . bin2hex(random_bytes(4));
mkdir($dir, 0700, true);
try {
    $cachePath = $dir . '/cache.json';
    $releases = [['version' => '3.2.5', 'label' => 'beta', 'tag' => '3.2.5-beta', 'prerelease' => true,
        'publishedAt' => '2026-11-23', 'pageUrl' => '', 'notes' => 'notes', 'assets' => []]];

    np_write_release_cache($cachePath, $releases, '"etag-1"', 0);
    $read = np_read_releases_file($cachePath);
    check($read !== null, 'cache written in the wrapped format is readable');
    eq($read['releases'][0]['tag'], '3.2.5-beta', 'cache round-trips the release list');
    eq($read['etag'], '"etag-1"', 'cache round-trips the ETag for conditional requests');
    eq($read['failedAt'], 0, 'a successful write clears the failure stamp');
    check($read['fetchedAt'] > 0, 'a successful write stamps the fetch time');

    np_write_release_cache($cachePath, [], '', time());
    $failedRead = np_read_releases_file($cachePath);
    eq($failedRead['fetchedAt'], 0, 'a failed write does not claim freshness');
    check($failedRead['failedAt'] > 0, 'a failed write stamps the backoff');

    // Legacy shapes must keep loading: an upgrade must not blank the changelog.
    file_put_contents($dir . '/legacy-list.json', json_encode($releases));
    $legacy = np_read_releases_file($dir . '/legacy-list.json');
    eq($legacy['fetchedAt'], 0, 'a bare list (baked snapshot) loads with no freshness stamp');
    eq($legacy['etag'], '', 'a bare list has no ETag');
    eq(count($legacy['releases']), 1, 'a bare list still yields its releases');

    file_put_contents($dir . '/legacy-obj.json', json_encode(['fetchedAt' => 123, 'releases' => $releases]));
    $legacyObj = np_read_releases_file($dir . '/legacy-obj.json');
    eq($legacyObj['fetchedAt'], 123, 'a pre-ETag cache keeps its timestamp');
    eq($legacyObj['etag'], '', 'a pre-ETag cache reads back with an empty ETag');

    file_put_contents($dir . '/broken.json', '{broken');
    check(np_read_releases_file($dir . '/broken.json') === null, 'a corrupt cache is ignored rather than trusted');
    check(np_read_releases_file($dir . '/does-not-exist.json') === null, 'a missing cache is not an error');
} finally {
    foreach (glob($dir . '/*') ?: [] as $file) {
        @unlink($file);
    }
    @rmdir($dir);
}

// ---------------------------------------------------------------------------
// Freshness policy: the default is near-real-time and the env override is
// clamped so a typo cannot pin the site to a stale list for a day.
// ---------------------------------------------------------------------------
echo "--- ttl policy ---\n";
$original = getenv('NP_RELEASES_TTL');
putenv('NP_RELEASES_TTL');
eq(np_releases_ttl(), 60, 'default TTL is one minute');
putenv('NP_RELEASES_TTL=30');
eq(np_releases_ttl(), 30, 'TTL honours the environment override');
putenv('NP_RELEASES_TTL=5');
eq(np_releases_ttl(), 15, 'TTL is clamped up to the minimum');
putenv('NP_RELEASES_TTL=999999');
eq(np_releases_ttl(), 86400, 'TTL is clamped down to the maximum');
putenv('NP_RELEASES_TTL=not-a-number');
eq(np_releases_ttl(), 15, 'a non-numeric TTL falls back to the minimum');
if ($original === false) {
    putenv('NP_RELEASES_TTL');
} else {
    putenv('NP_RELEASES_TTL=' . $original);
}

// ---------------------------------------------------------------------------
// The packaged snapshot must agree with the contract: this is the data source
// a visitor sees when GitHub is unreachable, and it is what the package ships.
// ---------------------------------------------------------------------------
echo "--- baked snapshot ---\n";
$bakedPath = dirname(__DIR__) . '/website/public/data/releases.json';
$baked = np_read_releases_file($bakedPath);
check($baked !== null, 'the baked snapshot exists and parses');
if ($baked !== null) {
    check(count($baked['releases']) > 0, 'the baked snapshot holds releases');
    $first = $baked['releases'][0] ?? null;
    check($first !== null, 'the baked snapshot has a newest entry');
    if ($first !== null) {
        check(preg_match('/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/D', $first['version']) === 1, 'the newest baked entry has a numeric version');
        check(isset($first['label']), 'the newest baked entry records a channel label field');
        check(np_release_asset($first) !== null, 'the newest baked entry offers an installer asset');
    }
    $previous = null;
    $ordered = true;
    foreach ($baked['releases'] as $release) {
        if ($previous !== null && version_compare($previous, $release['version']) < 0) {
            $ordered = false;
            break;
        }
        $previous = $release['version'];
    }
    check($ordered, 'the baked snapshot is ordered newest-first');
}

echo "\n" . ($failed === 0 ? "RELEASES-PARSE-OK ($passed checks)" : "RELEASES-PARSE-FAILED ($failed of " . ($passed + $failed) . ' checks)') . "\n";
exit($failed === 0 ? 0 : 1);
