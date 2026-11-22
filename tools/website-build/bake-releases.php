<?php
declare(strict_types=1);
/**
 * Bakes website/public/data/releases.json from GitHub Releases.
 *
 * The baked file is the offline fallback for lib/releases.php: at runtime the
 * site prefers a live GitHub fetch (1h cache) and falls back to this snapshot
 * so a page never loses its version banner or changelog.
 *
 * Usage:
 *   php tools/website-build/bake-releases.php
 *   php -d extension=php_openssl.dll tools/website-build/bake-releases.php   (CLI without php.ini)
 */
require dirname(__DIR__, 2) . '/website/lib/releases.php';

$releases = np_fetch_github_releases();
if ($releases === null) {
    fwrite(STDERR, "bake-releases: GitHub fetch failed (network / rate limit / openssl)\n");
    exit(1);
}

$out = dirname(__DIR__, 2) . '/website/public/data/releases.json';
$dir = dirname($out);
if (!is_dir($dir)) {
    mkdir($dir, 0755, true);
}
$json = json_encode($releases, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
if ($json === false) {
    fwrite(STDERR, "bake-releases: json_encode failed\n");
    exit(1);
}
file_put_contents($out, $json . "\n");

echo sprintf("bake-releases: %d releases -> %s\n", count($releases), $out);
echo 'latest: ' . $releases[0]['version'] . ' (' . $releases[0]['publishedAt'] . ")\n";
