// Regenerates website/public/data/releases.json from GitHub Releases.
//
// The changelog has exactly one source: the published releases. The pages bake a
// copy so they work without JavaScript, and js/site.js re-renders from this file,
// so refreshing it is how a new release reaches the site.
//
// Node is used rather than PowerShell because Invoke-RestMethod plus a .NET UTF8
// write double-encoded CJK release notes into mojibake. One tool, one encoding.
//
// After publishing a release:
//   node tools/website-build/fetch-releases.mjs
//   .\tools\package-website.ps1 -Force
const REPO = 'sudfiona/NovaProtect';

// Resolved from this file's own location so the script works in any clone:
// tools/website-build/fetch-releases.mjs -> <repo>/website/public/data/...
const { writeFileSync, mkdirSync } = await import('node:fs');
const { dirname, resolve } = await import('node:path');
const { fileURLToPath } = await import('node:url');

const here = dirname(fileURLToPath(import.meta.url));
const OUT = resolve(here, '..', '..', 'website', 'public', 'data', 'releases.json');

const response = await fetch(`https://api.github.com/repos/${REPO}/releases`, {
  headers: {
    'User-Agent': 'NovaProtect-site/1.0',
    Accept: 'application/vnd.github+json',
  },
});

if (!response.ok) {
  console.error(`GitHub API ${response.status} ${response.statusText}`);
  process.exit(1);
}

const releases = await response.json();
if (!Array.isArray(releases) || releases.length === 0) {
  console.error('no releases returned; refusing to write an empty feed');
  process.exit(1);
}

const semver = /^\d+\.\d+\.\d+$/;
const shaped = releases
  .map((r) => ({
    version: String(r.tag_name ?? '').replace(/^v/, ''),
    publishedAt: r.published_at ? String(r.published_at).slice(0, 10) : '',
    prerelease: Boolean(r.prerelease),
    pageUrl: String(r.html_url ?? ''),
    notes: String(r.body ?? '').trim() || '本次版本没有填写更新说明。',
  }))
  // The download page advertises feed[0] as the version to get, so anything
  // without a usable semver tag must not survive into the feed.
  .filter((r) => semver.test(r.version));

if (shaped.length === 0) {
  console.error('no release with a semver tag; refusing to write');
  process.exit(1);
}

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, JSON.stringify(shaped, null, 2) + '\n', 'utf8');

console.log(`${shaped.length} releases written to data/releases.json`);
for (const r of shaped) console.log(`  ${r.version}  ${r.publishedAt}  notes=${r.notes.length}`);
console.log(`\nlatest advertised version: ${shaped[0].version}`);
