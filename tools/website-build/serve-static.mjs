// Local preview server that mirrors deploy/nginx-location.conf, so the pages
// are tested against the same resolution rules the real origin uses:
//   try_files $uri $uri.html $uri/ =404   ->  error_page 404 /404.html
// Testing with a plain file server would hide exactly the bug worth catching:
// a clean URL like /download has no file until the .html fallback applies.
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { join, extname, normalize } from 'node:path';

const root = process.argv[2];
const port = Number(process.argv[3] || 5087);
if (!root) {
  console.error('usage: serve-static.mjs <public-dir> [port]');
  process.exit(2);
}

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.svg': 'image/svg+xml',
};

const CACHE = {
  '/assets/': 'public, max-age=2592000, immutable',
  '/css/': 'public, max-age=604800',
  '/js/': 'public, max-age=604800',
  '/data/': 'public, max-age=300',
};

async function isFile(path) {
  try {
    const info = await stat(path);
    return info.isFile();
  } catch {
    return false;
  }
}

async function resolve(pathname) {
  // Refuse anything that escapes the document root.
  const safe = normalize(decodeURIComponent(pathname)).replace(/^(\.\.[/\\])+/, '');
  const candidate = join(root, safe);
  if (!candidate.startsWith(root)) return null;

  if (await isFile(candidate)) return candidate;
  if (await isFile(candidate + '.html')) return candidate + '.html';
  const index = join(candidate, 'index.html');
  if (await isFile(index)) return index;
  return null;
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  let pathname = url.pathname;

  try {
    const file = await resolve(pathname);
    if (!file) {
      const body = await readFile(join(root, '404.html'));
      res.writeHead(404, { 'Content-Type': TYPES['.html'], 'Cache-Control': 'no-cache' });
      res.end(body);
      return;
    }
    const body = await readFile(file);
    const headers = {
      'Content-Type': TYPES[extname(file)] || 'application/octet-stream',
      'X-Content-Type-Options': 'nosniff',
    };
    let cache = 'no-cache';
    for (const [prefix, value] of Object.entries(CACHE)) {
      if (pathname.startsWith(prefix)) { cache = value; break; }
    }
    headers['Cache-Control'] = cache;
    res.writeHead(200, headers);
    res.end(req.method === 'HEAD' ? undefined : body);
  } catch (error) {
    res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(String(error));
  }
});

server.listen(port, '127.0.0.1', () => {
  console.log(`serving ${root} on http://127.0.0.1:${port}/`);
});
