// The files of the GUI (planning of item F, 4.1, 5.1; decisions F-2, F-23).  They are read ONCE, when the service starts, into memory; a request is answered from that
// map and never touches the file system, so there is no path to traverse, no directory to list and no race with a file that is replaced.  What is served is `/` (the
// page) and `/ui/<path>` (everything else); anything else that is not under /api/v1/ is a 404.  GET and HEAD only.
//
// What is refused when the directory is read (the service does not start, `ui = no` switches the GUI off): a name with a character outside [A-Za-z0-9._-] (or a part
// that starts with a dot), a link or any file that is not a regular file, an extension without a type below, more than 512 files or 8 MiB, a directory more than 8
// deep, no index.html.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ApiError } from './errors.js';

export const MAX_FILES = 512;
export const MAX_BYTES = 8 << 20;
const MAX_DEPTH = 8;

// the only types the GUI needs: a script is a module (ES modules, F-3), nothing is a font or an external image
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/vnd.microsoft.icon',
  '.txt': 'text/plain; charset=utf-8',
};

const PART = /^[A-Za-z0-9_-][A-Za-z0-9._-]*$/;

// where the files are unless `ui-dir` says otherwise: webadmin/ui next to webadmin/lib (the package puts both under /usr/local/libexec/karidns-webadmin/webadmin/)
export const defaultUiDir = () => fileURLToPath(new URL('../ui/', import.meta.url));

// -> Map('/css/app.css' -> { body: Buffer, type, etag }); throws Error (a text for the operator) when the directory is not fit to be served
export function loadStatic(dir, { fsx = fs } = {}) {
  const files = new Map();
  let total = 0;
  const walk = (abs, rel, depth) => {
    if (depth > MAX_DEPTH) throw new Error(`${rel || '/'}: directories nested more than ${MAX_DEPTH} deep`);
    for (const e of fsx.readdirSync(abs, { withFileTypes: true })) {
      const where = `${rel}/${e.name}`;
      if (!PART.test(e.name)) throw new Error(`${where}: the name must be letters, digits, '.', '_' and '-' (not starting with a dot)`);
      const full = path.join(abs, e.name);
      if (e.isDirectory()) {
        walk(full, where, depth + 1);
        continue;
      }
      if (!e.isFile()) throw new Error(`${where}: not a regular file (links and special files are not served)`);
      const type = MIME[path.extname(e.name).toLowerCase()];
      if (!type) throw new Error(`${where}: no content type is known for this extension (${Object.keys(MIME).join(' ')})`);
      if (files.size >= MAX_FILES) throw new Error(`more than ${MAX_FILES} files`);
      // (opened without following a link, and the descriptor is looked at: the entry was a file a moment ago, it may be another thing now)
      const fd = fsx.openSync(full, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
      try {
        const st = fsx.fstatSync(fd);
        if (!st.isFile()) throw new Error(`${where}: not a regular file`);
        total += st.size;
        if (total > MAX_BYTES) throw new Error(`more than ${MAX_BYTES >> 20} MiB in all`);
        const body = fsx.readFileSync(fd);
        files.set(where, { body, type, etag: `"${crypto.createHash('sha256').update(body).digest('hex').slice(0, 32)}"` });
      } finally {
        fsx.closeSync(fd);
      }
    }
  };
  walk(dir, '', 0);
  if (!files.has('/index.html')) throw new Error('there is no index.html');
  return files;
}

// 5.1: the headers of every file of the GUI.  The security headers of the API (nosniff, no-referrer, X-Frame-Options, HSTS on https) come from http.js for every answer;
// these replace or add to them.  No inline script or style, no outside origin, no framing, no HTML-string sink (Trusted Types: none is allowed).
export const GUI_HEADERS = Object.freeze({
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'",
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
});

// does If-None-Match name this entity tag?  (a weak comparison, RFC 9110 section 13.1.2; "*" matches anything that exists)
function notModified(header, etag) {
  if (typeof header !== 'string') return false;
  return header.split(',').some((t) => {
    const v = t.trim();
    return v === '*' || v.replace(/^W\//, '') === etag;
  });
}

// -> { status, headers, body, type } for a request the GUI answers, or null when the path is not one of its files (the caller answers 404).  Throws the 405 of a method
// other than GET and HEAD on a path that is.  ui: the map of loadStatic().
export function serveStatic(ui, req) {
  let p;
  try { p = new URL(req.url, 'http://localhost').pathname; } catch { return null; }
  let key;
  if (p === '/') key = '/index.html';
  else if (p.startsWith('/ui/')) key = p.slice(3);
  else return null;
  const f = ui.get(key);
  if (!f) return null;
  if (req.method !== 'GET' && req.method !== 'HEAD') throw new ApiError(405, 'method-not-allowed', 'this resource does not take that method', { headers: { Allow: 'GET, HEAD' } });
  // the page is never kept (it names the scripts, which change with the version); the rest may be kept but must be asked about again (F-23)
  const headers = { ...GUI_HEADERS, ETag: f.etag, 'Cache-Control': key === '/index.html' ? 'no-store' : 'no-cache' };
  if (key !== '/index.html' && notModified(req.headers['if-none-match'], f.etag)) return { status: 304, headers, body: '', type: f.type };
  return { status: 200, headers, body: f.body, type: f.type };
}
