#!/usr/bin/env node
/**
 * url-proxy — a personal web proxy.
 * Open http://localhost:3000, paste a URL, browse the site through this server.
 * HTML, CSS, images, audio and video are fetched by this server and streamed
 * to your browser. A strict content policy is injected into every page so the
 * page's own scripts can only talk back through this proxy, not around it.
 *
 * Zero dependencies. Requires Node 18+.
 *
 * Env:
 *   PORT         (default 3000)
 *   HOST         (default 127.0.0.1 — only this device)
 *   PROXY_TOKEN  (optional) passcode required before the proxy serves anything.
 *                Set this if the server is reachable by anyone but you.
 */

const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns');
const net = require('node:net');
const crypto = require('node:crypto');

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '127.0.0.1';
const TOKEN = process.env.PROXY_TOKEN || '';
const MAX_TEXT_BYTES = 8 * 1024 * 1024; // cap for rewritable HTML/CSS

const CSP = "default-src 'none'; img-src 'self' data: blob:; media-src 'self' data: blob:; "
  + "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
  + "font-src 'self' data:; connect-src 'self'; frame-src 'self'; "
  + "worker-src 'self' blob:; form-action 'self'; manifest-src 'self'; base-uri 'none'";

function escapeHtml(s) {
  return s.replace(/[<>&"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c]));
}

function homePage(authed) {
  const passcode = TOKEN && !authed
    ? '<form action="/auth" method="post"><input name="token" type="password" placeholder="Passcode" autocomplete="off" required><button type="submit">Unlock</button></form>'
    : '';
  const urlForm = !TOKEN || authed
    ? '<form action="/proxy" method="get"><input name="url" type="text" inputmode="url" placeholder="https://example.com" autocomplete="off" autofocus required><button type="submit">Load</button></form>'
    : '<p class="sub">This proxy is locked. Enter its passcode above.</p>';
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>URL Proxy</title>
<style>
  body{font-family:system-ui,-apple-system,sans-serif;background:#0f1115;color:#e8eaed;
       display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}
  .card{background:#191d24;border:1px solid #2a3038;border-radius:16px;padding:32px;
        width:min(560px,92vw);box-shadow:0 12px 40px rgba(0,0,0,.4)}
  h1{margin:0 0 6px;font-size:22px}
  p.sub{margin:0 0 20px;color:#9aa4b2;font-size:14px;line-height:1.5}
  form{display:flex;gap:8px;margin-bottom:10px}
  input{flex:1;padding:12px 14px;border-radius:10px;border:1px solid #2a3038;
        background:#0f1115;color:#e8eaed;font-size:15px}
  button{padding:12px 18px;border:0;border-radius:10px;background:#4f8cff;color:#fff;
         font-size:15px;font-weight:600;cursor:pointer}
  .note{margin-top:14px;font-size:12.5px;color:#7d8794;line-height:1.6}
</style></head><body>
<div class="card">
  <h1>URL Proxy</h1>
  <p class="sub">Paste any web address. This server fetches the page and everything
  on it — images, styles, scripts, audio, video — and streams it to your device.</p>
  ${passcode}
  ${urlForm}
  <p class="note">Pages are forced to load everything through this server, so the
  sites you visit see this server's IP address for their normal web traffic.
  Logins, captchas, some JavaScript-heavy apps and DRM video may not work.</p>
</div>
</body></html>`;
}

const TOOLBAR_CSS = 'position:fixed;top:0;left:0;right:0;z-index:2147483647;display:flex;gap:6px;'
  + 'align-items:center;background:#191d24;border-bottom:1px solid #2a3038;padding:6px 10px;'
  + 'font-family:system-ui,sans-serif;box-sizing:border-box;';
const TOOLBAR_JS = `(function(){
  if (window.__urlProxyBar) return; window.__urlProxyBar = true;
  var pad = document.createElement('div'); pad.style.height='46px';
  var bar = document.createElement('form');
  bar.style.cssText = '${TOOLBAR_CSS}';
  var input = document.createElement('input');
  input.type='text'; input.inputMode='url'; input.placeholder='Paste a URL';
  input.style.cssText='flex:1;padding:6px 10px;border-radius:8px;border:1px solid #2a3038;background:#0f1115;color:#e8eaed;font-size:13px;min-width:0';
  var btn = document.createElement('button'); btn.type='submit'; btn.textContent='Go';
  btn.style.cssText='padding:6px 14px;border:0;border-radius:8px;background:#4f8cff;color:#fff;font-size:13px;font-weight:600';
  bar.appendChild(input); bar.appendChild(btn);
  bar.addEventListener('submit', function(e){ e.preventDefault();
    var u = input.value.trim(); if(!u) return;
    if(!/^https?:\\/\\//i.test(u)) u = 'https://' + u;
    location.href = '/proxy?url=' + encodeURIComponent(u);
  });
  document.documentElement.prepend(pad); document.documentElement.prepend(bar);
})();`;

// ---------- SSRF protection, enforced at connection time ----------
// Every upstream connection (including each redirect hop) resolves DNS through
// this lookup, which refuses private/loopback addresses. That closes the
// DNS-rebinding gap a check-before-fetch approach would leave open.
function isPrivateIp(ip) {
  if (net.isIPv6(ip)) {
    const s = ip.toLowerCase();
    return s === '::1' || s === '::' || s.startsWith('fc') || s.startsWith('fd')
      || s.startsWith('fe80') || s.startsWith('::ffff:') && isPrivateIp(s.slice(7));
  }
  const p = ip.split('.').map(Number);
  return p[0] === 10 || p[0] === 127 || p[0] === 0 ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 169 && p[1] === 254) ||
    (p[0] === 100 && p[1] >= 64 && p[1] <= 127);
}

function guardedLookup(hostname, options, callback) {
  dns.lookup(hostname, options, (err, address, family) => {
    if (err) return callback(err);
    const list = Array.isArray(address) ? address : [{ address, family }];
    for (const entry of list) {
      if (isPrivateIp(entry.address)) {
        return callback(new Error('That address points at a private network and is blocked.'));
      }
    }
    callback(null, address, family);
  });
}

const httpAgent = new http.Agent({ lookup: guardedLookup });
const httpsAgent = new https.Agent({ lookup: guardedLookup });

function upstreamRequest(target, headers) {
  return new Promise((resolve, reject) => {
    // Node skips the custom lookup for IP literals, so check them here.
    if (net.isIP(target.hostname) && isPrivateIp(target.hostname)) {
      reject(new Error('That address points at a private network and is blocked.'));
      return;
    }
    const isHttps = target.protocol === 'https:';
    const mod = isHttps ? https : http;
    const req = mod.request(target, {
      agent: isHttps ? httpsAgent : httpAgent,
      headers,
    }, resolve);
    req.setTimeout(20000, () => req.destroy(new Error('The site took too long to answer.')));
    req.on('error', reject);
    req.end();
  });
}

// ---------- URL rewriting ----------
function proxiedUrl(abs) {
  return '/proxy?url=' + encodeURIComponent(abs);
}

function decodeEntities(value) {
  return value
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#0?39;|&apos;/gi, "'");
}

function resolveRel(value, base) {
  try { return new URL(decodeEntities(value), base).href; } catch { return null; }
}

function rewriteHtml(html, base) {
  const attr = (name) => new RegExp('(\\s' + name + '\\s*=\\s*)(["\\x27])(.*?)\\2', 'gi');
  for (const name of ['src', 'href', 'action', 'poster', 'data-src']) {
    html = html.replace(attr(name), (m, pre, q, val) => {
      if (!val || /^(#|mailto:|tel:|javascript:|data:|blob:)/i.test(val)) return m;
      const abs = resolveRel(val, base);
      return abs ? pre + q + proxiedUrl(abs) + q : m;
    });
  }
  html = html.replace(/(\ssrcset\s*=\s*)(["'])(.*?)\2/gi, (m, pre, q, val) => {
    const out = val.split(',').map((part) => {
      const bits = part.trim().split(/\s+/);
      const abs = bits[0] && resolveRel(bits[0], base);
      if (abs) bits[0] = proxiedUrl(abs);
      return bits.join(' ');
    }).join(', ');
    return pre + q + out + q;
  });
  html = html.replace(/url\(\s*(["']?)([^"')]+)\1\s*\)/gi, (m, q, val) => {
    if (/^(data:|blob:|#)/i.test(val)) return m;
    const abs = resolveRel(val, base);
    return abs ? 'url(' + (q || '') + proxiedUrl(abs) + (q || '') + ')' : m;
  });
  // Force every subrequest the page makes, including from its own JavaScript,
  // to stay on this proxy's origin. Requests to any other origin are blocked
  // by the browser instead of leaking the device IP.
  const cspMeta = '<meta http-equiv="Content-Security-Policy" content="' + CSP + '">';
  if (/<head[^>]*>/i.test(html)) html = html.replace(/<head[^>]*>/i, (m) => m + cspMeta);
  else html = cspMeta + html;
  const inject = '<script>' + TOOLBAR_JS + '<\/script>';
  if (/<body[^>]*>/i.test(html)) html = html.replace(/<body[^>]*>/i, (m) => m + inject);
  else html = inject + html;
  return html;
}

function rewriteCss(css, base) {
  css = css.replace(/url\(\s*(["']?)([^"')]+)\1\s*\)/gi, (m, q, val) => {
    if (/^(data:|blob:|#)/i.test(val)) return m;
    const abs = resolveRel(val, base);
    return abs ? 'url(' + (q || '') + proxiedUrl(abs) + (q || '') + ')' : m;
  });
  css = css.replace(/@import\s+(["'])(.*?)\1/gi, (m, q, val) => {
    const abs = resolveRel(val, base);
    return abs ? '@import ' + q + proxiedUrl(abs) + q : m;
  });
  return css;
}

// ---------- Site cookies ----------
// Default: ANONYMOUS VIEWING. No browser cookies are forwarded to target
// sites and target Set-Cookie headers are dropped. Every proxied page shares
// this server's origin, so forwarding cookies would let any proxied page's
// JavaScript ride your logged-in sessions on other sites through same-origin
// requests. Set SITE_COOKIES=1 only if you alone use the proxy and accept
// that risk (simple logins then work).
const SITE_COOKIES = process.env.SITE_COOKIES === '1';

function rewriteSetCookie(values, targetHost) {
  if (!SITE_COOKIES) return undefined;
  if (!values) return undefined;
  const list = Array.isArray(values) ? values : [values];
  return list.map((c) => {
    let out = c.replace(/;\s*Domain=[^;]*/gi, '').replace(/;\s*Path=[^;]*/gi, '; Path=/');
    out = out.replace(/;\s*Secure/gi, '').replace(/;\s*SameSite=[^;]*/gi, '');
    // HttpOnly: every proxied site shares this origin, so page JavaScript must
    // never read another site's (or its own) cookies via document.cookie.
    return 'ph_' + Buffer.from(targetHost).toString('base64url') + '__' + out + '; HttpOnly';
  });
}

function cookieHeaderFor(incoming, targetHost) {
  if (!SITE_COOKIES || !incoming) return undefined;
  const prefix = 'ph_' + Buffer.from(targetHost).toString('base64url') + '__';
  const kept = incoming.split(';').map((s) => s.trim()).filter((s) => s.startsWith(prefix))
    .map((s) => s.slice(prefix.length));
  return kept.length ? kept.join('; ') : undefined;
}

// ---------- Auth (optional) ----------
function tokenOk(value) {
  if (!TOKEN) return true;
  if (!value) return false;
  const a = Buffer.from(String(value));
  const b = Buffer.from(TOKEN);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function authedFromCookie(req) {
  if (!TOKEN) return true;
  const cookie = req.headers.cookie || '';
  const m = cookie.match(/(?:^|;\s*)url_proxy_auth=([^;]+)/);
  return m ? tokenOk(decodeURIComponent(m[1])) : false;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 64 * 1024) { reject(new Error('Body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function errorPage(message) {
  return '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<body style="font-family:system-ui;background:#0f1115;color:#e8eaed;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0">'
    + '<div style="max-width:480px;padding:24px"><h2>Could not load that</h2><p style="color:#9aa4b2">'
    + escapeHtml(message)
    + '</p><p><a style="color:#4f8cff" href="/">Back</a></p></div></body>';
}

// ---------- Proxy core ----------
async function handleProxy(req, res, target) {
  const headers = {
    'user-agent': req.headers['user-agent'] || 'Mozilla/5.0 (compatible; url-proxy)',
    'accept': req.headers['accept'] || '*/*',
    'accept-language': req.headers['accept-language'] || 'en-US,en;q=0.9',
    'accept-encoding': 'identity', // plain bodies so text can be rewritten and media ranges stay exact
  };
  if (req.headers.range) headers.range = req.headers.range; // media seeking
  const cookie = cookieHeaderFor(req.headers.cookie, target.host);
  if (cookie) headers.cookie = cookie;

  let upstream = await upstreamRequest(target, headers);

  // Sites often set cookies on redirect responses; keep them all.
  let redirectCookies = [];
  let hops = 0;
  while ([301, 302, 303, 307, 308].includes(upstream.statusCode) && hops < 10) {
    const loc = upstream.headers.location;
    if (!loc) break;
    const hopSetCookie = rewriteSetCookie(upstream.headers['set-cookie'], target.host);
    if (hopSetCookie) redirectCookies = redirectCookies.concat(hopSetCookie);
    upstream.resume();
    target = new URL(loc, target);
    if (target.protocol !== 'http:' && target.protocol !== 'https:') {
      throw new Error('The site redirected to a URL type that is not allowed.');
    }
    const hopCookie = cookieHeaderFor(req.headers.cookie, target.host);
    if (hopCookie) headers.cookie = hopCookie; else delete headers.cookie;
    upstream = await upstreamRequest(target, headers);
    hops++;
  }

  const type = upstream.headers['content-type'] || 'application/octet-stream';
  const out = {
    'content-type': type,
    'cache-control': 'no-store',
    'content-security-policy': CSP, // also enforce on non-HTML responses
  };
  for (const h of ['content-range', 'accept-ranges', 'etag', 'last-modified']) {
    if (upstream.headers[h]) out[h] = upstream.headers[h];
  }
  const finalSetCookie = rewriteSetCookie(upstream.headers['set-cookie'], target.host) || [];
  const setCookie = redirectCookies.concat(finalSetCookie);
  if (setCookie.length) out['set-cookie'] = setCookie;

  const isHtml = /\btext\/html\b/i.test(type);
  const isCss = /\btext\/css\b/i.test(type);
  const len = parseInt(upstream.headers['content-length'] || '0', 10);

  if ((isHtml || isCss) && upstream.statusCode >= 200 && upstream.statusCode < 300 && (!len || len <= MAX_TEXT_BYTES)) {
    const chunks = [];
    let size = 0;
    for await (const chunk of upstream) {
      size += chunk.length;
      if (size > MAX_TEXT_BYTES) break;
      chunks.push(chunk);
    }
    let text = Buffer.concat(chunks).toString('utf8');
    const body = isHtml ? rewriteHtml(text, target.href) : rewriteCss(text, target.href);
    res.writeHead(upstream.statusCode, out);
    res.end(body);
    return;
  }

  // Images, fonts, audio, video, downloads: stream straight through, ranges intact.
  if (upstream.headers['content-length']) out['content-length'] = upstream.headers['content-length'];
  res.writeHead(upstream.statusCode, out);
  upstream.pipe(res);
  upstream.on('error', () => res.destroy());
}

const server = http.createServer(async (req, res) => {
  try {
    const here = new URL(req.url, 'http://' + (req.headers.host || 'localhost'));

    if (here.pathname === '/auth' && req.method === 'POST') {
      const body = await readBody(req);
      const token = new URLSearchParams(body).get('token') || '';
      if (tokenOk(token)) {
        res.writeHead(303, {
          'set-cookie': 'url_proxy_auth=' + encodeURIComponent(token) + '; Path=/; HttpOnly; SameSite=Lax',
          'location': '/',
        });
        res.end();
      } else {
        res.writeHead(403, { 'content-type': 'text/html; charset=utf-8' });
        res.end(errorPage('Wrong passcode.'));
      }
      return;
    }

    if (here.pathname === '/' || here.pathname === '/index.html') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(homePage(authedFromCookie(req)));
      return;
    }

    if (here.pathname === '/proxy') {
      if (!authedFromCookie(req)) {
        res.writeHead(401, { 'content-type': 'text/html; charset=utf-8' });
        res.end(errorPage('This proxy needs its passcode first.'));
        return;
      }
      const raw = here.searchParams.get('url');
      if (!raw) { res.writeHead(400, { 'content-type': 'text/html; charset=utf-8' }); res.end(errorPage('Missing url.')); return; }
      let target;
      try {
        if (/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) && !/^https?:\/\//i.test(raw)) throw new Error('scheme');
        target = new URL(/^https?:\/\//i.test(raw) ? raw : 'https://' + raw);
        if (target.protocol !== 'http:' && target.protocol !== 'https:') throw new Error('scheme');
      } catch (e) {
        res.writeHead(400, { 'content-type': 'text/html; charset=utf-8' });
        res.end(errorPage(e && e.message === 'scheme' ? 'Only http and https URLs are allowed.' : 'That is not a valid URL.'));
        return;
      }
      await handleProxy(req, res, target);
      return;
    }

    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('Not found');
  } catch (err) {
    if (!res.headersSent) {
      res.writeHead(502, { 'content-type': 'text/html; charset=utf-8' });
      res.end(errorPage(err.message || 'Upstream fetch failed.'));
    } else res.destroy();
  }
});

server.listen(PORT, HOST, () => {
  console.log('url-proxy running at http://' + HOST + ':' + PORT);
  if (TOKEN) console.log('Passcode protection is ON.');
  const loopback = HOST === '127.0.0.1' || HOST === 'localhost' || HOST === '::1';
  if (!loopback && !TOKEN) {
    console.log('WARNING: reachable beyond this device with NO passcode. Set PROXY_TOKEN or anyone can browse through this proxy.');
  }
});
