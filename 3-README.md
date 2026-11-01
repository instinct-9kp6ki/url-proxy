# url-proxy

A personal web proxy in a single file. Open it in your browser, paste a URL,
and the server fetches the page — HTML, CSS, images, audio and video — and
streams it to your device.

Zero dependencies. Just Node 18+.

## Run it

```bash
node server.js
```

Then open http://localhost:3000 and paste a URL.

Settings (environment variables):

- `PORT` — default `3000`
- `HOST` — default `127.0.0.1`, so only this device can reach it. Set
  `0.0.0.0` only if you deliberately run it somewhere you want to reach from
  other devices.
- `PROXY_TOKEN` — optional passcode. When set, the proxy stays locked until
  the passcode is entered. Always set this if anyone but you can reach the
  server — without it, whoever finds the address can browse through it.
  The server prints a warning on startup if it is exposed without one.

## Keeping it running

Any machine that stays on works: a laptop, a home server, a Raspberry Pi, or
a free Node tier on a hosting service (start command `node server.js`, set
`HOST=0.0.0.0` and `PROXY_TOKEN=<something secret>` in its settings). Reach
it over HTTPS when it is not on your own machine.

## Privacy: what the sites you visit can see

Every page is served with a strict content policy that forces the page's own
scripts, images, media and connections to go through this server — requests
to any other address are blocked by your browser rather than sent directly.
So for normal web traffic, sites see this server's IP address.

Two honest exceptions:

- WebRTC (used by some video-chat and streaming sites) can reveal your real
  IP and cannot be blocked by a proxy page. If a site needs WebRTC, use a VPN
  instead.
- This is anonymous viewing: your browser's cookies and logins are never
  forwarded to the sites you open, so every site sees a fresh visitor.
  All proxied pages share one origin; never forwarding cookies is what keeps
  one site from riding your sessions on another. (If you self-host for
  yourself alone, SITE_COOKIES=1 turns simple logins back on — only do that
  on a server nobody else can reach.)

## What works

- Pages, stylesheets, scripts, images, fonts
- Audio and video streaming, including seeking (range requests pass through)
- Redirects and navigation stay inside the proxy via the bar at the top

## What doesn't

- Sites behind a login (your cookies are not forwarded, by design)
- Sites with bot protection or captchas (Cloudflare challenges, etc.)
- Some JavaScript-heavy apps that build requests in code
- WebSockets (live chat, real-time apps)
- DRM video (Netflix, etc.)

## Safety notes

- Only `http`/`https` targets. Addresses that resolve to private or internal
  networks are refused when the connection is made, so the proxy cannot be
  used to reach inside your network — including through redirects or DNS
  tricks.
- Nothing is cached or logged beyond normal process output.
- Run it only on infrastructure you control: whoever runs the proxy can see
  the traffic passing through it.
