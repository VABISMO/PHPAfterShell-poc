# Laravel target — working, opt-in via `--profile laravel`

This directory holds the Laravel target for the phpAfterShell chain. The
full chain runs against it over plain HTTP: a gadget from Laravel's own
vendor tree (`Illuminate\Broadcasting\PendingBroadcast`, PHPGGC
`Laravel/RCE9`) is planted through the session splice and `__destruct`
runs the command — no shell file, no diagnostic endpoint, no `/proc`,
no target-side help.

```sh
docker compose --profile laravel up -d --wait
./phpaftershell-poc --target http://127.0.0.1:8092 --command 'id' \
    --attempts 80 --chain laravel
# [+] RCE on attempt 23: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)'
```

The landing is stochastic (the OOM must interrupt the pwrite inside the
splice window), exactly like the WordPress target: budget 80+ attempts
(each takes ~5 s) and rerun on a miss — the mechanism is proven, only
the interruption's position is random. Measured **RCE on attempt 14, 23
and 45 in three consecutive runs** (all exited 0 within their budgets).
The target stays **behind a profile** so the default lab and CI are
untouched.

## Versions

| Piece | Evidence |
|---|---|
| Image & versions | `php:8.4.27-apache` + Laravel 11.57.1 created at build time (composer, no DB) — PHP inside the advisory's range |
| Entry point | `app/Http/Middleware/NativeSession.php` — a route middleware that starts a native PHP session on every request, representing the very common class of Laravel packages that do the same (carts, session-based auth bridges). It reports nothing and provides no endpoint or diagnostic |
| Routes | `routes-web.php`: `GET /` (consumer — any page that runs `session_start()` materialises the planted object) and `POST /bio` (ordinary form field → session store) |
| Gadget | PHPGGC `Laravel/RCE9` (5.4.0 ≤ 9.1.8+): `PendingBroadcast::__destruct` → `Bus\Dispatcher` → `queueResolver` = `system(BroadcastEvent::$connection)`. Verified with `php phpggc Laravel/RCE9 --test-payload` **against the shipped Laravel 11 + Monolog 3.13** (SUCCESS), and the embedded payload is **byte-identical** to phpggc's output (340 bytes, 14 NUL protected-property prefixes) |

## What made it work (measured root causes)

**1. Laravel middleware must be a class, not a closure.**
`Route::middleware()` casts every entry to `(string)`; a Closure throws
`Object of class Closure could not be converted to string` and every
route 500s (measured in `laravel.log`). The session middleware is
therefore a normal class.

**2. Laravel must be served the way Laravel is always served.**
Three stock-image gaps, each measured as a hard failure: DocumentRoot
must be `public/` (the framework's own docs), `AllowOverride All` for
the docroot (stock Apache sets `AllowOverride None` for `/var/www/`, so
`public/.htaccess`'s front-controller rewrite never runs → every
non-file route 404s at Apache), and `mod_rewrite` must be loaded (the
image doesn't load it, and `.htaccess` guards its rules in
`<IfModule mod_rewrite.c>` → silent 404). All three are stock
deployment steps, nothing PHP- or exploit-specific.

**3. CSRF without any target exemption.**
`VerifyCsrfToken` rejects a bare POST with 419. It accepts the
`XSRF-TOKEN` cookie echoed back in an `X-XSRF-TOKEN` header (Laravel
decrypts it server-side and compares with the session token), so the
exploit performs exactly the round-trip any browser client performs:
`GET /` → collect cookies → `POST /bio` with both cookies + header.

**4. Baseline drift: the prefork children accumulate allocator
arenas.** Without `MaxConnectionsPerChild` (stock default 0 =
unlimited) long-lived children keep the arenas of every buffered
multipart request. Measured: the container's rest charge climbed from
~40 MiB to **104 MiB of a 112 MiB limit** within a few attempts, so
the victim's page load was OOM-killed before its write on *every*
attempt (all-`early` runs). Fix: `apache-mcc.conf` — the same
documented Apache tuning the WordPress target ships
(`MaxConnectionsPerChild 1` + a pinned spare pool). After it: rest
~35–50 MiB and stable across requests (verified: 10 consecutive GETs
change the charge by <2 MiB).

**5. Charge band: `mem_limit: 112m` + uniform h sampling in
[6M, 18M].** Laravel rests far above the bare app (framework boot +
opcache SHM: ~47 MiB vs ~22 MiB), so the bare app's 64m leaves the
victim no headroom — measured at 96m the load peak crosses the limit
regardless of h, and at 112m the write runs *pinned at the limit*
while reclaim absorbs it through the file-cache cushion. Above ~18M
the charge crosses during the parse surge (`early`, 35–80 ms deaths);
below ~6M the write finishes uncrossed (`nooom`/`late`). At one h
**both** `early` and `late` occur across attempts — the reclaimable
file-cache cushion jitters ±5 MiB per attempt, wider than the
bisection's h steps — so, like WordPress, the driver samples the whole
plausible range uniformly instead of steering on the death signals.

**6. The output lives between two `</html>`s.** The gadget fires at
shutdown: `system()` output + marker are appended after the welcome
page, and Laravel then renders a full HTML exception response (the
chain's `Dispatcher` throws *after* the command ran). Splitting on the
*last* `</html>` lands inside that trailing page and yields an empty
output — the extractor anchors on the last `</html>` **before** the
marker (behaviour-identical for the other chains).

Plus the mechanics proven on the other targets and re-checked here:

- **Two carriers.** The payload rides the `bio` record while the
  victim rewrites its own progress record, so the session file **grows
  by ~8 MiB** during the pwrite (fresh page cache → new memcg charge).
- **Carriers stay open until after the consumer.**
  `session.upload_progress.cleanup=On` truncates the session file when
  a carrier closes mid-upload (measured: 8 MiB → 503 KiB).
- **Transient session lock (~1/6).** The victim occasionally waits
  >3 s for the progress record the carrier holds; the attempt is
  retried inside the budget (measured: 5/6 runs write the record
  within 500 ms).

## Target configuration (all documented, none rigged)

- `docker-compose.yml`: `mem_limit: 112m` + `memswap_limit: 112m` (no
  swap headroom — same root cause as the WordPress target: swap
  absorbs the OOM), `restart: unless-stopped`, a stock healthcheck.
- `apache-mcc.conf` — bounded-container Apache tuning (see root cause
  4); `apache-allowoverride.conf` — docroot `AllowOverride All` (see
  root cause 2). Both are plain Apache directives with the same
  justification the WordPress target documents.
- `setup.sh`: boot + an apache watchdog (the same pattern the other
  lab targets use) so an OOM-killed master costs a 1–2 s restart.
- Everything else is stock: default `php.ini` (opcache ON = image
  default), stock Laravel, no helper endpoints, no input exemptions.

## Files

- `Dockerfile` — Laravel 11 on `php:8.4.27-apache`, served from
  `public/`, rewrite + overrides enabled, middleware baked in
- `routes-web.php` — consumer + store routes (copied into the app)
- `app/Http/Middleware/NativeSession.php` — the session middleware
- `setup.sh` — boot + watchdog
- `apache-allowoverride.conf`, `apache-mcc.conf` — documented Apache
  tuning (enabled at build)

## Diagnostics (lab-side only)

`python3 -u poc/wp_diagnose.py [port] [container] [h] [chain]`
samples the container's cgroup (charge / file / anon / OOM counters)
during a **real attempt** — e.g.
`python3 -u poc/wp_diagnose.py 8092 phpaftershell-laravel-1 10000000 laravel`.
It is a controller-side harness: the exploit itself never touches any
of it.
