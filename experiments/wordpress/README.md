# WordPress target — working, opt-in via `--profile wp`

This directory holds the WordPress target for the phpAfterShell chain.
The full chain runs against it over plain HTTP: `WP_HTML_Token` (a class
from WordPress core, PHPGGC `WordPress/RCE2`) is planted through the
session splice and `__destruct` runs the command — no shell file, no
diagnostic endpoint, no `/proc`, no target-side help.

```sh
docker compose --profile wp up -d --wait
./phpaftershell-poc --target http://127.0.0.1:8091 --command 'id' \
    --attempts 80 --chain wordpress
# [+] RCE on attempt 63: 'uid=33(www-data) gid=33(www-data) ...'
```

The landing is stochastic (the OOM must interrupt the pwrite inside the
splice window), so each run is a per-run lottery: `RCE on attempt 63`
of an 80-attempt run, and 8/12 in the lab-side harness at the
calibrated pressure. Budget 80+ attempts (each takes ~5 s) and rerun on
a miss — the mechanism is proven, only the interruption's position is
random. The target
stays **behind a profile** so the default lab and CI (the four green
rows in the top-level README) are untouched.

## Versions

| Piece | Evidence |
|---|---|
| Image & versions | `wordpress:6.4.1-php8.2-apache` — WP 6.4.1 + PHP 8.2.13, both inside the advisory's ranges |
| First-boot install | `setup.sh`: entrypoint init → `wp core install` (idempotent) → readiness marker; healthcheck gates on marker + port |
| Entry point | `lab-session.php` mu-plugin: native `session_start()` on `init` + one user field stored in the session — the behaviour of a very common class of real plugins, **no diagnostics, no endpoints** |
| Gadget | WordPress core's own `WP_HTML_Token::__destruct` → `system("<cmd>;echo <marker>")`; success = the marker in the consumer response |

## What made it work (three measured root causes)

**1. Swap absorbed the OOM.** Docker's default `memory-swap` is 2×
`memory`, so the memcg swapped anonymous charge out instead of killing
the writer: `memory.swap.current` grew while the pwrite completed and
the file was never interrupted. Fix: `memswap_limit == mem_limit`
(`memory.swap.max = 0`). Containers without swap headroom are also the
Kubernetes default (`memory` + `memory-swap` set equal). Immediately
after the fix, real splice verdicts appeared inside the window
(k = 131072, 139264, 4247552, 925696 …).

**2. `wp_magic_quotes()` corrupts a payload in `$_POST`.** WordPress
runs `addslashes()` over every `$_POST` value, so every `"` of a payload
stored via `$_POST['bio']` lands in the session file as `\"`,
`session_decode()` aborts ("Failed to decode session object") and the
gadget never materialises (measured: bare app `bio|s:8000000:"…"` vs WP
`bio|s:8000022:"…\"…"`, +22 bytes). Fix: the payload rides the
**upload-progress `filename`**, which PHP's multipart parser writes
raw — it unescapes `\"` itself (measured: `filename="a\"b"` →
`s:7:"a"b"` in the record). `$_FILES` is the one input WordPress does
not slash.

**3. PHP splits over-long header lines at `FILLUNIT` (5120 bytes).**
`main/rfc1867.c` reads headers through a 5 KiB buffer: a
`Content-Disposition` line longer than that is returned in 5120-byte
pieces, and a continuation piece containing a `:` is parsed as a *new*
header — which flushes everything accumulated so far and truncates the
multi-MB filename at a 5120-byte boundary (measured: cut at line offset
7993232 = 5120 × 1561; an all-`A` filename survives because it has no
`:`). Fix: `lab.wp_align_geometry()` shifts `LEN2` so the payload's
structural tail starts exactly on a piece boundary, preceded by one
space — a continuation piece that starts with whitespace is appended
unconditionally.

Plus the two mechanics that were already proven for the bare app and
needed re-checking here:

- **Two carriers.** The payload lives in a *second* progress record
  (token `TOKEN2`) while the victim rewrites the small first record
  (`TOKEN`), so the session file **grows by ~8 MiB** during the pwrite
  (fresh page cache → new memcg charge). With a single record
  `|R| − |C| = −STRUCT` — the file never grows, the write adds no
  charge, and nothing ever crosses the limit inside the window.
- **Charge band.** `mem_limit: 172m` + 8 held fillers; the driver
  samples h uniformly in `[38M, 54M]` because WordPress's death signals
  cannot separate "pressure too high" from "past the window" (measured:
  no-write deaths 1.36–1.89 s vs in-write deaths 1.62–1.90 s — fully
  overlapping), so bisecting on them thrashes.

## Target configuration (all documented, none rigged)

- `docker-compose.yml`: `mem_limit: 172m` + `memswap_limit: 172m`
  (no swap headroom — see root cause 1), `restart: unless-stopped`,
  a stock WordPress healthcheck.
- `apache-mcc.conf`: `MaxConnectionsPerChild 1` + a pinned 3-child
  pool — Apache's own prefork guidance for bounded containers (children
  accumulate allocator arenas otherwise: measured 84 MiB of unreclaimable
  anon at rest) and a fixed pool keeps the cgroup baseline stable
  within the width of the landable band. Both directives are documented
  Apache core/MPM settings; nothing here is PHP- or exploit-specific.
- `setup.sh`: first-boot install, readiness marker, and an apache
  watchdog (the same pattern the other lab targets use) so an
  OOM-killed master costs a 1–2 s restart instead of a full
  re-bootstrap.
- Everything else is stock: default `php.ini`, default WordPress, no
  ini edits, no helper endpoints.

## Files

- `Dockerfile` — WP 6.4.1 + wp-cli + the mu-plugin baked into the skeleton
- `lab-session.php` — the session/form mu-plugin (copied into the skeleton at build)
- `setup.sh` — boot: entrypoint init → install → marker → hold apache
- `apache-mcc.conf` — bounded-container Apache tuning (mounted)

## Diagnostics (lab-side only)

`python3 -u poc/wp_diagnose.py [port] [container] [h]` samples the
container's cgroup (charge / file / anon / OOM counters) during a **real
attempt** — exactly like `poc/charge_trace.py` does for the bare app.
It is a controller-side harness: the exploit itself never touches any
of it.
