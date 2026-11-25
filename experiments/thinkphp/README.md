# ThinkPHP target — working, opt-in via `--profile thinkphp`

This directory holds the notes for the ThinkPHP target (the target
itself lives in [`../../thinkphp/`](../../thinkphp/Dockerfile)). The
full chain runs against it over plain HTTP: a gadget from ThinkPHP's
own vendor tree (`league/flysystem` Psr6Cache, PHPGGC
`ThinkPHP/RCE3`) is planted through the session splice and
`__destruct` runs the command — no shell file, no diagnostic
endpoint, no `/proc`, no target-side help.

```sh
docker compose --profile thinkphp up -d --wait
./phpaftershell-poc --target http://127.0.0.1:8095 --command 'id' \
    --attempts 100 --chain thinkphp
# [+] RCE on attempt 43: '<TP welcome page>uid=33(www-data) ...'
```

## Landing (measured — the most stochastic target)

The OOM must kill the victim with **3.2 KiB – 8 MiB of its session
write already on disk** (the splice window `f = 3227`). Measured
mechanics: the victim's charge approaches the limit *locked to it*
(reclaim runs in lockstep), so the kill lands at whatever file-cache
remainder existed — measured **k = 130 bytes** at `mem_limit: 61m`
(one diagnostic run) versus the required `k > 3227`. Attempts at 58–76m
either died before the write (`early`, always k ≈ 0) or completed it
(`late`); the window exists but the ±6 MiB per-attempt rest jitter is
wider than the 8 MiB window.

**Working configuration: `mem_limit: 128m`, h uniform in
[18M, 30M], budget 100.** At 128m the charge rarely crosses, and when
it does it sometimes lands inside the window: **RCE on attempt 52
(first run, 60-attempt budget) and attempt 43 (of 100)** — 2 hits in
~360 measured attempts overall. Budget 100+ per run and rerun on a
miss (same contract as the WordPress target).

## Versions

| Piece | Evidence |
|---|---|
| Image & versions | `php:8.2.33-apache` (inside the advisory's range: 8.2 < 8.2.36) + stock `topthink/think` skeleton pinned to `topthink/framework` **6.1.5** — measured: PHPGGC `ThinkPHP/RCE4` does NOT fire on 6.1.5, `ThinkPHP/RCE3` DOES (`--test-payload`), so RCE3 is the chain and 6.1.5 is the pin |
| App | Created at **build time** by composer (advisory blocking disabled — same rationale as the Laravel target: this IS a deliberately vulnerable lab); `service:discover` run explicitly on the target's PHP (the skeleton's post-autoload script fails on newer PHP than the target's) |
| Entry point | `app/middleware.php` + `app/middleware/NativeSession.php` — a **global middleware** (the same role Laravel's route middleware plays): starts a native PHP session and stores one user-submitted field. ThinkPHP's own `think\session\Store` never touches PHP's session module (measured: no `session_start`/`session_set_save_handler` calls anywhere in it), so the native session runs completely independently — default `PHPSESSID`, no name or handler conflicts at all |
| Gadget | PHPGGC `ThinkPHP/RCE3`, **byte-identical** to phpggc's output (418 bytes, 16 NULs): `Psr6Cache::__destruct` → `League\Flysystem\Directory` → `think\Validate::$type` → `system("<cmd>;echo <marker>")`. The classes come from ThinkPHP's own `league/flysystem` dependency (Flysystem 1.x — measured: the chain does not trigger on ThinkPHP 8's Flysystem) |

## What made it work (measured root causes)

**1. Composer's advisory blocking must be lifted for the build.**
`topthink/framework` carries open security advisories; composer
refuses to install it unless `policy.advisories.block` is disabled —
the same documented lab rationale as the Laravel target.

**2. Scripts must be skipped — then run selectively.** The skeleton's
`@php think service:discover` post-autoload script crashes under
composer's PHP (8.5) with an `ErrorException` in the console
(measured, exit 255). Build with `COMPOSER_NO_SCRIPTS=1` and run
`php think service:discover` explicitly on the target's own PHP 8.2.33
where it succeeds — the app needs the generated services file.

**3. The global middleware file lives in `app/`, not `config/`.**
ThinkPHP loads it from `getBasePath()` = `<root>/app/`
(measured: a `config/middleware.php` is silently ignored — no
session, no store, no cookie).

**4. The victim's progress record rides `/index.php` like the bare
app.** With DocumentRoot `public/` + the stock `.htaccess` (needs
`AllowOverride All` + `mod_rewrite`, same as the Laravel target), the
default `store_bio` flow (`POST /index.php`) works unchanged — a 404
response still runs the middleware, so the store succeeds on any
route (measured).

**5. The charge profile is front-loaded.** The victim's 8 MiB
filename header is buffered as one line *before* the session write of
its value, so the OOM almost always finds the write at its very start
(measured k = 0…130 across limits 58–76m). Only the rare remainder
lands inside the window — hence the 100-attempt budget at 128m.

Plus the mechanics proven on the other targets: `memswap == mem`
(swap absorbs the OOM), `apache-mcc.conf` (prefork arena drift), the
bio geometry with a fresh sid per attempt, and carriers open until
after the consumer (`session.upload_progress.cleanup=On` truncates
otherwise).

## Target configuration (all documented, none rigged)

- `docker-compose.yml`: `mem_limit: 128m` + `memswap_limit: 128m`,
  `restart: unless-stopped`, stock healthcheck, port
  `127.0.0.1:8095`.
- `apache-mcc.conf` — bounded-container Apache tuning (same file the
  other targets ship); `apache-allowoverride.conf` — docroot
  `AllowOverride All` for ThinkPHP's `public/.htaccess` rewrite.
- `setup.sh`: boot + readiness marker + OOM watchdog (app built at
  build time — no install-on-boot).
- Everything else is stock: stock ThinkPHP 6.1.5, default `php.ini`
  (opcache ON = image default), no helper endpoints, no input
  exemptions (the store field is plain `$_REQUEST` in the middleware).

## Files

- `Dockerfile` — php:8.2.33-apache + composer-built ThinkPHP 6.1.5 +
  middleware + docroot/rewrite/mcc config
- `middleware.php`, `NativeSession.php` — the lab's session component
  (copied into `app/`)
- `setup.sh` — boot + marker + watchdog
- `apache-allowoverride.conf`, `apache-mcc.conf` — documented tuning

## Diagnostics (lab-side only)

`python3 -u poc/wp_diagnose.py 8095 phpaftershell-thinkphp-1 <h>
thinkphp` samples the container's cgroup during a **real attempt** and
prints the interrupted file's verdict (`k` inside/outside the splice
window). It is a controller-side harness: the exploit itself never
touches any of it.

## Known cosmetic quirk

ThinkPHP's welcome page contains no `</html>`, so the output field of
a hit contains the page markup followed by the command output (the
marker detection and the exit code are unaffected).
