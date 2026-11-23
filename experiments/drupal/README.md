# Drupal 7 target — working, opt-in via `--profile drupal`

This directory holds the notes for the Drupal target (the target
itself lives in [`../../drupal/`](../../drupal/Dockerfile)). The full
chain runs against it over plain HTTP: a gadget from Drupal's own core
(`SchemaCache`, PHPGGC `Drupal7/RCE1`) is planted through the session
splice, its `__destruct` poisons `cache_form`, and a second request
rebuilds the poisoned form through Drupal's AHAH endpoint — no shell
file, no diagnostic endpoint, no `/proc`, no target-side help.

```sh
docker compose --profile drupal up -d --force-recreate --wait
./phpaftershell-poc --target http://127.0.0.1:8093 --command 'id' \
    --attempts 40 --chain drupal
# [+] RCE on attempt 1: 'uid=33(www-data) gid=33(www-data) ...'
```

## Landing protocol (measured)

The landing is stochastic (the OOM must interrupt the pwrite inside
the splice window) and, unlike the other targets, it is calibrated
against a **freshly started target**: the first run after a
`--force-recreate` lands within attempts 1–3 — measured **8/8
first-runs** (attempts 1, 1, 1, 1, 3, 1, 1, 1 at `mem_limit: 100m`,
h in [13M, 23M]).

A warmed target has not landed in measurement (~800 attempts across
`mem_limit` 96–108m): once the target's page cache is warm the charge
band shifts by roughly the warm code-cache delta, and neither the
limits tried nor the h zone recovered it. The warm band remains open
research; operationally, restart the target before a run (target
lifecycle — the exploit itself still learns only from natural HTTP
responses). Budget 40 attempts per run.

## Versions

| Piece | Evidence |
|---|---|
| Image & versions | `php:8.2.33-apache` + stock Drupal 7.98 — the upper bound PHPGGC advertises for `Drupal7/RCE1` (`7.0.8 <= 7.98`); newer 7.x adds a `cache_form` guard to `DrupalCacheArray::__destruct` that would silence the chain (measured) |
| Install | Stock web installer driven over HTTP at **build time** (`install.php`: the same form fills and `op=do` batch polls a browser sends) — the install peaks at ~118 MiB (measured), above any sane runtime limit, so it runs where there is no cgroup bound. SQLite (Drupal ships the driver; PDO SQLite is in the stock image) |
| Entry point | `settings-lab-snippet.php`, appended to `settings.php` after the install — the file Drupal auto-loads on every request (its `mu-plugin` equivalent): starts a native PHP session before Drupal installs its own save handler, provides the anonymous `$user` object Drupal normally loads inside its own DB session read, and stores one user-submitted field |
| Gadget | Drupal core's own `SchemaCache::__destruct` (PHPGGC `Drupal7/RCE1`) persists a forged form to `cache_form`; the trigger request `POST /?q=system/ajax` with `form_build_id=DrupalRCE` rebuilds it → `#process` → `drupal_process_attached` → `call_user_func_array('system', …)`. Success = the marker in the trigger response |

## What made it work (measured root causes)

**1. The payload cannot ride a multipart header line.** The chain's
protected properties serialize as `\0*\0…` (8 NUL bytes), and PHP's
`rfc1867` header-line reader cuts the line at the first NUL
(measured: the stored filename ended exactly at the first
`\0`). WordPress' payload has no NULs (public properties) and
Laravel's rides a body value; Drupal's therefore uses the **bio body
value** (raw bytes survive there — proven by Laravel's 14-NUL payload)
with the bare-app geometry. Side effect: no `FILLUNIT` alignment is
needed at all.

**2. The stock payload needs `#parents`.** A form that never went
through `form_builder` has no `#parents`, and 7.98's `form_builder`
derives `#id` from it (`form.inc:1878`, measured `TypeError`). The
payload matches phpggc's output plus `#parents => array()` in both
`keysToPersist` and `storage`.

**3. Drupal's DB session layer must be bypassed — honestly.**
Drupal registers its own save handler (DB sessions), which would never
read the spliced session *file*. The snippet starts the native session
first; PHP then refuses every later session mutation (measured
warnings: `session_name`/`session_set_save_handler`/`session_id`
"cannot be changed when a session is active"), so the target behaves
as a pure file-session site. `$user` is provided because Drupal loads
it inside its own DB session read — and the assignment is skipped
while `install.php` runs (its early tasks execute pre-DB;
`user_role_permissions()` would query it — measured fatal).

**4. The installer breaks under opcache.** Drupal 7's
`install_profile_modules` batch is known to die with "Call to
undefined function `field_attach_load()`" under opcache
(drupal.org #481758); the stock php.net default (opcache off — the
Docker image enables it) is restored, and errors are hidden via the
standard production setting `$conf['error_level'] = 0` (the native
session makes Drupal's own session calls warn on every request).

**5. Baseline drift: the prefork children accumulate allocator
arenas.** Without `MaxConnectionsPerChild` the rest charge climbed
from 17 MiB to **70 MiB within a single 60-attempt run** — every
victim then crossed the limit during its page load (all-early runs
regardless of h). Fix: the same `apache-mcc.conf` the WordPress and
Laravel targets ship.

**6. Session-file hygiene.** Reusing the sid across attempts breaks
the victim: its progress write dies on the previous attempt's leftover
file state (measured: **63% of reused-sid attempts die within 80 ms vs
27% with a fresh sid**), and every reused-sid run missed (0/360). A
fresh sid per attempt (like the bare app and Laravel) with a boot-time
`sess_*` sweep is the final policy.

Plus the mechanics re-checked from the other targets: two-carrier
growth is *not* needed here (the bio geometry grows the file by the
victim's rewrite, same as the bare app), carriers stay open until after
the consumer (`session.upload_progress.cleanup=On` truncates otherwise),
and `memswap == mem` (swap absorbs the OOM — root cause 1 of the
WordPress write-up).

## Target configuration (all documented, none rigged)

- `docker-compose.yml`: `mem_limit: 100m` + `memswap_limit: 100m`
  (no swap headroom), `restart: unless-stopped`, stock healthcheck,
  port `127.0.0.1:8093`.
- `apache-mcc.conf` — bounded-container Apache tuning (root cause 5);
  `opcache-off.ini` — stock php.net default + install-batch breakage
  (root cause 4). Both are plain Apache/PHP directives with the same
  justification the other targets document.
- `setup.sh`: boot + session-file sweep + an apache watchdog (the same
  pattern the other lab targets use).
- Everything else is stock: default `php.ini`, stock Drupal 7.98, no
  helper endpoints, no input exemptions (the CSRF-free `bio` store is
  plain `$_REQUEST` in the settings snippet — no target exemption is
  involved because no CSRF protection ever covered it).

## Files

- `Dockerfile` — Drupal 7.98 on `php:8.2.33-apache`, GD, build-time
  install, settings snippet, mcc/opcache config
- `install.php` — the HTTP installer driver (browser-equivalent form
  fills + `op=do` batch protocol, manual redirect handling so no
  `Set-Cookie` is lost — the batch token is derived from `session_id()`)
- `settings-lab-snippet.php` — the session component (appended post-install)
- `setup.sh` — boot + sweep + watchdog
- `apache-mcc.conf`, `opcache-off.ini` — documented tuning

## Diagnostics (lab-side only)

`python3 -u poc/wp_diagnose.py 8093 phpaftershell-drupal-1 <h> drupal`
samples the container's cgroup during a **real attempt** (it samples
the newest session file, so fresh-sid chains are covered). It is a
controller-side harness: the exploit itself never touches any of it.
