# Joomla 5 target — working, opt-in via `--profile joomla`

This directory holds the notes for the Joomla target (the target
itself lives in [`../../joomla/`](../../joomla/Dockerfile)). The full
chain runs against it over plain HTTP: a gadget from Joomla's own CMS
tree (`FormattedtextLogger`, PHPGGC `Joomla/FW1`) is planted through
the session splice, its `__destruct` writes this run's random shell,
and the exploit probes that shell — no diagnostic endpoint, no
`/proc`, no target-side help.

```sh
docker compose --profile joomla up -d --wait
./phpaftershell-poc --target http://127.0.0.1:8094 --command 'id' \
    --attempts 40 --chain joomla
# [+] RCE on attempt 1: '#Date: ... #Fields: f
#                        uid=33(www-data) gid=33(www-data) ...'
```

## Landing (measured)

The most reliable framework target so far: **6/6 runs landed within
the first 5 attempts** (attempts 1, 2, 5, 1, 5 across three
recreated runs, one warm run and the initial run) at
`mem_limit: 128m`, h in the bare-app bracket. Unlike Drupal, warm
targets land too — no restart protocol needed. Budget 40 attempts.

## Versions

| Piece | Evidence |
|---|---|
| Image & versions | `joomla:5.2.1-php8.2-apache` — Joomla **5.2.1** is the *last* version where PHPGGC's `Joomla/FW1` works (`3.9.0 <= 5.2.1`; fixed in 5.2.2's `__wakeup` guard, and PHP 8.4 closes the fast-destruct escape), and the image's **PHP 8.2.27** (built 2024-12-25, never re-pushed) is inside CVE-2026-126714's range (8.2 < 8.2.36) |
| Install | The official image's own **env-driven CLI auto-installer** (`php installation/joomla.php install …`) against the `joomla-db` MariaDB sidecar on first boot — stock mechanism, no web-form scripting |
| Entry point | `plugins/system/labsession` — a system plugin installed through the image's **own extension mechanism** (`JOOMLA_EXTENSIONS_PATHS` → `cli/joomla.php extension:install`) and published the way the admin UI would. It stores one user-submitted field in Joomla's native session: the ordinary form → session behaviour a real session-using plugin provides. No endpoint, no report, no diagnostic |
| Gadget | PHPGGC `Joomla/FW1`, **byte-identical** to phpggc's output (398 bytes, 12 NULs): `FormattedtextLogger::__destruct` → `File::write(path, …)` where the path is this run's random `/s_*.php` shell. Success = the probe of that shell (`?c=id`) |

## What made it work (measured root causes)

**1. Joomla's session handler must be filesystem — and `'file'` is
not a valid value.** The stock configuration ships
`$session_handler = 'database'` (sessions in `#__session` — a storage
the session splice can never reach). Joomla's own documented option
for native file sessions is **`'filesystem'`** (measured: `'file'`
throws `The "file" session handler is not recognised.`);
`setup.sh` flips that one line after the stock install.

**2. Nothing may hold the session before Joomla names it.** Joomla's
`NativeStorage::setName()` throws `Cannot change the name of an
active session` when it finds a session already active under a
different name — so the "start the session early from configuration.php"
approach that works for Drupal **cannot** work here. The target
instead lets Joomla run its own sessions from the start; the exploit
speaks Joomla's cookie name (below).

**3. Joomla's session cookie name is a per-installation hash.**
Measured: `Set-Cookie: 0e3ac5dd5f0474f8f4a1d89e4c970ddc=<sid>` — 32
lowercase hex, stable across requests, different per install. The
exploit discovers it the natural way (the `Set-Cookie` of a plain
`GET /`) and uses it for the store and the consumer; the
upload-progress layer underneath keeps using `PHPSESSID` (PHP reads
the *ini* name before any script runs), and both cookie names carry
the **same sid value** → the same `sess_<sid>` file.

**4. The installed plugin is not published.** The image's
`extension:install` leaves plugins disabled (stock Joomla behaviour —
the admin UI publishes them as a second step): measured
`enabled=0` and the store silently ignored. `setup.sh` publishes the
row and clears the cache, the way the admin UI would.

**5. The payload cannot ride `$_POST`-shaped guesses — it rides the
session directly.** With the lab plugin storing `bio`, the geometry is
the bare app's: carrier + `bio|s:8000000:"<payload>"` + the victim's
rewrite growing the file ~8 MiB.

Plus the mechanics proven on the other targets: `memswap == mem`
(swap absorbs the OOM), `apache-mcc.conf` (measured drift 59 → 70 MiB
of a 128m limit within one run without it), carriers open until after
the consumer (`session.upload_progress.cleanup=On` truncates
otherwise), fresh sid per attempt (a reused file state made the
victim's progress write fail on the Drupal measurements — same risk
profile here, same policy).

## Target configuration (all documented, none rigged)

- `docker-compose.yml`: `joomla` + `joomla-db` (MariaDB 11) behind the
  profile; `mem_limit: 128m` + `memswap_limit: 128m`; the stock env
  installer (`JOOMLA_*`) and the official extension path
  (`JOOMLA_EXTENSIONS_PATHS`); port `127.0.0.1:8094`.
- `apache-mcc.conf` — bounded-container Apache tuning (root cause 5).
- `setup.sh`: waits for the official entrypoint's install, flips the
  one `session_handler` line, publishes the plugin, marks readiness,
  holds Apache under an OOM watchdog.
- Everything else is stock: stock Joomla 5.2.1, stock installer, no
  helper endpoints, no CSRF or input exemptions (the store field is
  plain `$_REQUEST` in the plugin — no Joomla protection ever covered
  it).

## Files

- `Dockerfile` — pinned official image + the lab plugin zipped for the
  official extension installer + mcc + boot wrapper
- `plg_system_labsession/` — the session-using system plugin
  (manifest + code)
- `setup.sh` — install completion: handler line, plugin publish,
  marker, watchdog
- `apache-mcc.conf` — documented Apache tuning

## Diagnostics (lab-side only)

`python3 -u poc/wp_diagnose.py 8094 phpaftershell-joomla-1 <h> joomla`
samples the container's cgroup during a **real attempt** (newest
session file). It is a controller-side harness: the exploit itself
never touches any of it.
