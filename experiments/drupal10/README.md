# Drupal 10 target — working, opt-in via `--profile drupal10`

This directory holds the notes for the modern Drupal target (the
target itself lives in [`../../drupal10/`](../../drupal10/Dockerfile)).
The full chain runs against it over plain HTTP: a gadget from Drupal's
own vendor tree (`guzzle`'s `FileCookieJar`, PHPGGC `Guzzle/FW1`) is
planted through the session splice, its `__destruct` writes this run's
random shell, and the exploit probes that shell — no diagnostic
endpoint, no `/proc`, no target-side help.

```sh
docker compose --profile drupal10 up -d --wait
./phpaftershell-poc --target http://127.0.0.1:8096 --command 'id' \
    --attempts 40 --chain drupal10
# [+] RCE on attempt 1: '[{"Expires":1,...,"Value":"uid=33(www-data) ..."}]'
```

## Landing (measured)

**5/5 runs landed**: the first four fresh runs on attempt 1, 1, 1 and
17, and a warm run (no restart) on attempt 14 — at `mem_limit: 128m`,
h uniform in [6M, 18M]. The probe output carries the JSON cookie
envelope Guzzle writes around the shell (cosmetic only — PHP executes
the `<?php … ?>` block inside it).

## Versions

| Piece | Evidence |
|---|---|
| Image & versions | Official `drupal:10.6.17-php8.3-apache` — **PHP 8.3.35** (built 2026-09-25, before the advisory) is inside CVE-2026-126714's range (8.3 < 8.3.37). Current, supported Drupal — no EOL objection unlike the D7 target |
| Install | Drupal's **own web installer** driven over HTTP at BUILD time (same reasoning as the D7 target: the stock install peaks above any sane runtime limit). SQLite; `settings.php` is written by the installer, the lab's snippet is appended after it |
| Entry point | `settings-lab-snippet.php` appended to `settings.php` (the file Drupal auto-loads on every request): starts a native PHP session (files handler — the only storage the splice can reach; PHP refuses Drupal's later handler/name changes, measured), stores one user-submitted field, and **closes the session immediately** (see root cause 2) |
| Gadget | PHPGGC `Guzzle/FW1`, **byte-identical** to phpggc's output (469 bytes): `FileCookieJar::__destruct` → JSON-encodes the cookie (single-quoted `$_GET['c']` survives JSON untouched) → writes `/s_*.php`. Success = the probe of that shell. Guzzle ships with Drupal core (`--test-payload` SUCCESS measured against this exact image) |

## What made it work (measured root causes)

**1. The obvious modern-Drupal chain does NOT work here.**
PHPGGC's `Drupal9/RCE1` (8.9.6 – 9.5.10+) needs
`Laminas\Diactoros\RelativeStream` — bundled in Drupal 8/9 but
**dropped from Drupal 10/11** (measured: absent from core's
composer.json and vendor). The other modern-Drupal chains (AT1, SQLI1,
SSRF1, XXE1, FD1) are not RCE. `Guzzle/FW1` — pure vendor, present in
every Drupal 10 — is the chain that fits.

**2. Drupal's session service rebuilds `$_SESSION` — the open session
must be closed up front.** With the session left active, D10's Symfony
`SessionManager` starts its own storage later in the request and
rebuilds `$_SESSION` from its *database* handler; the file session's
contents (the carrier's progress record, the stored field) are wiped
and the session is destroyed (measured: `Set-Cookie: PHPSESSID=deleted`,
the record zeroed to 0 bytes). The snippet therefore does
`session_start()` → store → **`session_write_close()`**: our sid's file
is flushed and frozen immediately; the rest of the request runs its own
separate session (which Drupal may destroy harmlessly), while the
consumer's `session_start()` still materialises the planted object at
decode time — its destructor fires at shutdown regardless of what the
framework does with `$_SESSION` afterwards.

**3. The installer driver needs a User-Agent and a client-side batch
protocol.** Without a `User-Agent`, D10's `install_begin_request`
hits `str_contains(null)` and the deprecation text is printed *in
front of* the batch's JSON (measured: `json_decode` fails on the
prefix). And D10's `batch.js` protocol reports `percentage` 42 → 66 →
95 → 100 and never a `"finished"` status: the client must switch to
`op=finished` at 100% (the Drupal 7 driver's status check would poll
forever). Redirects are followed manually for the same reason as the
D7 driver: PHP's wrapper hides intermediate `Set-Cookie`s and the
batch is bound to the session.

**4. Session-file hygiene**: a fresh sid per attempt, carriers open
until after the consumer (`session.upload_progress.cleanup=On`
truncates otherwise), `sess_*` swept at boot.

Plus the mechanics shared with the other targets: `memswap == mem`
(swap absorbs the OOM), `apache-mcc.conf` (prefork arena drift) and
the bio geometry (the payload's NUL bytes cannot ride a multipart
header line — same as the Laravel/ThinkPHP measurements).

## Target configuration (all documented, none rigged)

- `docker-compose.yml`: `drupal10` behind the profile; `mem_limit:
  128m` + `memswap_limit: 128m`; port `127.0.0.1:8096`.
- `apache-mcc.conf` — bounded-container Apache tuning (same file the
  other targets ship).
- `setup.sh`: boot + session sweep + readiness marker + OOM watchdog
  (install happens at build time).
- Everything else is stock: stock Drupal 10.6.17, stock installer,
  default `php.ini`, no helper endpoints, no input exemptions (the
  store field is plain `$_REQUEST` in the settings snippet).

## Files

- `Dockerfile` — official image + writable webroot + build-time
  installer run + settings snippet + mcc
- `install.php` — the HTTP installer driver (browser-equivalent form
  fills, the `op=do`/percentage batch protocol, manual redirects)
- `settings-lab-snippet.php` — the session component (start → store →
  close), appended after the stock install
- `setup.sh` — boot + sweep + watchdog
- `apache-mcc.conf` — documented Apache tuning

## Diagnostics (lab-side only)

`python3 -u poc/wp_diagnose.py 8096 phpaftershell-drupal10-1 <h>
drupal10` samples the container's cgroup during a **real attempt**
(newest session file). It is a controller-side harness: the exploit
itself never touches any of it.
