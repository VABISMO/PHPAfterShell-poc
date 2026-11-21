# WordPress target — research notes (parked, not in the default lab)

This directory holds a **fully built but not-yet-reliable** WordPress
target for the phpAfterShell chain. Everything below was validated
locally on 2026-11-21; the target is **not** part of `docker compose
up` / CI because the final step (the OOM interruption landing inside the
splice window) does not yet converge reliably.

## What is proven working

| Piece | Evidence |
|---|---|
| Image & versions | `wordpress:6.4.1-php8.2-apache` — WP 6.4.1 + PHP 8.2.13, both inside the advisory's ranges |
| First-boot install | `setup.sh`: entrypoint init → `wp core install` (idempotent) → readiness marker; healthcheck gates on marker + port |
| Entry point | `lab-session.php` mu-plugin: native `session_start()` on `init` + one user field stored in the session — the behaviour of a very common class of real plugins, **no diagnostics, no endpoints** |
| Carrier | progress record written (336 bytes, verified live) |
| Pressure | 8 held fillers charge **+29 MiB** into the cgroup (measured) |
| Victim rewrite | the replacement upload-progress request writes the full **16 MiB `R`** (measured: file 15,993,385 bytes) |
| **Gadget** | **PHPGGC `WordPress/RCE2`** — WordPress core's own `WP_HTML_Token::__destruct` → `system()`. The exact bytes the exploit plants were round-tripped through PHP: `unserialize` → `unset` → `uid=0(root)` + marker |
| Signal plumbing | `Host:` port handling, `/index.php`→`/` canonical redirect, marker-in-response hit detection, `--chain wordpress` |

## What blocks it: the OOM economics

The chain needs the cgroup limit to be crossed **inside the victim's
write** (k in `[f, E')`). WordPress defeats this with its own footprint:

- resting charge ≈ **40–60 MiB** (3-child pool + **~20–30 MiB of WP code
  page cache** — evictable!)
- bio-store transient ≈ **+36 MiB in 60 ms**
- **WP's evictable code cache acts as a shock absorber**: reclaim frees
  it before the limit is reached, so the anon pressure (fillers +
  serialisation) never actually crosses. Measured: at `mem_limit: 128m`
  with maximum pressure the charge tops out ≈ 109–120 MiB — *below* the
  limit — permanent `nooom`.

Configurations tried (each a full 40-attempt run unless noted):

| mem_limit | pool | result |
|---|---|---|
| 64m | 8 (pinned) | band razor-thin at h≈0.3–0.9M; 0 hits in 40 (closest: `late`) |
| 96m | 8 | bio-store hits the ceiling; `nooom` pinned at h_max |
| 128m | 3 | pressure charges correctly (+29M) but reclaim absorbs the crossing; `nooom` everywhere |
| 64m | 3 | (measured, not run: resting ≈48M leaves no band) |

**Lead for future work**: the model suggests `mem_limit ≈ 110–118m`
(anon+serial ≈ 109 must exceed the limit *after* reclaim drains the
code cache, while the bio transient ≈ 90 must stay below it) — a ~10M
window that was not validated before the time-box expired.

## Files

- `Dockerfile` — WP 6.4.1 + wp-cli + the mu-plugin baked into the skeleton
- `lab-session.php` — the session/form mu-plugin (copied into the skeleton at build)
- `setup.sh` — boot: entrypoint init → install → marker → hold apache
- `../config/wp-sessions.ini` — PHP GC tuning (no gc endpoint exists in the no-oracle chain; without a short lifetime the attempts pile up multi-MiB session files)
- `../config/wp-apache-tuning.conf` — 3-child pinned pool

## Exploit support (shipped, unit-tested)

`./phpaftershell-poc --chain wordpress` is implemented and offline-tested
(`tests/test_geometry.py::test_wp_gadget_payload`): the planted record is
`WP_HTML_Token{bookmark_name="<cmd>;echo <marker>", on_destroy=system}`
and success is the marker in the consumer response — no shell file.

To resume: pick a `mem_limit` from the lead above, run
`python poc/charge_trace.py 8091 phpaftershell-wp-1` to confirm the
crossing, then a 40-attempt run with `--chain wordpress`.
