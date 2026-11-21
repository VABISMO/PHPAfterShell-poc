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

| mem_limit | fillers | result |
|---|---|---|
| 64m | 4 | band razor-thin at h≈0.3–0.9M; 0 hits in 40 (closest: `late`) |
| 96m | 4 | band unreachable (h_max 28M too low for the window); `nooom` |
| 128m | 8 | pressure charges correctly (+54M measured) but reclaim absorbs the crossing; `nooom` everywhere |
| 112m | 8 | window needs pre ≥105M, max pressure gives ~99M; `nooom` |
| **96m** | **8** | **the model's window (pre ∈ 89–105, measured ~99) — flip zone located at h≈37M (nooom 36.99 / early 37.39 / late 37.84) but 0 hits across 100+13 in-zone samples: the write-crossing itself is stochastic on this host (reclaim/writeback race), P(hit) per in-band sample ≈ ≤10%** |

**Conclusion**: the landing exists but its per-sample probability is too
low for a reliable CI step — parked after the time-box expired.
Resuming options: (a) raise the in-band sample count (200+ attempts,
~15min), (b) attack the reclaim/writeback race directly (an eviction
lever during the write — note the no-oracle constraint: any helper
endpoint must be removed again for the final version), or (c) accept
the row as "gadget-proven, band-unreliable" and prefer targets whose
footprint matches the green bare-app economics (Laravel is next).

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
