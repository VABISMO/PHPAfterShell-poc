# PHPAfterShell-poc

[![CI](https://github.com/VABISMO/PHPAfterShell-poc/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/VABISMO/PHPAfterShell-poc)](https://github.com/VABISMO/PHPAfterShell-poc/releases)
[![CVE](https://img.shields.io/badge/CVE--2026--126714-critical-red)](https://www.cve.org/CVERecord?id=CVE-2026-126714)
[![PHP](https://img.shields.io/badge/PHP-8.2%20%E2%80%93%208.5%20(affected)-orange)](https://www.php.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Educational proof of concept for CVE-2026-126714 ("phpAfterShell")** — an
unauthenticated remote code execution chain against PHP's default file-based
session handler. Ships a fully automated local lab, an HTTP-only exploit
launcher that needs **no cooperation from the target** (no diagnostic
endpoints, no state dumps — natural signals only), and three verification
stages that go from the raw parser effect up to command execution. CI
re-proves the chain on **Apache/mod_php and nginx + php-fpm** on every
push, with negative controls.

> **Authorized testing only.** Run it against the bundled lab (localhost) or
> systems you own/have permission to test. See [Disclaimer](#disclaimer).

```
./phpaftershell-poc --target http://127.0.0.1:8087 --command 'id'
```

---

## The vulnerability

| | |
|---|---|
| **CVE** | CVE-2026-126714 · CVSS v4.0 **9.2** (critical) |
| **Discovered by** | [depthfirst](https://depthfirst.com/research/phpaftershell) (coordinated disclosure with the PHP security team) |
| **Fixed in** | PHP 8.2.36, 8.3.37, 8.4.28, 8.5.13 (published 2026-11-19) |
| **Still vulnerable** | PHP 8.2 < 8.2.36, 8.3 < 8.3.37, 8.4 < 8.4.28, 8.5 < 8.5.13 — *including the October "PHP2Shell" patched releases* |
| **Root cause** | Non-atomic `pwrite()` + `ftruncate()` update of the session file by the RFC1867 upload-progress callback |
| **Impact** | Unauthenticated remote object injection into `session_start()` → RCE when a gadget exists |

### What actually happens

1. `session.upload_progress` is **enabled by default**. While PHP parses an
   unauthenticated `multipart/form-data` request — *before any application
   code runs* — the callback opens the target's session file, merges the
   progress record and writes the result back **in place** with `pwrite()`.
2. That write is not atomic. If the worker dies mid-copy (in the lab: a
   memcg OOM triggered by the attacker's own memory pressure), the inode is
   left with **the prefix of the new state and the tail of the old one**:

   ```
   disk = R[0:k] || C[k:]
   ```

3. The attacker chose the serialized length fields, so bytes that were
   *inert string content* in `C` become *top-level session records* when the
   decoder re-reads the spliced file on the next `session_start()`.
4. The planted record reconstructs a live object. Its `__destruct()`
   (a `FileCache` gadget in the demo app — real apps have their own
   loggers/caches) writes a webshell → **command execution as the PHP user**.

Both source states (`C` and `R`) are produced by PHP itself from ordinary
multipart fields — no application cooperation, no authentication, no local
access to the target.

## Repository layout

```
├── phpaftershell-poc        # the exploit launcher (banner + CLI)
├── docker-compose.yml       # vulnerable / fixed / mitigated / fpm targets
├── Makefile                 # make up | test | e2e | clean
├── SECURITY.md              # reporting policy, scope, lab hardening
├── app/                     # deliberately boring target app + gadget
│                            # (no diagnostic endpoints at all)
├── config/                  # lab tuning: apache pool, mitigations
├── fpm/                     # nginx + php-fpm target (cross-SAPI proof)
├── poc/
│   ├── lab.py               # byte-level geometry engine + HTTP helpers
│   ├── remote.py            # 100% HTTP-only exploit chain (used by the CLI)
│   ├── stage1_splice.py     # deterministic interrupted-write simulation
│   ├── stage2_oom.py        # real interrupted pwrite via cgroup OOM
│   └── charge_trace.py      # diagnostic: this host's victim charge curve
├── scripts/e2e-local.sh     # local mirror of the CI sequence (make e2e)
├── tests/test_geometry.py   # offline unit tests (no docker needed)
├── experiments/wordpress/   # parked WordPress target + research notes
└── .github/workflows/ci.yml # unit + end-to-end RCE + controls
```

## Quick start

Requires Docker with Compose v2.

```bash
# 1. start the lab: vulnerable (8087), fixed (8088), mitigated (8089),
#    nginx + php-fpm cross-SAPI target (8090)
#    (the lab makes the webroot writable itself)
docker compose up -d --wait

# 2. fire the exploit (100% HTTP, no docker access needed on the target)
./phpaftershell-poc --target http://127.0.0.1:8087 --command 'id; uname -srm'
```

Example output:

```
[+] RCE confirmed - output:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux ... x86_64
```

CLI options:

```bash
--target URL        # base URL of the target (required)
--command CMD       # shell command to execute (required)
--attempts N        # interruption budget (default 40; CI uses 80)
--chain NAME        # planted gadget: filecache (lab default) | wordpress
-q, --quiet         # only print the command output
```

### Three verification stages

| Stage | What it proves | Interruption |
|---|---|---|
| `python poc/stage1_splice.py` | The splice grammar: `R[:k] \|\| C[k:]` decodes into a live `FileCache` object | simulated (writes the mixed state directly) |
| `python poc/stage2_oom.py` | The **real** interrupted `pwrite()` — memcg OOM kills the worker inside the syscall | real (local controller sets `oom_score_adj`) |
| `./phpaftershell-poc --target …` | Full chain over **plain HTTP only**: pressure → interrupted write → object injection → webshell → command — tuned from natural signals alone, the target reports nothing | real (remote memory pressure) |

## Target support

**Works** = the full chain over plain HTTP against that exact target with
no target-side help, proven by CI on every push or by the evidence
noted. All rows are **Linux** targets: the interruption needs a cgroup
boundary (the bug itself is cross-platform — see
[requirements](#requirements--reliability-notes)).

| Target | Stack | Status | Evidence |
|---|---|---|---|
| Bare PHP demo app (lab victim, `:8087`) | Apache · mod_php · PHP 8.4.27 | ✅ **works** | CI every push — RCE within the attempt budget (observed: 2–22) |
| nginx + php-fpm (lab fpm, `:8090`) | nginx · php-fpm · PHP 8.4.27 | ✅ **works** | CI every push — cross-SAPI, RCE observed as fast as attempt 1 |
| Patched PHP (lab fixed, `:8088`) | Apache · PHP 8.4.28 | ✅ **not exploitable** | CI negative control — exhausts its budget with no hit |
| `upload_progress` disabled (lab mitigated, `:8089`) | Apache · PHP 8.4.27 | ✅ **no entry path** | CI negative control — never writes a progress record |
| WordPress 6.4.1 | Apache · mod_php · PHP 8.2.13 | 🟡 **parked** | gadget + every mechanism proven; OOM band not yet reliable — [`experiments/wordpress/`](experiments/wordpress/README.md) |
| Laravel | — | ⬜ planned | next target |
| Joomla / Drupal | — | ⬜ not evaluated | — |

What each row additionally needs beyond the vulnerable PHP itself:
`session.save_handler=files` (default), `session.upload_progress` on
(default), a memory-bounded worker, and — for command execution — a
**gadget from the target's own code**. The lab ships its own
`FileCache`; `--chain wordpress` plants WordPress's own `WP_HTML_Token`
(PHPGGC `WordPress/RCE2`). For CMS/framework rows the two hard parts are
(1) a component that calls native `session_start()` (WordPress core
never does — the parked target uses a realistic session-using plugin)
and (2) a gadget chain that fits the splice — which is why those rows
are parked/planned rather than green.

## How the splice works

The chain leans on the fact that the session serializer is a stream of
`key|value` records with attacker-controlled length fields, and that `C` and
`R` differ only in the position of the `bio` record (the progress record in
`R` is ~8 MiB longer):

```
C = [ progress_c (336 B) ][ bio | s:L1:"  <payload with planted bytes>  "; ]
R = [ progress' (adds the long field_name) ][ bio (byte-identical) ]
                    ^
                    f = offset where R's filename string starts

mix = R[:k] || C[k:]           (k chosen inside R's filename string)

parse mix:  ... R's filename string closes at E' using C's planted '"' ...
            SUFFIX completes the open a:5/a:1/a:7 arrays
            -> back at top level ->  evil|O:9:"FileCache":2:{...}  is a
               real session record -> pad record swallows the remainder
```

The accepted window for `k` is `[f, E')` — about **8 MiB wide** in the
remote geometry — which is what makes the OOM timing tractable: the
exploit only has to land the cgroup charge failure somewhere inside it,
and it only ever watches **natural signals** to know where it landed
(see below) — the target reports nothing.

## Requirements & reliability notes

The exploit (all three stages) needs:

- a **vulnerable PHP** (see [target support](#target-support)) with the
  default `session.save_handler=files`;
- a **Linux target with a memory boundary** — the interruption is
  produced by a memcg OOM, so a container/K8s limit or an equivalent
  cgroup budget is required. The bundled lab uses `mem_limit: 64m`
  (normal for containers). The vulnerability itself is cross-platform;
  this chain's *kill mechanism* is Linux-specific;
- a **destructor gadget** — the demo app ships a representative `FileCache`;
  real frameworks/apps (WordPress, Laravel, …) have known gadget chains;
- **low latency** to the target (the bundled lab is localhost; timing is
  feedback-tuned but a WAN round trip widens the jitter).

The chain is **SAPI-agnostic** — CI proves it against both bundled
targets: Apache/mod_php (8087) and nginx + php-fpm (8090, the most
common production pairing; built in `fpm/` with
`fastcgi_request_buffering off` so the held filler bodies buffer in the
FPM worker exactly like mod_php buffers them).

The remote mode gets **no help from the target**: the demo app exposes no
diagnostic endpoint, no state dump and no helper route. Every attempt is
judged from natural signals alone —

- **the victim connection itself**: a timeout means the write completed
  (limit never crossed → more pressure); a death within **250ms** means
  the OOM struck during serialisation, long before the pwrite finished
  (→ less pressure); a death after 250ms outlived a full serialisation
  plus part of the write (→ more pressure). The 250ms threshold comes
  from the measured death distributions on every target so far (early
  deaths land at 7–108ms — a 16 MiB serialisation cannot finish faster
  — late deaths at ≥1.2s); an earlier adaptive split was tried and
  discarded after it collapsed on clustered data and thrashed the
  pressure for a whole CI run;
- **PHP's `Failed to decode` warning** on the consumer response: the file
  is structurally broken → the attempt carries no trustworthy direction
  and the pressure is held;
- **the positive signal**: the webshell probe, against a shell name
  randomised **per run** so a stale shell can never fake a hit — or, in
  `--chain wordpress` mode, a per-run **marker echoed by the gadget**
  (`system()` output appended to the consumer response) — that mode
  writes no shell file at all.

The pressure search bisects those signals into a bracket, slides a
collapsed bracket toward the last signal instead of freezing, and then
samples the band (the landing is stochastic at the edges). On the
bundled lab it lands within a handful of attempts; `--attempts`
(default 40, CI uses 80) raises the budget.

## WordPress target (research status)

The exploit ships `--chain wordpress`, which plants **WordPress's own
core gadget** instead of the lab's FileCache: PHPGGC `WordPress/RCE2` —
`WP_HTML_Token::__destruct()` → `system()` (verified by round-tripping
the exact planted bytes through PHP: `unserialize` → `unset` → command
output). No lab-provided gadget is involved.

The full chain against a real WordPress is **built but parked**: every
mechanical piece is proven (session entry via a realistic mu-plugin,
carrier record, +54 MiB of filler pressure, the 16 MiB victim rewrite,
the gadget), and five `mem_limit` configurations were tried — at the
best one (96m + 8 fillers) the flip zone was located precisely
(h≈37M) but the write-crossing itself proved stochastic on this host
(≤10% per in-band sample: 0 hits in 100+ attempts). Measured numbers
and resume options are in
[`experiments/wordpress/README.md`](experiments/wordpress/README.md).

## Controls (the lab proves the fix works)

CI runs both controls on every push:

```bash
# patched target (8.4.28): same real interruption path, must exhaust its
# attempt budget WITHOUT a hit - the fixed parser cannot produce a mix
! ./phpaftershell-poc --target http://127.0.0.1:8088 --command 'id' --attempts 8

# mitigated target: session.upload_progress.enabled = 0 -> no progress
# record is ever written, so the whole entry path disappears
```

Interim mitigation (if you cannot upgrade yet) — from PHP / depthfirst:

```ini
session.upload_progress.enabled = 0
```

…closes the upload-progress entry path but **does not repair the session
handler**; upgrading to 8.2.36 / 8.3.37 / 8.4.28 / 8.5.13 is the fix.

## Detection & IOCs (for defenders)

Even without the fixed release, the chain leaves traces:

- **Session files** — `sess_*` files growing to multiple MiB, or log
  lines with `Failed to decode` (a session file that no longer parses is
  the direct product of an interrupted write).
- **Webshell drops** — new `.php` files under the webroot containing a
  one-liner like `<?php system($_GET['c']);`. This PoC writes a random
  `s_<hex>.php` name per run — treat *any* unexpected webroot `.php` as
  an IOC, and watch for writes during multipart uploads.
- **Progress records** — an `upload_progress_*` session key whose
  `field_name` is a multi-megabyte run of a single character (the
  replacement filename used to open the splice window).
- **Resource behaviour** — apache/php workers dying mid-request during
  unauthenticated multipart uploads that hold their connections open,
  or cgroup OOM kills clustered around such traffic.
- **Process behaviour** — held connections that never send their body,
  followed by a rewrite of the same session id from a second connection.

Cheap mitigations when you cannot upgrade yet: keep
`session.upload_progress.enabled = 0` (the interim mitigation above),
monitor the webroot for unexpected file creation (file-integrity
monitoring), and alert on multi-megabyte session files.

## Development

```bash
make up        # start the lab, block until every healthcheck passes
make test      # offline unit tests (geometry, decoder, classifier)
make e2e       # full local mirror of the CI sequence
make clean     # wipe lab artifacts (sessions, results, stray shells)

# or directly:
python -m pip install pytest
python -m pytest tests/ -q     # offline: geometry, decoder, classifier

python poc/charge_trace.py 8087                    # victim's charge curve
python poc/charge_trace.py 8090 phpaftershell-fpm-1 # any target's curve
```

CI (`.github/workflows/ci.yml`) runs the unit tests plus the full
end-to-end chain on every push: stage 1, stage 2, a fresh target for the
remote exploit, the charge-trace diagnostic, the remote RCE itself, the
**same chain again against nginx + php-fpm (cross-SAPI)**, and both
controls (patched 8.4.28 must not be exploitable; the mitigated target
must never write a progress record).

Found something wrong with the lab, the exploit or the CI? See
[SECURITY.md](SECURITY.md) for how to report it (and what is out of
scope).

## References

- depthfirst — [phpAfterShell: From Interrupted Session Writes to Remote Code Execution](https://depthfirst.com/research/phpaftershell)
- PHP project security advisory (2026-11-19) — fixed releases 8.2.36 / 8.3.37 / 8.4.28 / 8.5.13
- [CVE-2026-126714](https://www.cve.org/CVERecord?id=CVE-2026-126714)
- Related: PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — the October advisories this bug bypasses

## Disclaimer

This repository is provided for **educational purposes, defensive research
and authorized security testing**. The authors assume no responsibility for
misuse. Running exploit code against systems without explicit permission is
illegal in most jurisdictions.

## License & contributors

MIT — see [LICENSE](LICENSE). Thanks to everyone working on the project in
[CONTRIBUTORS.md](CONTRIBUTORS.md); exploit-chain credit to the depthfirst
research team who discovered and disclosed CVE-2026-126714.
