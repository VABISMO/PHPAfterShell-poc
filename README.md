# PHPAfterShell-poc

[![CI](https://github.com/VABISMO/PHPAfterShell-poc/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)
[![CVE](https://img.shields.io/badge/CVE--2026--126714-critical-red)](https://www.cve.org/CVERecord?id=CVE-2026-126714)
[![PHP](https://img.shields.io/badge/PHP-8.2%20%E2%80%93%208.5%20(affected)-orange)](https://www.php.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Educational proof of concept for CVE-2026-126714 ("phpAfterShell")** — an
unauthenticated remote code execution chain against PHP's default file-based
session handler. Ships a fully automated local lab, an HTTP-only exploit
launcher that needs **no cooperation from the target** (no diagnostic
endpoints, no state dumps — natural signals only), and three verification
stages that go from the raw parser effect up to command execution.

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
├── docker-compose.yml       # vulnerable / fixed / mitigated targets
├── app/                     # deliberately boring target app + gadget
│                            # (no diagnostic endpoints at all)
├── poc/
│   ├── lab.py               # byte-level geometry engine + HTTP helpers
│   ├── remote.py            # 100% HTTP-only exploit chain (used by the CLI)
│   ├── stage1_splice.py     # deterministic interrupted-write simulation
│   ├── stage2_oom.py        # real interrupted pwrite via cgroup OOM
│   └── charge_trace.py      # diagnostic: this host's victim charge curve
├── tests/test_geometry.py   # offline unit tests (no docker needed)
└── .github/workflows/ci.yml # unit + end-to-end RCE + controls
```

## Quick start

Requires Docker with Compose v2.

```bash
# 1. start the lab: vulnerable (8087), fixed (8088), mitigated (8089)
#    (the lab makes the webroot writable itself)
docker compose up -d

# 2. fire the exploit (100% HTTP, no docker access needed on the target)
./phpaftershell-poc --target http://127.0.0.1:8087 --command 'id; uname -srm'
```

Example output:

```
[+] RCE confirmed - output:
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Linux ... x86_64
```

### Three verification stages

| Stage | What it proves | Interruption |
|---|---|---|
| `python poc/stage1_splice.py` | The splice grammar: `R[:k] \|\| C[k:]` decodes into a live `FileCache` object | simulated (writes the mixed state directly) |
| `python poc/stage2_oom.py` | The **real** interrupted `pwrite()` — memcg OOM kills the worker inside the syscall | real (local controller sets `oom_score_adj`) |
| `./phpaftershell-poc --target …` | Full chain over **plain HTTP only**: pressure → interrupted write → object injection → webshell → command — tuned from natural signals alone, the target reports nothing | real (remote memory pressure) |

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

- a **vulnerable PHP** (table above) with the default `session.save_handler=files`;
- a **memory-bounded target** — the OOM interruption needs a cgroup
  boundary; the bundled lab uses `mem_limit: 64m` (normal for containers);
- a **destructor gadget** — the demo app ships a representative `FileCache`;
  real frameworks/apps (WordPress, Laravel, …) have known gadget chains;
- **low latency** to the target (the bundled lab is localhost; timing is
  feedback-tuned but a WAN round trip widens the jitter).

The remote mode gets **no help from the target**: the demo app exposes no
diagnostic endpoint, no state dump and no helper route. Every attempt is
judged from natural signals alone —

- **the victim connection itself**: a timeout means the write completed
  (limit never crossed → more pressure), a fast death means the OOM
  struck before the write (→ less pressure), a slow death means it
  struck deeper into the rewrite (→ more pressure); the fast/slow split
  calibrates from the run's own death times, so it encodes no host's
  timing;
- **PHP's `Failed to decode` warning** on the consumer response: the file
  is structurally broken → the attempt carries no trustworthy direction
  and the pressure is held;
- **the webshell probe**: the shell name is randomised **per run**, so a
  stale shell can never fake a hit — this is the only positive signal.

The pressure search bisects those signals into a bracket, slides a
collapsed bracket toward the last signal instead of freezing, and then
samples the band (the landing is stochastic at the edges). On the
bundled lab it lands within a handful of attempts; `--attempts`
(default 40) raises the budget.

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

## Development

```bash
python -m pip install pytest
python -m pytest tests/ -q     # offline: geometry, decoder, classifier

python poc/charge_trace.py 8087  # prints this host's victim charge curve
```

CI (`.github/workflows/ci.yml`) runs the unit tests plus the full
end-to-end chain on every push: stage 1, stage 2, a fresh target for the
remote exploit, the charge-trace diagnostic, the remote RCE itself, and
both controls (patched 8.4.28 must not be exploitable; the mitigated
target must never write a progress record).

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
