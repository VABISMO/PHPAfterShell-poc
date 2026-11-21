#!/usr/bin/env python3
"""Charge-trace: one instrumented attempt, for CI diagnostics.

Runs the real remote attempt while sampling the target's
memory.current every ~20ms from inside the container (one docker exec -
this is a lab-side diagnostic harness like the stages, NOT part of the
HTTP-only exploit), then prints the series so the exact charge curve of
the victim's read / serialization / pwrite - and where the cgroup limit
is actually crossed - can be read straight off the CI log.

usage: charge_trace.py [port] [container]
"""
from __future__ import annotations

import subprocess
import sys
import time

import lab
import remote

SAMPLES = 400          # 400 x 20ms = 8s of coverage
DURATION_S = SAMPLES * 0.02


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8087
    if len(sys.argv) > 2:
        lab.CONTAINER = sys.argv[2]   # e.g. phpaftershell-fpm-1
    lab.set_geometry("big")
    lab.set_shell(lab.new_shell_name())   # never inherit a stale shell
    lab.HOST, lab.PORT = "127.0.0.1", port
    h = 22_000_000
    c_len = remote.P_START + lab.L1 + 2
    r_len = (len(lab.r_prefix()) + lab.LEN2 + len(lab.r_suffix())
             + lab.L1 + 17)

    proc = subprocess.Popen(
        ["docker", "exec", lab.CONTAINER, "sh", "-c",
         f"i=0; while [ $i -lt {SAMPLES} ]; do "
         "cat /sys/fs/cgroup/memory.current; sleep 0.02; "
         "i=$((i+1)); done"],
        stdout=subprocess.PIPE, text=True)
    t0 = time.monotonic()
    try:
        res = remote.attempt("127.0.0.1", port, h, c_len, r_len)
    finally:
        try:
            out, _ = proc.communicate(timeout=DURATION_S + 10)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
    elapsed = time.monotonic() - t0

    samples = [int(x) for x in out.split() if x.strip().isdigit()]
    limit = 64 * 1024 * 1024   # matches docker-compose mem_limit
    print(f"=== CHARGE TRACE: attempt={res}")
    print(f"elapsed={elapsed:.1f}s samples={len(samples)} "
          f"min={min(samples)/1048576:.1f}M max={max(samples)/1048576:.1f}M "
          f"limit=64.0M")
    lo, hi = min(samples), max(samples)
    span = max(hi - lo, 1)
    for i, s in enumerate(samples):
        # 60-column bar; the '#' row of the limit marks the crossing
        n = int((s - lo) / span * 59)
        mark = "  <== OVER LIMIT" if s >= limit else ""
        print(f"t={i * 0.02:5.2f}s {s / 1048576:6.1f}M "
              f"{'#' * n}{'.':<{60 - n}}{mark}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
