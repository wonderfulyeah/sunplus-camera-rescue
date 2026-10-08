#!/usr/bin/env python3
"""Probe-based read-only firmware dump for healthy Sunplus ThinkPad camera bars.

For machines whose RGB camera works but whose healthy USB identity we do not
know in advance (e.g. FRU 01HW040: X1 Yoga Gen 3 / X1 Carbon 6th / X280 /
X380 Yoga / L380 / L390 Yoga / P1). Also matches known-good identities.

Strategy (strictly read-only):
  1. enumerate /dev/video* and map every node to its USB device
  2. SKIP every node that is a known IR camera, a known ROM/recovery state,
     or non-camera hardware
  3. for each remaining candidate, probe XU unit 4 with the vendor read pair
       SET_CUR selector 0x0E (seek) + GET_CUR selector 0x16 (64-byte read)
     - if the node answers, dump 64 KiB TWICE and require both passes equal
  4. validate the image: Sunplus header (89 17/18 02 80) + at least one
     embedded USB device descriptor; print everything found

Protocol per fwupd plugins/sunplus-camera (vendor verify path). No write
selectors (9/10/11/12) can ever be sent.

Linux + Python 3.7+. No pip packages.

  python3 donor-dump-probe.py --check      # inventory only
  sudo python3 donor-dump-probe.py         # probe + dump
"""
import argparse
import ctypes
import datetime
import fcntl
import hashlib
import math
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

if not sys.platform.startswith("linux"):
    sys.stderr.write("ERROR: Linux only.\n")
    sys.exit(2)

UNIT = 4
SEL_READ_ADDR, SEL_READ_CHUNK = 0x0E, 0x16
CHUNK = 64
UVC_SET_CUR, UVC_GET_CUR = 0x01, 0x81
DUMP_SIZE = 65536

ALLOWED_TRANSFERS = frozenset((
    (SEL_READ_ADDR, UVC_SET_CUR, 4),
    (SEL_READ_CHUNK, UVC_GET_CUR, CHUNK),
))

# identities we must NEVER talk to
SKIP = {
    (0x5986, 0x211A): "IR camera (SPCA2093B, healthy)",
    (0x04F2, 0xB615): "IR camera (Chicony-branded IR variant)",
    (0x1BCF, 0x0B09): "ROM/recovery state (not a donor)",
    (0x1BCF, 0x0B13): "ROM/recovery state (bricked camera)",
}


class XuQuery(ctypes.Structure):
    _fields_ = [("unit", ctypes.c_uint8), ("selector", ctypes.c_uint8),
                ("query", ctypes.c_uint8), ("size", ctypes.c_uint16),
                ("data", ctypes.POINTER(ctypes.c_uint8))]


def _ioc32(nr):
    nr &= 0xFFFFFFFF
    return nr - 0x100000000 if nr > 0x7FFFFFFF else nr


UVCIOC_CTRL_QUERY = _ioc32(
    (3 << 30) | (ctypes.sizeof(XuQuery) << 16) | (ord("u") << 8) | 0x21)


def die(msg, code=1):
    sys.stdout.flush()
    sys.stderr.write("ERROR: %s\n" % msg)
    sys.exit(code)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _txt(p):
    try:
        return p.read_text(errors="replace").strip()
    except OSError:
        return ""


def sysfs_usb(node):
    cur = Path("/sys/class/video4linux") / node.name / "device"
    if not cur.exists():
        return None
    try:
        cur = cur.resolve()
    except OSError:
        return None
    for _ in range(12):
        vp, pp = cur / "idVendor", cur / "idProduct"
        if vp.is_file() and pp.is_file():
            try:
                return {"sysfs": str(cur),
                        "vid": int(_txt(vp), 16), "pid": int(_txt(pp), 16),
                        "bcdDevice": _txt(cur / "bcdDevice"),
                        "product": _txt(cur / "product")}
            except ValueError:
                return None
        if cur.parent == cur:
            break
        cur = cur.parent
    return None


def list_videos():
    out = [p for p in Path("/dev").glob("video*") if p.name[5:].isdigit()]
    return sorted(out, key=lambda p: int(p.name[5:]))


def xu(fd, selector, query, data):
    key = (selector, query, len(data))
    if key not in ALLOWED_TRANSFERS:
        raise RuntimeError("blocked transfer sel=0x%02x q=0x%02x len=%d"
                           % (selector, query, len(data)))
    buf = (ctypes.c_uint8 * len(data)).from_buffer(data)
    q = XuQuery(unit=UNIT, selector=selector, query=query, size=len(data),
                data=ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint8)))
    fcntl.ioctl(fd, UVCIOC_CTRL_QUERY, q, True)


def read_chunk(fd, off):
    a = bytearray(4)
    struct.pack_into("<I", a, 0, off)
    xu(fd, SEL_READ_ADDR, UVC_SET_CUR, a)
    c = bytearray(64)
    xu(fd, SEL_READ_CHUNK, UVC_GET_CUR, c)
    return bytes(c)


def dump_once(fd):
    out = bytearray()
    for off in range(0, DUMP_SIZE, CHUNK):
        out += read_chunk(fd, off)
        if (off & 0xFFFF) == 0:
            print("  0x%04X" % off, flush=True)
    return bytes(out)


def validate(img):
    ok = img[:2] in (b"\x89\x17", b"\x89\x18")
    descs = []
    for m in re.finditer(rb"\x12\x01", img):
        d = img[m.start():m.start() + 18]
        if len(d) < 18:
            continue
        bcdUSB = int.from_bytes(d[2:4], "little")
        vid = int.from_bytes(d[8:10], "little")
        pid = int.from_bytes(d[10:12], "little")
        bcd = int.from_bytes(d[12:14], "little")
        if 0x0100 <= bcdUSB <= 0x0210 and vid >= 0x0100:
            descs.append((m.start(), bcdUSB, vid, pid, bcd))
    brands = set()
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){5,}", img):
        s = m.group().decode("utf-16-le")
        if any(k in s for k in ("Camera", "Sunplus", "Chicony", "Bison",
                                "Integrated", "PC ", "IR")):
            brands.add(s)
    ent = []
    for i in range(0, 0x8000, 0x1000):
        b = img[i:i + 0x1000]
        c = {}
        for x in b:
            c[x] = c.get(x, 0) + 1
        n = len(b)
        ent.append(-sum(v / n * math.log2(v / n) for v in c.values()))
    return ok, descs, brands, ent


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="inventory only, no XU access")
    ap.add_argument("--out", default="donor-dump.bin")
    args = ap.parse_args(argv)

    print("donor-dump-probe.py — read-only probe for healthy Sunplus camera")
    cands = []
    print("\n/dev/video* inventory:")
    for node in list_videos():
        info = sysfs_usb(node)
        if not info:
            continue
        key = (info["vid"], info["pid"])
        tag = "%04x:%04x" % key
        if key in SKIP:
            why = "SKIP   " + SKIP[key]
        else:
            why = "CANDIDATE (unknown identity - will probe XU read path)"
            cands.append((node, info))
        print("  %-12s %s bcd=%s %r  %s" % (node, tag, info["bcdDevice"],
                                            info["product"], why))
    if not cands:
        die("No candidate camera found. (Is this a machine with a working "
            "01HW040-family RGB camera?)")
    if args.check:
        print("\n--check: stopping before any XU access.")
        return 0

    for node, info in cands:
        print("\n=== probing %s (%04x:%04x %r) ==="
              % (node, info["vid"], info["pid"], info["product"]))
        try:
            fd = os.open(str(node), os.O_RDWR)
        except OSError as exc:
            print("  open failed: %s (try sudo)" % exc)
            continue
        try:
            first = read_chunk(fd, 0)
        except OSError as exc:
            print("  no XU read response (unit 4 sel 0x0E/0x16): %s" % exc)
            os.close(fd)
            continue
        print("  XU read path RESPONDS — first 16B: %s" % first[:16].hex())
        if first[:2] not in (b"\x89\x17", b"\x89\x18"):
            print("  no Sunplus firmware header at 0x0 — not a camera flash "
                  "window; skipping")
            os.close(fd)
            continue
        print("  Sunplus header OK — dumping 64 KiB twice...")
        try:
            a = dump_once(fd)
            b = dump_once(fd)
        except OSError as exc:
            print("  read failed mid-dump: %s" % exc)
            os.close(fd)
            continue
        os.close(fd)
        if a != b:
            print("  two passes DIFFER — unstable, discarding")
            continue
        ok, descs, brands, ent = validate(a)
        print("  SHA256: %s" % sha256(a))
        print("  header ok: %s" % ok)
        for off, bcdUSB, vid, pid, bcd in descs:
            print("  descriptor @0x%05X: USB=%04X VID=%04X PID=%04X bcd=%04X"
                  % (off, bcdUSB, vid, pid, bcd))
        print("  brand strings: %s" % sorted(brands))
        print("  8KiB-block entropies: %s" % " ".join("%.2f" % e for e in ent))
        Path(args.out).write_bytes(a)
        print("\n  WROTE %s (%d bytes)" % (args.out, len(a)))
        print("  Send this file + the `lsusb -nn` line of this machine back.")
        return 0
    die("No candidate produced a valid dump.")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        die("interrupted — nothing was written")
    except RuntimeError as exc:
        die("refused unsafe USB transfer: %s" % exc)
