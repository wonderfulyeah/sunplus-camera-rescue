#!/usr/bin/env python3
"""Forensic read-only SPI dump of a BRICKED Sunplus ThinkPad camera in ROM mode.

Target device: 1BCF:0B13  ("SPCA2087 PC Camera" mask-ROM fallback)
Purpose:       read the SPI flash of the bricked camera to learn
                 * how much of the original firmware survived the brick
                 * the original USB descriptors (healthy VID/PID), if intact
               and produce the raw image needed for a possible
               boot-sector-splice reconstruction of the original firmware.

Protocol (confirmed by fwupd plugins/sunplus-camera, vendor flow):
  SET_CUR  unit 4  selector 0x0E  4 bytes   SPI read pointer (seek)
  GET_CUR  unit 4  selector 0x16  64 bytes  read 64 bytes at that pointer
NOTHING else is ever sent — no selector 9/10/11/12 (ISP/write path),
no register writes. Strictly read-only.

Linux + Python 3.7+. No pip packages.

  python3 brick-forensics-0b13.py --check
  python3 brick-forensics-0b13.py
  python3 brick-forensics-0b13.py --size 131072     # read 128 KiB
"""
import argparse
import ctypes
import datetime
import fcntl
import hashlib
import math
import os
import struct
import subprocess
import sys
from pathlib import Path

if not sys.platform.startswith("linux"):
    sys.stderr.write("ERROR: this script is Linux-only (sysfs + uvcvideo).\n")
    sys.exit(2)

TARGET_VID, TARGET_PID = 0x1BCF, 0x0B13
UNIT = 4
SEL_READ_ADDR, SEL_READ_CHUNK = 0x0E, 0x16   # 14 / 22 decimal
CHUNK = 64
UVC_SET_CUR, UVC_GET_CUR = 0x01, 0x81

ALLOWED_TRANSFERS = frozenset((
    (SEL_READ_ADDR, UVC_SET_CUR, 4),
    (SEL_READ_CHUNK, UVC_GET_CUR, CHUNK),
))


class XuQuery(ctypes.Structure):
    _fields_ = [
        ("unit", ctypes.c_uint8),
        ("selector", ctypes.c_uint8),
        ("query", ctypes.c_uint8),
        ("size", ctypes.c_uint16),
        ("data", ctypes.POINTER(ctypes.c_uint8)),
    ]


def _ioc_i32(nr):
    nr = nr & 0xFFFFFFFF
    if nr > 0x7FFFFFFF:
        nr -= 0x100000000
    return nr


UVCIOC_CTRL_QUERY = _ioc_i32(
    (3 << 30) | (ctypes.sizeof(XuQuery) << 16) | (ord("u") << 8) | 0x21
)


def die(msg, code=1):
    try:
        sys.stdout.flush()
    except OSError:
        pass
    sys.stderr.write("ERROR: %s\n" % msg)
    sys.exit(code)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def _txt(path):
    try:
        return path.read_text(errors="replace").strip()
    except OSError:
        return ""


def sysfs_usb(video):
    cur = Path("/sys/class/video4linux") / video.name / "device"
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
                vid = int(_txt(vp), 16)
                pid = int(_txt(pp), 16)
            except ValueError:
                return None
            return {"sysfs": str(cur), "vid": vid, "pid": pid,
                    "bcdDevice": _txt(cur / "bcdDevice"),
                    "product": _txt(cur / "product")}
        if cur.parent == cur:
            break
        cur = cur.parent
    return None


def list_videos():
    out = []
    for p in Path("/dev").glob("video*"):
        if p.name[5:].isdigit():
            out.append(p)
    out.sort(key=lambda p: int(p.name[5:]))
    return out


def is_target(info):
    return info is not None and (info["vid"], info["pid"]) == (TARGET_VID, TARGET_PID)


def inventory():
    rows = []
    print("USB cameras behind /dev/video* (sysfs only, no camera commands):")
    for node in list_videos():
        info = sysfs_usb(node)
        if not info:
            continue
        tag = "%04x:%04x" % (info["vid"], info["pid"])
        if is_target(info):
            why = "TARGET 1bcf:0b13 (bricked camera, ROM mode)"
        elif (info["vid"], info["pid"]) == (0x5986, 0x211A):
            why = "SKIP   IR camera 5986:211a (healthy - do not touch)"
        elif (info["vid"], info["pid"]) == (0x1BCF, 0x0B09):
            why = "SKIP   1bcf:0b09 (a recovery state of some other camera)"
        else:
            why = "SKIP   unrelated"
        print("  %-12s  %s  bcd=%s  %r  %s" % (
            node, tag, info["bcdDevice"], info["product"], why))
        rows.append((node, info))
    if not rows:
        print("  (none found)")
    return rows


def pick_target(rows, device=None):
    if device:
        node = Path(device)
        info = sysfs_usb(node)
        if not is_target(info):
            got = "unknown" if not info else "%04x:%04x" % (info["vid"], info["pid"])
            die("%s is %s, not 1bcf:0b13 — refusing" % (node, got))
        return node, info
    matches = [(n, i) for n, i in rows if is_target(i)]
    if not matches:
        die("No 1bcf:0b13 device. Is the bricked camera present? (lsusb, "
            "re-plug, or check usbcore errors in dmesg)")
    return matches[0]


def xu(fd, selector, query, data):
    key = (selector, query, len(data))
    if key not in ALLOWED_TRANSFERS:
        raise RuntimeError(
            "blocked USB transfer selector=0x%02x query=0x%02x len=%d "
            "(not a read-only forensics control)" % (selector, query, len(data)))
    buf = (ctypes.c_uint8 * len(data)).from_buffer(data)
    q = XuQuery(unit=UNIT, selector=selector, query=query,
                size=len(data), data=ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint8)))
    fcntl.ioctl(fd, UVCIOC_CTRL_QUERY, q, True)


def dump_once(fd, size):
    out = bytearray()
    addr, chunk = bytearray(4), bytearray(CHUNK)
    for off in range(0, size, CHUNK):
        struct.pack_into("<I", addr, 0, off)
        xu(fd, SEL_READ_ADDR, UVC_SET_CUR, addr)
        chunk[:] = b"\x00" * CHUNK
        xu(fd, SEL_READ_CHUNK, UVC_GET_CUR, chunk)
        out.extend(chunk)
        if (off & 0xFFFF) == 0:
            print("  0x%04X" % off)
    if len(out) != size:
        die("short dump: %d bytes" % len(out))
    return bytes(out)


def entropy(b):
    if not b:
        return 0.0
    c = {}
    for x in b:
        c[x] = c.get(x, 0) + 1
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def analyze(img):
    print("\n===== forensics report =====")
    print("SHA256: %s" % sha256(img))
    ff0 = img[:4096].count(0xFF)
    print("sector 0 (boot): 0xFF %d/4096  entropy %.2f  -> %s" % (
        ff0, entropy(img[:4096]),
        "ERASED (matches the T480s brick signature)" if ff0 == 4096 else
        "partly intact" if ff0 > 2048 else "intact"))
    print("\n4 KiB block map (E=erased-FF, Z=zeros, .=code/data):")
    for i in range(0, len(img), 4096):
        b = img[i:i + 4096]
        ffr = b.count(0xFF)
        zr = b.count(0x00)
        mark = "E" if ffr == 4096 else ("Z" if zr == 4096 else ".")
        print("  0x%05X  %s  ent=%.2f  FF=%4d  00=%4d" % (
            i, mark, entropy(b), ffr, zr))
    # scan for USB device descriptors (12 01 ...) anywhere
    print("\nembedded USB device descriptors (potential original identity):")
    found = False
    for off in range(0, len(img) - 18):
        if img[off] == 0x12 and img[off + 1] == 0x01:
            d = img[off:off + 18]
            bcdUSB = int.from_bytes(d[2:4], "little")
            vid = int.from_bytes(d[8:10], "little")
            pid = int.from_bytes(d[10:12], "little")
            bcd = int.from_bytes(d[12:14], "little")
            if 0x0100 <= bcdUSB <= 0x0210 and vid >= 0x0100:
                print("  @0x%05X  USB=%04X VID=%04X PID=%04X bcdDevice=%04X" % (
                    off, bcdUSB, vid, pid, bcd))
                found = True
    if not found:
        print("  (none found)")
    # UTF-16 strings of interest
    print("\nUTF-16 strings (branding):")
    import re
    seen = set()
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){5,}", img):
        s = m.group().decode("utf-16-le")
        if any(k in s for k in ("Camera", "camera", "Sunplus", "SunplusIT",
                                "Chicony", "Bison", "Lux", "IR", "Integrated",
                                "PC ", "MSFT")) and s not in seen:
            seen.add(s)
            print("  @0x%05X  %r" % (m.start(), s))
    if not seen:
        print("  (none found)")
    if img[:2] in (b"\x89\x17", b"\x89\x18"):
        print("\nSunplus firmware header PRESENT at 0x0 — boot sector intact!")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Read-only forensic dump of a bricked 1bcf:0b13 camera.")
    ap.add_argument("--check", action="store_true",
                    help="identify 1bcf:0b13 via sysfs; do not open XU")
    ap.add_argument("--size", type=lambda x: int(x, 0), default=65536,
                    help="bytes to read (default 65536 = 64 KiB)")
    ap.add_argument("--out", default="brick-forensics.bin")
    ap.add_argument("--device", help="/dev/videoN (still must be 1bcf:0b13)")
    args = ap.parse_args(argv)
    if args.size % CHUNK or args.size < CHUNK or args.size > 1048576:
        die("--size must be a multiple of %d, at most 1 MiB" % CHUNK)

    print("brick-forensics-0b13.py — read-only, 1bcf:0b13 only")
    rows = inventory()
    node, info = pick_target(rows, args.device)
    print("\nSelected device (no camera commands issued yet):")
    print("  node:    %s" % node)
    print("  vid:pid: %04x:%04x" % (info["vid"], info["pid"]))
    print("  bcd:     %s" % info["bcdDevice"])
    if not is_target(info):
        die("internal VID/PID check failed")
    if args.check:
        print("\n--check: stopping before any UVC XU ioctl.")
        return 0

    print("\nAbout to READ %d bytes twice using only:" % args.size)
    print("  SET_CUR  unit 4  selector 0x0E  (SPI read address)")
    print("  GET_CUR  unit 4  selector 0x16  (64-byte read)")
    print("Write-path selectors (9/10/11/12) and register writes (2/3) are "
          "code-blocked.")
    try:
        fd = os.open(str(node), os.O_RDWR)
    except OSError as exc:
        die("open %s failed: %s (close camera apps; try sudo)" % (node, exc))
    try:
        again = sysfs_usb(node)
        if not is_target(again):
            die("VID/PID changed after open — refusing")
        print("pass 1/2")
        a = dump_once(fd, args.size)
        print("pass 2/2")
        b = dump_once(fd, args.size)
    except OSError as exc:
        die("UVC read failed: %s\n"
            "If every ioctl fails with EPIPE/EIO, this ROM build may not map "
            "the SPI read path — report the exact error." % exc)
    finally:
        os.close(fd)

    if a != b:
        die("the two reads differ — flash is unstable/not mapped; "
            "sha A=%s sha B=%s" % (sha256(a), sha256(b)))

    Path(args.out).write_bytes(a)
    print("\ndumps match; wrote %s (%d bytes)" % (args.out, len(a)))
    analyze(a)
    print("\nSend %s back together with `lsusb -nn` output." % args.out)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        die("interrupted — nothing was written")
    except RuntimeError as exc:
        die("refused unsafe USB transfer: %s" % exc)
