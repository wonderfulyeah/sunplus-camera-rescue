# sunplus-camera-rescue

Read-only SPI firmware dump & recovery tooling for **Sunplus-based ThinkPad
integrated cameras** (FRU 01HW040 family), talking over the camera's own UVC
extension unit — **no disassembly, no programming clip, no Windows required**.

```
─────────────────────────────────────────────────────────────
  ⚠  READ-ONLY BY DESIGN. These scripts can never write to your
  ⚠  camera: the flash-write selectors (9/10/11/12) and register
  ⚠  writes are rejected in code before any USB transfer happens.
  ⚠  (A future write/restore tool will ship separately, gated
  ⚠  behind --write and an image verification step.)
─────────────────────────────────────────────────────────────
```

## Background

Many 2017–2019 ThinkPads (X1 Yoga Gen 3, X1 Carbon 6th, X280, X380 Yoga,
L380/L390 Yoga, P1, …) carry the "Common Camera E" module — **FRU 01HW040**
(Chicony-manufactured, Sunplus SPCA208x-family controllers inside, one
controller per sensor: RGB + IR).

The RGB controller keeps its firmware on a 64 KiB SPI flash chip. Unlike the
IR camera (SPCA2093B, for which Lenovo shipped an official firmware update
utility, ds505129 / version 5465), **no RGB firmware package was ever
published**. If that firmware is lost or a flash attempt goes wrong, the
camera falls back to its mask-ROM mode and enumerates as:

```
ID 1bcf:0b13  "SPCA2087 PC Camera"      (mask-ROM / recovery state)
```

…which no driver, no OS reinstall and no Lenovo download can fix. Recovery
requires a valid firmware image from a healthy module of the same family.
These tools make collecting and inspecting such images a one-command,
provably read-only operation.

> Note: the X1 Yoga Gen 3 shipped with **two RGB camera vendors**. Units with
> `04f2:b61e` (Chicony variant — the ID you see on ArchWiki) are a different
> hardware lineage and are **not** relevant here. Only the Sunplus variant
> (`1bcf:0b09` / `1bcf:0b13` states) applies.

## Tools

### `donor-dump-probe.py` — collect a firmware image from a healthy camera

For owners of a machine whose RGB camera **works**. You do not need to know
your camera's USB ID: the script inventories every `/dev/video*` node, skips
anything known (IR cameras, ROM/recovery states), probes the remaining
candidates with the vendor read path, validates what it finds (Sunplus header,
embedded USB descriptors, entropy) and writes `donor-dump.bin`.

```bash
python3 donor-dump-probe.py --check   # inventory only, no camera I/O
sudo python3 donor-dump-probe.py      # probe + read-only 64 KiB dump
```

If you have a bricked camera of this family, **please consider running this
on your healthy machine and sharing the dump** — see
[linux-enable-ir-emitter issue #190](https://github.com/EmixamPP/linux-enable-ir-emitter)
for the community effort this continues.

### `brick-forensics-0b13.py` — forensics on a bricked camera (ROM mode)

Talks to a camera stuck in the `1bcf:0b13` recovery state and reads its SPI
flash to answer: how much of the original firmware survived, and what did the
camera's healthy USB identity look like (the descriptor tables live in the
firmware body, not the boot sector).

```bash
python3 brick-forensics-0b13.py --check          # inventory only
sudo python3 brick-forensics-0b13.py             # read 64 KiB twice + report
sudo python3 brick-forensics-0b13.py --size 0x20000   # read 128 KiB
```

Produces `brick-forensics.bin` plus a console report: per-4 KiB sector map
(intact / erased / zeros), every embedded USB device descriptor, branding
strings.

## How it works (protocol)

The vendor flash-read path over the camera's UVC extension unit **unit 4** —
identical to the verify step of the vendor flasher and the
[fwupd `sunplus-camera` plugin](https://github.com/fwupd/fwupd/tree/main/plugins/sunplus-camera):

| Transfer | Meaning |
|---|---|
| `SET_CUR` selector `0x0E`, 4 bytes | SPI read pointer (seek) |
| `GET_CUR` selector `0x16`, 64 bytes | read 64 bytes at that pointer |

The flash-write path (`0x09` ISP enable, `0x0A` chunk write, `0x0B` checksum,
`0x0C` finish) and ASIC register writes (`0x02`/`0x03`) are **never used and
are hard-blocked** in these scripts.

## Requirements

- Linux with `uvcvideo` (any recent distro or live USB — no extra packages)
- Python 3.7+
- read/write permission on the camera's `/dev/videoN` node (membership in
  `video`, or `sudo`)

## Safety properties

- The only USB transfers the scripts can emit are the two read controls
  above; anything else raises before reaching the kernel.
- Target allowlists are hardcoded: the donor tool skips IR cameras
  (`5986:211a`, `04f2:b615`) and every known ROM state (`1bcf:0b09`,
  `1bcf:0b13`); the forensics tool talks **only** to `1bcf:0b13`.
- Every dump is read **twice** and discarded unless both passes match.
- Nothing is ever written to the camera. Flash content is not modified by
  reading.

## Related work

- [Shlok-Bhakta's read-only 04F2:B614 dumper](https://gist.github.com/Shlok-Bhakta/7df42a1cdab03d1c0f095a2005b8dd5e)
  — the original script this tooling is adapted from, and
  [the T480s firmware dump](https://gist.github.com/Shlok-Bhakta/5334482f8affd25b9e04d6b5b5b83dd5)
  that proved cross-module images do not transfer.
- [fwupd `sunplus-camera` plugin](https://github.com/fwupd/fwupd/tree/main/plugins/sunplus-camera)
  — documents the vendor XU flash protocol used here.
- [linux-enable-ir-emitter #190](https://github.com/EmixamPP/linux-enable-ir-emitter)
  — the community recovery effort for these modules.

## Disclaimer

Not affiliated with Lenovo or Sunplus Innovation Technology. The firmware
images you dump are device-internal blobs containing no user data; please
share them only with the recovery effort. Flashing a mismatched firmware
image can render the camera module unusable — replacement modules for these
models are inexpensive on the second-hand market. Use at your own risk.

## License

[MIT](LICENSE)
