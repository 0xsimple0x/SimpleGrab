#!/usr/bin/env python3
"""Generate app.ico for the stub -- a plain, boring desktop-app icon.

windres wants a real ICO (BITMAPINFOHEADER + XOR bitmap + AND mask), not a PNG,
so the pixels are written by hand: a blue panel with a white ring. Nothing here
is decorative for its own sake -- a PE with no icon and no VERSIONINFO is a
feature static models notice, and this is the cheap half of looking like an
ordinary application.

usage: python make_icon.py [output.ico]
"""
import struct
import sys
import os

SIZE = 32


def px(x, y):
    """BGRA for (x, y). Diagonal blue gradient inside a white ring."""
    t = (x + y) / (2 * (SIZE - 1))
    r = int(24 + 44 * t)
    g = int(54 + 74 * t)
    b = int(110 + 100 * t)

    cx, cy = (SIZE - 1) / 2.0, (SIZE - 1) / 2.0
    d = ((x - cx) ** 2 + (y - cy) ** 2) ** 0.5
    if 9.5 <= d <= 13.0:                      # ring
        r, g, b = 236, 242, 250
    elif d < 5.0:                             # centre dot
        r, g, b = 250, 252, 255

    return bytes((b, g, r, 255))              # ICO stores BGRA


def build_bmp():
    """BITMAPINFOHEADER (biHeight doubled for XOR+AND), bottom-up XOR, AND mask."""
    xor = b"".join(
        b"".join(px(x, y) for x in range(SIZE))
        for y in range(SIZE - 1, -1, -1)
    )
    # 32 px per row, each row padded to a 4-byte boundary == 32*4 already
    mask_row = (SIZE + 31) // 32 * 4
    mask = b"\x00" * (mask_row * SIZE)

    hdr = struct.pack(
        "<IiiHHIIiiII",
        40,                # biSize
        SIZE,              # biWidth
        SIZE * 2,          # biHeight (XOR + AND)
        1,                 # biPlanes
        32,                # biBitCount
        0,                 # biCompression = BI_RGB
        len(xor) + len(mask),
        0, 0, 0, 0,        # resolution + colours
    )
    return hdr + xor + mask


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "app.ico")
    img = build_bmp()

    # ICONDIR (6) + one ICONDIRENTRY (16) + pixel data
    icon_dir = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack(
        "<BBBBHHII",
        SIZE if SIZE < 256 else 0,   # width (0 == 256)
        SIZE if SIZE < 256 else 0,   # height
        0,                           # palette size (truecolour)
        0,                           # reserved
        1,                           # colour planes
        32,                          # bits per pixel
        len(img),
        6 + 16,                      # offset to pixel data
    )
    with open(out, "wb") as f:
        f.write(icon_dir + entry + img)
    print(f"[+] icon written : {out}  ({os.path.getsize(out)} B)")


if __name__ == "__main__":
    main()
