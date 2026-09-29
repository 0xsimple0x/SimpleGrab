#pragma once
#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <fstream>
#include <filesystem>

namespace dbcopy {

namespace detail {

using NtQuerySystemInformation_t = NTSTATUS (NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryObject_t            = NTSTATUS (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

constexpr ULONG  kSystemExtendedHandleInformation = 64;
constexpr ULONG  kObjectNameInformation           = 1;
constexpr DWORD  kProcessDupHandle                = 0x0040;
constexpr DWORD  kFileTypeDisk                    = 1;
constexpr NTSTATUS kStatusInfoLengthMismatch      = (NTSTATUS)0xC0000004;

struct SYSHANDLE_ENTRY {
    PVOID     Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG     GrantedAccess;
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;
    ULONG     HandleAttributes;
    ULONG     Reserved;
};

struct SYSHANDLE_INFO {
    ULONG_PTR       NumberOfHandles;
    ULONG_PTR       Reserved;
    SYSHANDLE_ENTRY Handles[1];
};

inline NtQuerySystemInformation_t NtQSI() {
    static auto f = reinterpret_cast<NtQuerySystemInformation_t>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));
    return f;
}

inline NtQueryObject_t NtQO() {
    static auto f = reinterpret_cast<NtQueryObject_t>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject"));
    return f;
}

inline std::vector<uint8_t> SnapshotHandles() {
    auto fn = NtQSI();
    if (!fn) return {};
    size_t size = 1u << 20;
    std::vector<uint8_t> buf;
    for (int i = 0; i < 8; ++i) {
        buf.resize(size);
        ULONG need = 0;
        NTSTATUS st = fn(kSystemExtendedHandleInformation, buf.data(),
                         (ULONG)buf.size(), &need);
        if (st == kStatusInfoLengthMismatch) {
            size = need ? need * 2 : size * 2;
            continue;
        }
        if (st < 0) return {};
        return buf;
    }
    return {};
}

inline USHORT FileObjectTypeIndex(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), 0,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 0;
    USHORT idx = 0;
    auto snap = SnapshotHandles();
    if (!snap.empty()) {
        auto* info = reinterpret_cast<const SYSHANDLE_INFO*>(snap.data());
        DWORD_PTR me = GetCurrentProcessId();
        ULONG_PTR mine = (ULONG_PTR)h;
        size_t n = (size_t)info->NumberOfHandles;
        for (size_t i = 0; i < n; ++i) {
            const auto& e = info->Handles[i];
            if (e.UniqueProcessId == me && (ULONG_PTR)e.HandleValue == mine) {
                idx = e.ObjectTypeIndex;
                break;
            }
        }
    }
    CloseHandle(h);
    return idx;
}

inline std::wstring ObjectName(HANDLE h) {
    auto fn = NtQO();
    if (!fn) return {};
    ULONG size = 1u << 16;
    std::vector<uint8_t> buf(size);
    for (int i = 0; i < 8; ++i) {
        ULONG need = 0;
        NTSTATUS st = fn(h, kObjectNameInformation, buf.data(), size, &need);
        if (st == kStatusInfoLengthMismatch) {
            size = need ? need * 2 : size * 2;
            if (size > (1u << 22)) return {};
            buf.resize(size);
            continue;
        }
        if (st < 0) return {};
        auto* us = reinterpret_cast<const UNICODE_STRING*>(buf.data());
        if (!us->Buffer || !us->Length) return {};
        return std::wstring(us->Buffer, us->Length / sizeof(wchar_t));
    }
    return {};
}

inline bool EndsWithLeaf(const std::wstring& objName, const std::wstring& leaf) {
    if (leaf.empty() || objName.size() < leaf.size() + 1) return false;
    size_t off = objName.size() - leaf.size();
    if (objName[off - 1] != L'\\') return false;
    return _wcsnicmp(objName.c_str() + off, leaf.c_str(), leaf.size()) == 0;
}

inline bool IsBlockedProcess(DWORD pid, std::wstring& imgName) {
    if (pid == 0 || pid == 4) return true;
    static const wchar_t* kBlocked[] = {
        L"svchost.exe", L"csrss.exe", L"smss.exe", L"services.exe",
        L"wininit.exe", L"lsass.exe", L"fontdrvhost.exe", L"dwm.exe",
        L"audiodg.exe", L"system", L"memory compression",
    };
    imgName.clear();
    HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (p) {
        wchar_t buf[MAX_PATH] = {};
        DWORD n = MAX_PATH;
        if (QueryFullProcessImageNameW(p, 0, buf, &n)) {
            const wchar_t* base = wcsrchr(buf, L'\\');
            imgName = base ? base + 1 : buf;
        }
        CloseHandle(p);
    }
    std::wstring lower = imgName;
    for (auto& c : lower) c = (wchar_t)towlower(c);
    for (const wchar_t* b : kBlocked)
        if (lower == b) return true;
    return false;
}

inline bool CopyViaSection(HANDLE h, uint64_t size, const std::filesystem::path& tmp) {
    namespace fs = std::filesystem;
    if (!size || size > (uint64_t)1 << 34) return false;

    HANDLE map = CreateFileMappingW(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!map) return false;
    void* view = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    if (!view) { CloseHandle(map); return false; }

    bool ok = false;
    if (memcmp(view, "SQLite format 3", 15) == 0) {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (out) {
            out.write(reinterpret_cast<const char*>(view), (std::streamsize)size);
            out.flush();
            ok = out.good();
        }
    }
    UnmapViewOfFile(view);
    CloseHandle(map);

    if (!ok) { std::error_code e; fs::remove(tmp, e); }
    return ok;
}

}

inline bool CopyLockedDb(const std::filesystem::path& src,
                         const std::filesystem::path& tmp) {
    namespace fs = std::filesystem;
    using namespace detail;

    std::error_code ec;

    fs::copy_file(src, tmp, fs::copy_options::overwrite_existing, ec);
    if (!ec) return true;
    if (!fs::exists(src, ec)) return false;

    const uintmax_t wantSize = fs::file_size(src, ec);
    if (ec || !wantSize) return false;

    const std::wstring plain = src.filename().wstring();
    std::wstring strict = plain;
    {
        fs::path parent = src.parent_path();
        for (int k = 0; k < 2 && !parent.empty(); ++k) {
            strict = parent.filename().wstring() + L"\\" + strict;
            parent = parent.parent_path();
        }
    }

    struct Strategy { const wchar_t* leaf; bool requireSize; };
    const Strategy strat[3] = {
        { strict.c_str(),  true  },
        { strict.c_str(),  false },
        { plain.c_str(),   false },
    };

    USHORT typeIdx = FileObjectTypeIndex(src.wstring());
    if (!typeIdx) return false;

    auto snap = SnapshotHandles();
    if (snap.empty()) return false;
    auto* info = reinterpret_cast<const SYSHANDLE_INFO*>(snap.data());
    const size_t count = (size_t)info->NumberOfHandles;
    const DWORD self = GetCurrentProcessId();
    HANDLE me = GetCurrentProcess();

    for (const auto& st : strat) {
        const std::wstring leaf = st.leaf;
        HANDLE proc = nullptr;
        DWORD  procPid = 0;
        auto closeProc = [&]() {
            if (proc) { CloseHandle(proc); proc = nullptr; procPid = 0; }
        };

        for (size_t i = 0; i < count; ++i) {
            const auto& e = info->Handles[i];
            if (e.ObjectTypeIndex != typeIdx) continue;
            DWORD pid = (DWORD)e.UniqueProcessId;
            if (pid == self) continue;

            if (procPid != pid) {
                closeProc();
                std::wstring img;
                if (IsBlockedProcess(pid, img)) { procPid = pid; continue; }
                proc = OpenProcess(kProcessDupHandle, FALSE, pid);
                procPid = proc ? pid : 0;
            }
            if (!proc) continue;

            HANDLE dup = nullptr;
            if (!DuplicateHandle(proc, (HANDLE)e.HandleValue, me, &dup, 0, FALSE,
                                 DUPLICATE_SAME_ACCESS))
                continue;
            if (GetFileType(dup) != kFileTypeDisk) { CloseHandle(dup); continue; }

            LARGE_INTEGER sz{};
            bool sizeOk = GetFileSizeEx(dup, &sz) &&
                          (uintmax_t)sz.QuadPart == wantSize;
            if (st.requireSize && !sizeOk) { CloseHandle(dup); continue; }

            bool nameOk = EndsWithLeaf(ObjectName(dup), leaf);
            bool ok = false;
            if (nameOk)
                ok = CopyViaSection(dup, (uint64_t)sz.QuadPart, tmp);
            CloseHandle(dup);
            if (ok) { closeProc(); return true; }
        }
        closeProc();
    }
    return false;
}

}
