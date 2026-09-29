#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <fstream>
#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace abk {

inline std::string TempDir() {
    char b[MAX_PATH] = "C:\\Windows\\Temp\\";
    GetTempPathA(MAX_PATH, b);
    return b;
}
inline std::string ReqPath() { return TempDir() + "abk_req.txt"; }
inline std::string OutPath() { return TempDir() + "abk_out.bin"; }
inline std::string DllPath() { return TempDir() + "abk_hook.dll"; }
inline std::string LogPath() { return TempDir() + "abk.log"; }

inline std::string DllPathFor(DWORD pid) {
    return TempDir() + "abk_" + std::to_string(pid) + ".dll";
}

inline void Log(const char* fmt, ...) {
    char buf[512];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    FILE* f = fopen(LogPath().c_str(), "a");
    if (f) { fputs(buf, f); fputc('\n', f); fclose(f); }
}

inline std::string Narrow(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string s(n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], n, nullptr, nullptr);
    return s;
}

inline bool ExeMatches(DWORD pid, const std::string& want) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    char name[MAX_PATH] = {};
    DWORD n = MAX_PATH;
    bool ok = false;
    if (QueryFullProcessImageNameA(h, 0, name, &n)) {
        const char* base = strrchr(name, '\\');
        base = base ? base + 1 : name;
        ok = _stricmp(base, want.c_str()) == 0;
    }
    CloseHandle(h);
    return ok;
}

struct EnumState { std::string want; DWORD pid; };

inline BOOL CALLBACK EnumBrowser(HWND h, LPARAM lp) {
    auto* st = reinterpret_cast<EnumState*>(lp);
    if (st->pid) return FALSE;
    if (!IsWindowVisible(h)) return TRUE;
    char cls[64] = {};
    GetClassNameA(h, cls, sizeof(cls));
    if (strcmp(cls, "Chrome_WidgetWin_1") != 0) return TRUE;
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid && ExeMatches(pid, st->want)) { st->pid = pid; return FALSE; }
    return TRUE;
}

inline DWORD FindBrowserPid(const std::wstring& exeName) {
    std::string want = Narrow(exeName);
    if (want.empty()) return 0;

    EnumState st{ want, 0 };
    EnumWindows(EnumBrowser, reinterpret_cast<LPARAM>(&st));
    if (st.pid) return st.pid;

    struct Row { DWORD pid, parent; std::string exe; };
    std::vector<Row> rows;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snap, &pe)) do {
        rows.push_back({ pe.th32ProcessID, pe.th32ParentProcessID, Narrow(pe.szExeFile) });
    } while (Process32NextW(snap, &pe));
    CloseHandle(snap);

    for (auto& r : rows) {
        if (_stricmp(r.exe.c_str(), want.c_str()) != 0) continue;
        bool parentIsSame = false;
        for (auto& p : rows)
            if (p.pid == r.parent && _stricmp(p.exe.c_str(), want.c_str()) == 0) {
                parentIsSame = true; break;
            }
        if (!parentIsSame) return r.pid;
    }
    return 0;
}

inline bool WriteReq(const std::wstring& localState, const wchar_t* clsid,
                     const wchar_t* iidV2, const wchar_t* iidV1) {
    std::ofstream f(ReqPath(), std::ios::trunc);
    if (!f) return false;
    f << Narrow(localState) << '|'
      << Narrow(clsid) << '|'
      << Narrow(iidV2) << '|'
      << Narrow(iidV1);
    return (bool)f;
}

inline bool ReadKey(std::vector<uint8_t>& out) {
    std::ifstream f(OutPath(), std::ios::binary);
    if (!f) return false;
    out.assign(std::istreambuf_iterator<char>(f), {});
    return out.size() == 32;
}

inline bool DropDll(const std::string& path, const uint8_t* data, size_t size) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write((const char*)data, size);
    return (bool)f;
}

inline bool InjectLoadLibrary(DWORD pid, const std::string& dll) {
    HANDLE hp = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                            FALSE, pid);
    if (!hp) { Log("[abk] OpenProcess err=%lu", GetLastError()); return false; }

    SIZE_T bytes = dll.size() + 1;
    LPVOID remote = VirtualAllocEx(hp, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { Log("[abk] VirtualAlloc err=%lu", GetLastError()); CloseHandle(hp); return false; }
    WriteProcessMemory(hp, remote, dll.c_str(), bytes, nullptr);

    auto loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE th = CreateRemoteThread(hp, nullptr, 0, loadLib, remote, 0, nullptr);
    if (!th) { Log("[abk] CreateRemoteThread err=%lu", GetLastError());
               VirtualFreeEx(hp, remote, 0, MEM_RELEASE); CloseHandle(hp); return false; }
    WaitForSingleObject(th, 15000);
    CloseHandle(th);
    VirtualFreeEx(hp, remote, 0, MEM_RELEASE);
    CloseHandle(hp);
    return true;
}

inline bool ModuleLoaded(DWORD pid, const std::string& leaf) {
    HANDLE hs = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hs == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me{ sizeof(me) };
    bool found = false;
    if (Module32FirstW(hs, &me)) do {
        if (_stricmp(Narrow(me.szModule).c_str(), leaf.c_str()) == 0) { found = true; break; }
    } while (Module32NextW(hs, &me));
    CloseHandle(hs);
    return found;
}

inline void RemoteFreeLibrary(DWORD pid, const std::string& dllPath) {
    size_t slash = dllPath.find_last_of("\\/");
    std::string leaf = dllPath.substr(slash == std::string::npos ? 0 : slash + 1);

    for (int attempt = 0; attempt < 3; ++attempt) {
        HMODULE target = nullptr;
        HANDLE hs = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hs != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me{ sizeof(me) };
            if (Module32FirstW(hs, &me)) do {
                if (_stricmp(Narrow(me.szModule).c_str(), leaf.c_str()) == 0) {
                    target = me.hModule; break;
                }
            } while (Module32NextW(hs, &me));
            CloseHandle(hs);
        }
        if (!target) return;

        HANDLE hp = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hp) return;
        auto freeLib = (LPTHREAD_START_ROUTINE)GetProcAddress(
            GetModuleHandleA("kernel32.dll"), "FreeLibrary");
        HANDLE th = CreateRemoteThread(hp, nullptr, 0, freeLib, target, 0, nullptr);
        if (th) { WaitForSingleObject(th, 5000); CloseHandle(th); }
        CloseHandle(hp);
        Sleep(150);
        if (!ModuleLoaded(pid, leaf)) return;
    }
}

inline void Cleanup(const std::string& dllPath = {}) {
    DeleteFileA(ReqPath().c_str());
    DeleteFileA(OutPath().c_str());
    DeleteFileA(LogPath().c_str());
    if (!dllPath.empty() &&
        GetFileAttributesA(dllPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
        for (int i = 0; i < 5 && !DeleteFileA(dllPath.c_str()); ++i) Sleep(200);
    }
}


inline std::wstring FindExePath(const std::wstring& exeName, const std::wstring& hint) {
    if (!hint.empty() && GetFileAttributesW(hint.c_str()) != INVALID_FILE_ATTRIBUTES)
        return hint;

    std::wstring sub = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" + exeName;
    const REGSAM views[] = { KEY_WOW64_64KEY, KEY_WOW64_32KEY, 0 };
    for (REGSAM v : views)
        for (HKEY root : { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER }) {
            HKEY k = nullptr;
            if (RegOpenKeyExW(root, sub.c_str(), 0, KEY_QUERY_VALUE | v, &k) != ERROR_SUCCESS)
                continue;
            wchar_t buf[MAX_PATH] = {};
            DWORD sz = sizeof(buf) - sizeof(wchar_t), type = 0;
            LONG rc = RegQueryValueExW(k, nullptr, nullptr, &type,
                                        reinterpret_cast<LPBYTE>(buf), &sz);
            RegCloseKey(k);
            if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ) || !buf[0])
                continue;
            wchar_t exp[MAX_PATH] = {};
            DWORD n = ExpandEnvironmentStringsW(buf, exp, MAX_PATH);
            if (n && n <= MAX_PATH && GetFileAttributesW(exp) != INVALID_FILE_ATTRIBUTES)
                return exp;
        }
    return {};
}

inline DWORD LaunchBrowser(const std::wstring& exe, bool headless) {
    if (exe.empty()) return 0;

    std::wstring wd = exe;
    size_t slash = wd.find_last_of(L'\\');
    if (slash != std::wstring::npos) wd = wd.substr(0, slash);

    std::wstring args = L"\"" + exe + L"\""
        L" --no-first-run --no-default-browser-check"
        L" --disable-extensions --disable-background-networking"
        L" --noerrdialogs --hide-crash-restore-bubble";
    if (headless) args += L" --headless=new --disable-gpu --mute-audio";
    else          args += L" --start-minimized";
    args += L" about:blank";

    std::vector<wchar_t> cmd(args.begin(), args.end());
    cmd.push_back(0);

    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(exe.c_str(), cmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NEW_PROCESS_GROUP, nullptr, wd.c_str(), &si, &pi)) {
        Log("[abk] launch failed err=%lu", GetLastError());
        return 0;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return pi.dwProcessId;
}

inline void KillTree(DWORD root) {
    if (!root) return;
    struct Row { DWORD pid, parent; };
    std::vector<Row> rows;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe{ sizeof(pe) };
        if (Process32FirstW(snap, &pe)) do {
            rows.push_back({ pe.th32ProcessID, pe.th32ParentProcessID });
        } while (Process32NextW(snap, &pe));
        CloseHandle(snap);
    }

    std::vector<DWORD> list;
    list.push_back(root);
    for (bool changed = true; changed; ) {
        changed = false;
        for (auto& r : rows) {
            bool seen = false, kid = false;
            for (DWORD x : list) {
                if (x == r.pid) seen = true;
                if (x == r.parent) kid = true;
            }
            if (!seen && kid) { list.push_back(r.pid); changed = true; }
        }
    }

    auto die = [](DWORD pid) {
        HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (!h) return;
        TerminateProcess(h, 0);
        CloseHandle(h);
    };
    die(root);
    for (DWORD pid : list) if (pid != root) die(pid);
}

inline std::vector<uint8_t> InjectOnce(DWORD pid, const uint8_t* hookDll, size_t hookSize,
                                       const std::wstring& localStatePath,
                                       const wchar_t* clsid, const wchar_t* iidV2,
                                       const wchar_t* iidV1,
                                       std::string* outDll = nullptr)
{
    Log("[abk] pid=%lu", pid);

    std::string dll = DllPathFor(pid);
    if (outDll) *outDll = dll;
    DeleteFileA(OutPath().c_str());
    if (!WriteReq(localStatePath, clsid, iidV2, iidV1)) {
        Log("[abk] req write fail");
        Cleanup();
        return {};
    }
    if (!DropDll(dll, hookDll, hookSize)) { Cleanup(dll); return {}; }
    if (!InjectLoadLibrary(pid, dll)) { Cleanup(dll); return {}; }

    std::vector<uint8_t> key;
    for (int i = 0; i < 100 && key.empty(); ++i) {
        if (ReadKey(key)) break;
        Sleep(100);
    }
    RemoteFreeLibrary(pid, dll);
    const bool gotIt = key.size() == 32;
    if (gotIt) Log("[abk] key ok len=32 (bytes withheld)");
    else       Log("[abk] no key (len=%d)", (int)key.size());
    if (outDll) Cleanup();
    else        Cleanup(dll);
    if (!gotIt) return {};
    return key;
}

inline std::vector<uint8_t> GetAppBoundKeyInjected(
    const uint8_t* hookDll, size_t hookSize,
    const std::wstring& exeName,
    const std::wstring& exeHint,
    const std::wstring& localStatePath,
    const wchar_t* clsid, const wchar_t* iidV2, const wchar_t* iidV1)
{
    DWORD pid = FindBrowserPid(exeName);
    if (pid) return InjectOnce(pid, hookDll, hookSize, localStatePath,
                               clsid, iidV2, iidV1);

    std::wstring exe = FindExePath(exeName, exeHint);
    if (exe.empty()) {
        Log("[abk] no exe for %s", Narrow(exeName).c_str());
        return {};
    }
    DWORD root = LaunchBrowser(exe, true);
    if (!root) return {};

    DWORD p = 0;
    for (int i = 0; i < 100 && !p; ++i) {
        p = FindBrowserPid(exeName);
        if (!p) Sleep(100);
    }

    std::vector<uint8_t> key;
    std::string dll;
    if (p) key = InjectOnce(p, hookDll, hookSize, localStatePath,
                            clsid, iidV2, iidV1, &dll);
    KillTree(root);
    Cleanup(dll);
    return key;
}

}
