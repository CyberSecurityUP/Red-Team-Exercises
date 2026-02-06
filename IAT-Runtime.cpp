#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <cstdio>

#pragma comment(linker, "/ENTRY:mainCRTStartup")

// =====================================================
// Case-insensitive wide-string substring check
// =====================================================
bool ContainsIgnoreCase(const wchar_t* haystack, const wchar_t* needle)
{
    if (!haystack || !needle) return false;

    wchar_t h[MAX_PATH] = { 0 };
    wchar_t n[MAX_PATH] = { 0 };

    wcsncpy_s(h, haystack, _TRUNCATE);
    wcsncpy_s(n, needle, _TRUNCATE);

    _wcsupr_s(h);
    _wcsupr_s(n);

    return wcsstr(h, n) != nullptr;
}

// =====================================================
// Get kernel32 / kernelbase base via PEB (Windows 10/11)
// =====================================================
HMODULE GetKernelModuleBase()
{
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif

    if (!peb || !peb->Ldr)
        return nullptr;

    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* curr = head->Flink;

    while (curr && curr != head)
    {
        auto entry = CONTAINING_RECORD(
            curr,
            LDR_DATA_TABLE_ENTRY,
            InMemoryOrderLinks
        );

        if (entry->FullDllName.Buffer)
        {
            if (ContainsIgnoreCase(entry->FullDllName.Buffer, L"KERNEL32.DLL") ||
                ContainsIgnoreCase(entry->FullDllName.Buffer, L"KERNELBASE.DLL"))
            {
                return (HMODULE)entry->DllBase;
            }
        }

        curr = curr->Flink;
    }

    return nullptr;
}

// =====================================================
// Manual Export Table resolver
// =====================================================
FARPROC GetExport(HMODULE module, const char* name)
{
    if (!module || !name)
        return nullptr;

    BYTE* base = (BYTE*)module;

    auto dos = (PIMAGE_DOS_HEADER)base;
    auto nt  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

    auto& dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (!dir.VirtualAddress)
        return nullptr;

    auto exp = (PIMAGE_EXPORT_DIRECTORY)(base + dir.VirtualAddress);

    auto names = (DWORD*)(base + exp->AddressOfNames);
    auto ords  = (WORD*)(base + exp->AddressOfNameOrdinals);
    auto funcs = (DWORD*)(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++)
    {
        char* funcName = (char*)(base + names[i]);
        if (strcmp(funcName, name) == 0)
        {
            return (FARPROC)(base + funcs[ords[i]]);
        }
    }

    return nullptr;
}

// =====================================================
// Runtime IAT (reconstructed at runtime)
// =====================================================
struct RUNTIME_IAT
{
    decltype(&CreateThread)        CreateThread;
    decltype(&WaitForSingleObject) WaitForSingleObject;
};

RUNTIME_IAT g_IAT = { 0 };

// =====================================================
// x64-safe visual stack dump
// =====================================================
void DumpStack(const char* label)
{
    printf("\n=== STACK DUMP: %s ===\n", label);

    void** rsp = (void**)_AddressOfReturnAddress();

    for (int i = -4; i < 12; i++)
    {
        printf("RSP %+03X : %p\n", i * 8, rsp[i]);
    }
}

// =====================================================
// Benign thread function
// =====================================================
DWORD WINAPI DemoThread(LPVOID)
{
    DumpStack("Inside DemoThread");
    printf("[Thread] Hello from runtime-resolved APIs.\n");
    return 0;
}

// =====================================================
// Entry point
// =====================================================
int main()
{
    printf("[*] Locating kernel32/kernelbase via PEB...\n");

    HMODULE hKernel = GetKernelModuleBase();
    if (!hKernel)
    {
        printf("[-] Failed to locate kernel32 or kernelbase.\n");
        return -1;
    }

    printf("[+] Module base found at: %p\n", hKernel);

    auto pGetProcAddress =
        (decltype(&GetProcAddress))GetExport(hKernel, "GetProcAddress");

    if (!pGetProcAddress)
    {
        printf("[-] Failed to resolve GetProcAddress.\n");
        return -1;
    }

    g_IAT.CreateThread =
        (decltype(&CreateThread))pGetProcAddress(hKernel, "CreateThread");

    g_IAT.WaitForSingleObject =
        (decltype(&WaitForSingleObject))pGetProcAddress(hKernel, "WaitForSingleObject");

    if (!g_IAT.CreateThread || !g_IAT.WaitForSingleObject)
    {
        printf("[-] Failed to resolve runtime APIs.\n");
        return -1;
    }

    DumpStack("Before CreateThread");

    HANDLE hThread = g_IAT.CreateThread(
        nullptr,
        0,
        DemoThread,
        nullptr,
        0,
        nullptr
    );

    g_IAT.WaitForSingleObject(hThread, INFINITE);

    DumpStack("After Thread Exit");

    printf("[+] Clean execution finished.\n");
    return 0;
}
