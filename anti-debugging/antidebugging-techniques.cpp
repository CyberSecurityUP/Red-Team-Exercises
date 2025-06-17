#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")
#define ProcessDebugPort (PROCESSINFOCLASS)7

// 1. PEB BeingDebugged check
bool isPEBDebugged() {
#ifdef _M_X64
    return (*(BYTE*)(__readgsqword(0x60) + 2)) != 0;
#else
    return (*(BYTE*)(__readfsdword(0x30) + 2)) != 0;
#endif
}

// 2. DebugPort syscall
bool isDebugPortSet() {
    DWORD_PTR debugPort = 0;
    NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &debugPort, sizeof(debugPort), nullptr);
    return debugPort != 0;
}

// 3. Exception handling via __debugbreak (x64-safe)
bool detectExceptionHandling() {
    __try {
        __debugbreak(); // replaces int 3
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// 4. Patch check
bool isIsDebuggerPresentPatched() {
    BYTE expected[] = { 0x64, 0xA1 };  // typical x86, may differ on x64!
    BYTE actual[2];

    FARPROC addr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsDebuggerPresent");
    memcpy(actual, addr, 2);

    return memcmp(actual, expected, 2) != 0;
}

// 5. Timing check
bool detectTiming() {
    LARGE_INTEGER t1, t2, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);

    for (volatile int i = 0; i < 100000; ++i);

    QueryPerformanceCounter(&t2);
    double elapsed = (double)(t2.QuadPart - t1.QuadPart) / freq.QuadPart;
    return elapsed > 0.01;
}

// 6. Debugger windows
bool detectDebuggerWindows() {
    const char* debuggers[] = {
        "x64dbg", "x32dbg", "IDA", "OLLYDBG", "GHIDRA", "Cheat Engine"
    };

    for (const char* name : debuggers) {
        if (FindWindowA(NULL, name)) {
            return true;
        }
    }
    return false;
}

// 7. Hardware breakpoints
bool detectHardwareBreakpoints() {
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE thread = GetCurrentThread();
    if (GetThreadContext(thread, &ctx)) {
        return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
    }
    return false;
}

// Detect loaded debug-related modules
bool detectDebugDrivers() {
    const wchar_t* suspicious[] = {
        L"dbk64", L"dbghelp", L"windbg", L"vboxdrv", L"vmtools"
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32W me32 = {};
    me32.dwSize = sizeof(MODULEENTRY32W);

    if (Module32FirstW(snap, &me32)) {
        do {
            for (const auto& mod : suspicious) {
                if (wcsstr(me32.szModule, mod)) {
                    CloseHandle(snap);
                    return true;
                }
            }
        } while (Module32NextW(snap, &me32));
    }
    CloseHandle(snap);
    return false;
}

bool isDebuggerDetected() {
    return isPEBDebugged() ||
           isDebugPortSet() ||
           detectExceptionHandling() ||
           isIsDebuggerPresentPatched() ||
           detectTiming() ||
           detectDebuggerWindows() ||
           detectHardwareBreakpoints() ||
           detectDebugDrivers();
}

int main() {
    if (isDebuggerDetected()) {
        std::cout << "Debugger detected. Exiting" << std::endl;
        ExitProcess(1);
    }

    std::cout << "Clean execution. No debugger found" << std::endl;
    MessageBoxA(NULL, "Program executed normally!", "Success", MB_OK);
    return 0;
}
