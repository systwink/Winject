#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// ─── Privilege ───────────────────────────────────────────────────────────────

BOOL EnableDebugPrivilege() {
    HANDLE token;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &token)) {
        printf("[-] OpenProcessToken failed: %lu\n", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        printf("[-] LookupPrivilegeValue failed: %lu\n", GetLastError());
        CloseHandle(token);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &tp,
        sizeof(TOKEN_PRIVILEGES),
        NULL, NULL)) {
        printf("[-] AdjustTokenPrivileges failed: %lu\n", GetLastError());
        CloseHandle(token);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[-] SeDebugPrivilege not present in token\n");
        CloseHandle(token);
        return FALSE;
    }

    CloseHandle(token);
    return TRUE;
}

// ─── DLL Injection ───────────────────────────────────────────────────────────

BOOL InjectDLL(HANDLE hProcess, const char* dllPath) {
    size_t pathLen = strlen(dllPath) + 1;

    LPVOID remoteMem = VirtualAllocEx(
        hProcess,
        NULL,
        pathLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!remoteMem) {
        printf("    [-] VirtualAllocEx failed: %lu\n", GetLastError());
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, remoteMem,
        dllPath, pathLen, NULL)) {
        printf("    [-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return FALSE;
    }

    LPVOID loadLibAddr = (LPVOID)GetProcAddress(
        GetModuleHandleA("kernel32.dll"),
        "LoadLibraryA"
    );

    if (!loadLibAddr) {
        printf("    [-] GetProcAddress failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)loadLibAddr,
        remoteMem,
        0,
        NULL
    );

    if (!hThread) {
        printf("    [-] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return FALSE;
    }

    WaitForSingleObject(hThread, 5000);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    if (exitCode == 0) {
        printf("    [-] LoadLibraryA returned NULL in target\n");
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        return FALSE;
    }

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    return TRUE;
}

// ─── Enum + Open + Optionally Inject ─────────────────────────────────────────

void EnumAndOpenAll(const char* dllPath) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    int opened = 0;
    int failed = 0;
    int injected = 0;

    printf("\n%-8s %-40s %s\n", "PID", "Name", "Status");
    printf("%-8s %-40s %s\n", "---", "----", "------");

    if (Process32First(snapshot, &pe)) {
        do {
            HANDLE hProcess = OpenProcess(
                PROCESS_ALL_ACCESS,
                FALSE,
                pe.th32ProcessID
            );

            if (hProcess) {
                printf("[+] %-8lu %-40ls OPENED\n",
                    pe.th32ProcessID,
                    pe.szExeFile);
                opened++;

                if (dllPath) {
                    printf("    [>] Injecting %s...\n", dllPath);
                    if (InjectDLL(hProcess, dllPath)) {
                        printf("    [+] Injected OK\n");
                        injected++;
                    }
                }

                CloseHandle(hProcess);
            }
            else {
                printf("[-] %-8lu %-40ls FAILED (GLE=%lu)\n",
                    pe.th32ProcessID,
                    pe.szExeFile,
                    GetLastError());
                failed++;
            }

        } while (Process32Next(snapshot, &pe));
    }

    CloseHandle(snapshot);

    printf("\n[*] Results: %d opened, %d failed", opened, failed);
    if (dllPath)
        printf(", %d injected", injected);
    printf("\n");
}

// ─── Entry Point ─────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    printf("Winject\n");
    printf("-------\n");

    // usage:
    //   Winject.exe              -- enumerate only
    //   Winject.exe C:\my.dll    -- enumerate and inject into all
    const char* dllPath = (argc > 1) ? argv[1] : NULL;

    if (dllPath)
        printf("[*] DLL injection mode: %s\n", dllPath);
    else
        printf("[*] Enumerate only mode (no DLL specified)\n");

    printf("[*] Enabling SeDebugPrivilege...\n");

    if (!EnableDebugPrivilege()) {
        printf("[-] Failed -- run as admin or SYSTEM\n");
        return 1;
    }

    printf("[+] SeDebugPrivilege enabled\n");
    printf("[*] Enumerating processes...\n");

    EnumAndOpenAll(dllPath);

    return 0;
}