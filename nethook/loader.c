/*
 * DLL Injector for NetHook
 * Injects nethook.dll into a running LoLPrivate.exe process.
 *
 * Build: gcc -o loader.exe loader.c
 * Usage: loader.exe <PID>
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

DWORD FindProcessByName(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = {sizeof(pe)};

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

int main(int argc, char *argv[]) {
    printf("=== LoL NetHook Loader ===\n\n");

    // Find the game process
    DWORD pid = 0;
    if (argc > 1) {
        pid = atoi(argv[1]);
    } else {
        pid = FindProcessByName("LoLPrivate.exe");
        if (!pid) pid = FindProcessByName("League of Legends.exe");
    }

    if (!pid) {
        printf("Error: Could not find LoLPrivate.exe\n");
        printf("Start the game first, then run this loader.\n");
        return 1;
    }
    printf("Found game process: PID %d\n", pid);

    // Get full path to nethook.dll
    char dllPath[MAX_PATH];
    GetFullPathNameA("nethook.dll", MAX_PATH, dllPath, NULL);
    printf("DLL path: %s\n", dllPath);

    if (GetFileAttributesA(dllPath) == INVALID_FILE_ATTRIBUTES) {
        printf("Error: nethook.dll not found at %s\n", dllPath);
        return 1;
    }

    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("Error: Could not open process %d (error %d)\n", pid, GetLastError());
        printf("Try running as Administrator.\n");
        return 1;
    }

    // Allocate memory in the target process for the DLL path
    size_t pathLen = strlen(dllPath) + 1;
    LPVOID remotePath = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remotePath) {
        printf("Error: VirtualAllocEx failed\n");
        CloseHandle(hProcess);
        return 1;
    }

    // Write the DLL path to the target process
    WriteProcessMemory(hProcess, remotePath, dllPath, pathLen, NULL);

    // Get LoadLibraryA address (same in all processes)
    FARPROC loadLib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    // Create remote thread to call LoadLibraryA(dllPath)
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLib, remotePath, 0, NULL);

    if (!hThread) {
        printf("Error: CreateRemoteThread failed (error %d)\n", GetLastError());
        printf("Vanguard might be blocking injection. Try with the proxy method instead.\n");
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    printf("Injection thread created! Waiting...\n");
    WaitForSingleObject(hThread, 5000);

    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    printf("Thread exit code: 0x%08X\n", exitCode);

    if (exitCode != 0) {
        printf("SUCCESS! nethook.dll loaded into game process.\n");
        printf("Check the game directory for nethook_logs/ folder.\n");
    } else {
        printf("FAILED: LoadLibraryA returned NULL.\n");
        printf("The DLL might have a dependency issue.\n");
    }

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}
