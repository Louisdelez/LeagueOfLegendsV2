// auto_debug.c - Automatic debugger that traces WSARecvFrom callers
// Launches LoLPrivate.exe under DEBUG_PROCESS, sets breakpoint on WSARecvFrom,
// and logs the return address (caller) when recvfrom returns with data.
//
// Compile: gcc -o auto_debug.exe auto_debug.c -ldbghelp
// Usage: auto_debug.exe

#include <windows.h>
#include <stdio.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#define PSAPI_VERSION 1
#include <psapi.h>

#pragma comment(lib, "dbghelp.lib")

static FILE *logfile = NULL;
static HANDLE hProcess = NULL;
static HANDLE hThread = NULL;
static DWORD pid = 0;
static BYTE origByte = 0;
static DWORD64 bpAddr = 0;
static DWORD64 recvFromAddr = 0;
static int hitCount = 0;
static int maxHits = 20;

// Breakpoint on WSARecvFrom return — we want to see who CALLED it
// Strategy: break on WSARecvFrom entry, read return address from stack,
// then log the caller module+offset

static void Log(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    printf("\n");
    if (logfile) {
        vfprintf(logfile, fmt, args);
        fprintf(logfile, "\n");
        fflush(logfile);
    }
    va_end(args);
}

static DWORD64 FindWSARecvFrom(HANDLE proc) {
    // Get ws2_32.dll base in target process
    HMODULE ws2 = LoadLibraryA("ws2_32.dll");
    if (!ws2) return 0;
    FARPROC p = GetProcAddress(ws2, "WSARecvFrom");
    if (!p) {
        // Try recvfrom
        p = GetProcAddress(ws2, "recvfrom");
    }
    return (DWORD64)p;
}

static DWORD64 FindRecvFrom(HANDLE proc) {
    HMODULE ws2 = LoadLibraryA("ws2_32.dll");
    if (!ws2) return 0;
    return (DWORD64)GetProcAddress(ws2, "recvfrom");
}

static void SetBreakpoint(HANDLE proc, DWORD64 addr) {
    BYTE bp = 0xCC;
    ReadProcessMemory(proc, (LPCVOID)addr, &origByte, 1, NULL);
    WriteProcessMemory(proc, (LPVOID)addr, &bp, 1, NULL);
    FlushInstructionCache(proc, (LPCVOID)addr, 1);
    bpAddr = addr;
    Log("Breakpoint set at 0x%llX", addr);
}

static void RestoreBreakpoint(HANDLE proc, DWORD64 addr) {
    WriteProcessMemory(proc, (LPVOID)addr, &origByte, 1, NULL);
    FlushInstructionCache(proc, (LPCVOID)addr, 1);
}

static void LogContext(HANDLE proc, HANDLE thread, CONTEXT *ctx) {
    hitCount++;
    Log("\n=== WSARecvFrom hit #%d ===", hitCount);

    // Return address is at [RSP]
    DWORD64 retAddr = 0;
    ReadProcessMemory(proc, (LPCVOID)ctx->Rsp, &retAddr, 8, NULL);
    Log("  Return address: 0x%llX", retAddr);

    // Walk the stack manually
    Log("  Stack trace:");
    DWORD64 rsp = ctx->Rsp;
    for (int i = 0; i < 8; i++) {
        DWORD64 val = 0;
        ReadProcessMemory(proc, (LPCVOID)(rsp + i * 8), &val, 8, NULL);

        // Check if this looks like a code address (in the main module range)
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(proc, (LPCVOID)val, &mbi, sizeof(mbi))) {
            if (mbi.Type == MEM_IMAGE && (mbi.Protect & 0xF0)) { // Executable
                // Get module name
                char modName[MAX_PATH] = "???";
                GetModuleFileNameExA(proc, (HMODULE)mbi.AllocationBase, modName, MAX_PATH);
                char *slash = strrchr(modName, '\\');
                if (slash) slash++; else slash = modName;
                DWORD64 offset = val - (DWORD64)mbi.AllocationBase;
                Log("    [RSP+%02X] = 0x%llX (%s+0x%llX)", i*8, val, slash, offset);
            }
        }
    }

    // Also log RCX, RDX (first two args on x64 Windows)
    // WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD cnt, LPDWORD recv, ...)
    Log("  RCX (socket): 0x%llX", ctx->Rcx);
    Log("  RDX (bufs):   0x%llX", ctx->Rdx);
    Log("  R8  (cnt):    0x%llX", ctx->R8);
    Log("  R9  (recv):   0x%llX", ctx->R9);

    // Read the WSABUF structure to get buffer address
    if (ctx->Rdx) {
        DWORD bufLen = 0;
        DWORD64 bufPtr = 0;
        // WSABUF: { ULONG len; CHAR* buf; }
        ReadProcessMemory(proc, (LPCVOID)ctx->Rdx, &bufLen, 4, NULL);
        ReadProcessMemory(proc, (LPCVOID)(ctx->Rdx + 8), &bufPtr, 8, NULL);
        Log("  Buffer: addr=0x%llX len=%u", bufPtr, bufLen);
    }
}

// Need psapi for GetModuleFileNameExA
#define PSAPI_VERSION 1

int main() {
    logfile = fopen("D:\\LeagueOfLegendsV2\\auto_debug_output.log", "w");
    Log("=== LoL Auto Debugger ===");

    // Build command line
    char cmdLine[4096];
    snprintf(cmdLine, sizeof(cmdLine),
        "\"D:\\LeagueOfLegendsV2\\client-private\\Game\\LoLPrivate.exe\" "
        "\"127.0.0.1 5119 17BLOhi6KZsTtldTsizvHg== 1\" "
        "\"-Product=LoL\" \"-PlayerID=1\" \"-GameID=1\" "
        "\"-PlayerNameMode=ALIAS\" \"-LNPBlob=N6oAFO++rd4=\" "
        "\"-GameBaseDir=D:\\LeagueOfLegendsV2\\client-private\" "
        "\"-Region=EUW\" \"-PlatformID=EUW1\" \"-Locale=fr_FR\" "
        "\"-SkipBuild\" \"-EnableCrashpad=false\" "
        "\"-RiotClientPort=51843\" \"-RiotClientAuthToken=test\"");

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};

    Log("Launching: %s", cmdLine);
    Log("Working dir: D:\\LeagueOfLegendsV2\\client-private\\Game");

    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
                       DEBUG_PROCESS | CREATE_NEW_CONSOLE,
                       NULL, "D:\\LeagueOfLegendsV2\\client-private\\Game",
                       &si, &pi)) {
        Log("CreateProcess failed: %lu", GetLastError());
        return 1;
    }

    hProcess = pi.hProcess;
    hThread = pi.hThread;
    pid = pi.dwProcessId;
    Log("Process started, PID=%lu", pid);

    // Find WSARecvFrom address
    recvFromAddr = FindWSARecvFrom(hProcess);
    DWORD64 recvfromAddr2 = FindRecvFrom(hProcess);
    Log("WSARecvFrom at 0x%llX", recvFromAddr);
    Log("recvfrom at 0x%llX", recvfromAddr2);

    BOOL bpSet = FALSE;
    BOOL bpSet2 = FALSE;
    BYTE origByte2 = 0;

    // Debug loop
    DEBUG_EVENT de;
    DWORD continueStatus;
    int eventCount = 0;

    while (WaitForDebugEvent(&de, 30000)) {
        continueStatus = DBG_CONTINUE;
        eventCount++;

        switch (de.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT:
                Log("Process created");
                CloseHandle(de.u.CreateProcessInfo.hFile);
                break;

            case LOAD_DLL_DEBUG_EVENT: {
                // Log DLL loads to find ws2_32.dll
                char dllName[MAX_PATH] = "";
                if (de.u.LoadDll.lpImageName) {
                    DWORD64 namePtr = 0;
                    ReadProcessMemory(hProcess, de.u.LoadDll.lpImageName, &namePtr, 8, NULL);
                    if (namePtr) {
                        if (de.u.LoadDll.fUnicode)
                            ReadProcessMemory(hProcess, (LPCVOID)namePtr, dllName, MAX_PATH, NULL);
                        else
                            ReadProcessMemory(hProcess, (LPCVOID)namePtr, dllName, MAX_PATH, NULL);
                    }
                }
                if (strstr(dllName, "ws2_32") || strstr(dllName, "WS2_32")) {
                    Log("ws2_32.dll loaded at %p", de.u.LoadDll.lpBaseOfDll);
                    // Set breakpoints now
                    if (!bpSet && recvFromAddr) {
                        SetBreakpoint(hProcess, recvFromAddr);
                        bpSet = TRUE;
                    }
                    if (!bpSet2 && recvfromAddr2 && recvfromAddr2 != recvFromAddr) {
                        ReadProcessMemory(hProcess, (LPCVOID)recvfromAddr2, &origByte2, 1, NULL);
                        BYTE bp = 0xCC;
                        WriteProcessMemory(hProcess, (LPVOID)recvfromAddr2, &bp, 1, NULL);
                        FlushInstructionCache(hProcess, (LPCVOID)recvfromAddr2, 1);
                        bpSet2 = TRUE;
                        Log("Breakpoint set on recvfrom at 0x%llX", recvfromAddr2);
                    }
                }
                if (de.u.LoadDll.hFile) CloseHandle(de.u.LoadDll.hFile);
                break;
            }

            case EXCEPTION_DEBUG_EVENT: {
                DWORD code = de.u.Exception.ExceptionRecord.ExceptionCode;
                DWORD64 addr = (DWORD64)de.u.Exception.ExceptionRecord.ExceptionAddress;

                if (code == EXCEPTION_BREAKPOINT) {
                    if (addr == recvFromAddr || addr == recvfromAddr2) {
                        // Get thread context
                        HANDLE ht = OpenThread(THREAD_ALL_ACCESS, FALSE, de.dwThreadId);
                        if (ht) {
                            CONTEXT ctx = {0};
                            ctx.ContextFlags = CONTEXT_FULL;
                            GetThreadContext(ht, &ctx);

                            LogContext(hProcess, ht, &ctx);

                            // Restore original byte and single-step
                            if (addr == recvFromAddr) {
                                RestoreBreakpoint(hProcess, recvFromAddr);
                            } else {
                                WriteProcessMemory(hProcess, (LPVOID)recvfromAddr2, &origByte2, 1, NULL);
                                FlushInstructionCache(hProcess, (LPCVOID)recvfromAddr2, 1);
                            }

                            // Rewind RIP to re-execute the instruction
                            ctx.Rip = addr;
                            ctx.EFlags |= 0x100; // Single-step flag
                            SetThreadContext(ht, &ctx);
                            CloseHandle(ht);

                            if (hitCount >= maxHits) {
                                Log("\nMax hits reached. Detaching...");
                                DebugActiveProcessStop(pid);
                                goto done;
                            }
                        }
                    } else {
                        // System breakpoint or other
                        if (eventCount < 5) Log("System breakpoint at 0x%llX", addr);
                    }
                }
                else if (code == EXCEPTION_SINGLE_STEP) {
                    // Re-set breakpoints after single step
                    if (bpSet) {
                        BYTE bp = 0xCC;
                        WriteProcessMemory(hProcess, (LPVOID)recvFromAddr, &bp, 1, NULL);
                        FlushInstructionCache(hProcess, (LPCVOID)recvFromAddr, 1);
                    }
                    if (bpSet2) {
                        BYTE bp = 0xCC;
                        WriteProcessMemory(hProcess, (LPVOID)recvfromAddr2, &bp, 1, NULL);
                        FlushInstructionCache(hProcess, (LPCVOID)recvfromAddr2, 1);
                    }
                }
                else {
                    // Pass exception to debuggee
                    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                }
                break;
            }

            case EXIT_PROCESS_DEBUG_EVENT:
                Log("Process exited with code %lu", de.u.ExitProcess.dwExitCode);
                goto done;
        }

        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, continueStatus);
    }

done:
    Log("\nDone. %d breakpoint hits.", hitCount);
    if (logfile) fclose(logfile);
    return 0;
}
