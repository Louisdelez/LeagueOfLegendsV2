/*
 * LoL Network Hook DLL
 *
 * Intercepts sendto/recvfrom from ws2_32.dll to capture
 * UDP packets BEFORE encryption and AFTER decryption.
 *
 * Usage: Place nethook.dll in the game directory and rename
 * a system DLL (like winmm.dll) to load it via DLL proxying.
 * Or use the loader to inject it.
 *
 * Build: gcc -shared -o nethook.dll nethook.c -lws2_32
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <time.h>
#include <stdarg.h>

// Original function pointers
typedef int (WINAPI *sendto_t)(SOCKET s, const char *buf, int len, int flags,
                                const struct sockaddr *to, int tolen);
typedef int (WINAPI *recvfrom_t)(SOCKET s, char *buf, int len, int flags,
                                  struct sockaddr *from, int *fromlen);
typedef int (WINAPI *send_t)(SOCKET s, const char *buf, int len, int flags);
typedef int (WINAPI *recv_t)(SOCKET s, char *buf, int len, int flags);

static sendto_t   real_sendto = NULL;
static recvfrom_t real_recvfrom = NULL;
static send_t     real_send = NULL;
static recv_t     real_recv = NULL;

static FILE *logfile = NULL;
static CRITICAL_SECTION logLock;
static int packetCount = 0;
static char logDir[MAX_PATH] = {0};

static void InitLogging(void) {
    InitializeCriticalSection(&logLock);

    // Create log directory next to the DLL
    GetModuleFileNameA(NULL, logDir, MAX_PATH);
    char *lastSlash = strrchr(logDir, '\\');
    if (lastSlash) *lastSlash = 0;
    strcat(logDir, "\\nethook_logs");
    CreateDirectoryA(logDir, NULL);

    char logPath[MAX_PATH];
    snprintf(logPath, MAX_PATH, "%s\\nethook.log", logDir);
    logfile = fopen(logPath, "w");
    if (logfile) {
        fprintf(logfile, "=== LoL NetHook started ===\n");
        fprintf(logfile, "PID: %d\n", GetCurrentProcessId());
        fflush(logfile);
    }
}

static void Log(const char *fmt, ...) {
    if (!logfile) return;
    EnterCriticalSection(&logLock);

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(logfile, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_list args;
    va_start(args, fmt);
    vfprintf(logfile, fmt, args);
    va_end(args);

    fprintf(logfile, "\n");
    fflush(logfile);
    LeaveCriticalSection(&logLock);
}

static void SavePacket(const char *prefix, const char *buf, int len,
                       const struct sockaddr *addr, int isUDP) {
    packetCount++;

    // Save binary packet
    char filename[MAX_PATH];
    snprintf(filename, MAX_PATH, "%s\\%s_%04d_%dB.bin", logDir, prefix, packetCount, len);
    FILE *f = fopen(filename, "wb");
    if (f) {
        fwrite(buf, 1, len, f);
        fclose(f);
    }

    // Log summary
    char addrStr[64] = "unknown";
    if (addr && addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        snprintf(addrStr, 64, "%s:%d", inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
    }

    Log("%s #%d: %dB to/from %s (UDP=%d)", prefix, packetCount, len, addrStr, isUDP);

    // Log first 32 bytes as hex
    if (logfile) {
        EnterCriticalSection(&logLock);
        fprintf(logfile, "  Hex: ");
        for (int i = 0; i < len && i < 64; i++) {
            fprintf(logfile, "%02X ", (unsigned char)buf[i]);
            if (i == 7 || i == 15 || i == 31) fprintf(logfile, " ");
        }
        if (len > 64) fprintf(logfile, "...");
        fprintf(logfile, "\n");
        fflush(logfile);
        LeaveCriticalSection(&logLock);
    }
}

// === Hooked functions ===

int WINAPI Hooked_sendto(SOCKET s, const char *buf, int len, int flags,
                          const struct sockaddr *to, int tolen) {
    // Only log UDP packets to our server port (5119) or all UDP
    if (to && to->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)to;
        int port = ntohs(sin->sin_port);
        // Log ALL UDP sendto calls
        SavePacket("SEND", buf, len, to, 1);
    }

    return real_sendto(s, buf, len, flags, to, tolen);
}

int WINAPI Hooked_recvfrom(SOCKET s, char *buf, int len, int flags,
                            struct sockaddr *from, int *fromlen) {
    int result = real_recvfrom(s, buf, len, flags, from, fromlen);

    if (result > 0 && from && from->sa_family == AF_INET) {
        SavePacket("RECV", buf, result, from, 1);
    }

    return result;
}

int WINAPI Hooked_send(SOCKET s, const char *buf, int len, int flags) {
    // Log TCP sends too (for LCU WSS)
    SavePacket("TCP_SEND", buf, len, NULL, 0);
    return real_send(s, buf, len, flags);
}

// === IAT Hook implementation ===

static void HookIAT(HMODULE module, const char *dllName, const char *funcName, void *hookFunc, void **origFunc) {
    // Parse PE headers manually to find import table
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE *)module + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

    DWORD importRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA == 0) { Log("No import table"); return; }

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)module + importRVA);

    // Find the target DLL
    for (; importDesc->Name; importDesc++) {
        const char *name = (const char *)((BYTE *)module + importDesc->Name);
        if (_stricmp(name, dllName) != 0) continue;

        PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE *)module + importDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((BYTE *)module + importDesc->FirstThunk);

        for (; origThunk->u1.AddressOfData; origThunk++, firstThunk++) {
            if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;

            PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)
                ((BYTE *)module + origThunk->u1.AddressOfData);

            if (strcmp(importByName->Name, funcName) == 0) {
                // Found it! Replace the function pointer
                DWORD oldProtect;
                VirtualProtect(&firstThunk->u1.Function, sizeof(void *), PAGE_READWRITE, &oldProtect);
                *origFunc = (void *)firstThunk->u1.Function;
                firstThunk->u1.Function = (ULONGLONG)hookFunc;
                VirtualProtect(&firstThunk->u1.Function, sizeof(void *), oldProtect, &oldProtect);
                Log("Hooked %s!%s (orig=%p)", dllName, funcName, *origFunc);
                return;
            }
        }
    }

    Log("Could not find %s!%s in IAT", dllName, funcName);
}

// Alternative: hook via GetProcAddress detour since the game loads dynamically
static FARPROC (WINAPI *real_GetProcAddress)(HMODULE, LPCSTR) = NULL;

FARPROC WINAPI Hooked_GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    FARPROC result = real_GetProcAddress(hModule, lpProcName);

    if (result && lpProcName && !IS_INTRESOURCE(lpProcName)) {
        if (strcmp(lpProcName, "sendto") == 0) {
            Log("Game requesting sendto - hooking!");
            real_sendto = (sendto_t)result;
            return (FARPROC)Hooked_sendto;
        }
        if (strcmp(lpProcName, "recvfrom") == 0) {
            Log("Game requesting recvfrom - hooking!");
            real_recvfrom = (recvfrom_t)result;
            return (FARPROC)Hooked_recvfrom;
        }
        if (strcmp(lpProcName, "send") == 0) {
            Log("Game requesting send - hooking!");
            real_send = (send_t)result;
            return (FARPROC)Hooked_send;
        }
    }

    return result;
}

// Trampoline storage for calling the original function after inline hook
static BYTE trampoline_sendto[32];
static BYTE trampoline_recvfrom[32];

static void MakeTrampoline(void *origFunc, BYTE *trampoline, BYTE *savedBytes) {
    // Copy first 14 original bytes to trampoline
    memcpy(trampoline, origFunc, 14);
    memcpy(savedBytes, origFunc, 14);
    // Then jump back to origFunc + 14
    trampoline[14] = 0xFF;
    trampoline[15] = 0x25;
    *(DWORD *)(trampoline + 16) = 0;
    *(void **)(trampoline + 20) = (BYTE *)origFunc + 14;
    // Make trampoline executable
    DWORD old;
    VirtualProtect(trampoline, 32, PAGE_EXECUTE_READWRITE, &old);
}

static void WriteJmp(void *target, void *dest) {
    DWORD old;
    VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &old);
    BYTE jmp[14] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    *(void **)(jmp + 6) = dest;
    memcpy(target, jmp, 14);
    VirtualProtect(target, 14, old, &old);
}

static void InstallHooks(void) {
    Log("Installing hooks via inline patching...");

    HMODULE ws2 = LoadLibraryA("ws2_32.dll");
    if (!ws2) {
        Log("FATAL: ws2_32.dll not loaded");
        return;
    }

    void *pSendto = (void *)GetProcAddress(ws2, "sendto");
    void *pRecvfrom = (void *)GetProcAddress(ws2, "recvfrom");
    real_send = (send_t)GetProcAddress(ws2, "send");

    Log("ws2_32: sendto=%p recvfrom=%p", pSendto, pRecvfrom);

    if (pSendto) {
        // Create trampoline (original code + jmp back)
        BYTE saved[14];
        MakeTrampoline(pSendto, trampoline_sendto, saved);
        real_sendto = (sendto_t)trampoline_sendto;
        // Overwrite original with jmp to our hook
        WriteJmp(pSendto, Hooked_sendto);
        Log("Inline hooked sendto!");
    }

    if (pRecvfrom) {
        BYTE saved[14];
        MakeTrampoline(pRecvfrom, trampoline_recvfrom, saved);
        real_recvfrom = (recvfrom_t)trampoline_recvfrom;
        WriteJmp(pRecvfrom, Hooked_recvfrom);
        Log("Inline hooked recvfrom!");
    }

    Log("Hooks installed successfully!");
}

// === DLL Entry Point ===

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            InitLogging();
            Log("NetHook DLL loaded into process");
            InstallHooks();
            break;

        case DLL_PROCESS_DETACH:
            Log("NetHook DLL unloading");
            if (logfile) fclose(logfile);
            DeleteCriticalSection(&logLock);
            break;
    }
    return TRUE;
}
