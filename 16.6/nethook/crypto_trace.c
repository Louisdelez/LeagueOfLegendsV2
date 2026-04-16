// crypto_trace.c - Enhanced version.dll proxy that traces crypto after recvfrom
// Compile: gcc -shared -o version.dll crypto_trace.c -lws2_32 -ldbghelp
//
// In addition to capturing packets, this hooks recvfrom and after receiving data,
// scans the call stack and logs what functions process the received buffer.
// It also traces memory reads from the receive buffer to find the decrypt function.

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <dbghelp.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dbghelp.lib")

// ============ Forward declarations for version.dll proxy ============
typedef DWORD (WINAPI *GetFileVersionInfoSizeW_t)(LPCWSTR, LPDWORD);
typedef BOOL (WINAPI *GetFileVersionInfoW_t)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef BOOL (WINAPI *VerQueryValueW_t)(LPCVOID, LPCWSTR, LPVOID*, PUINT);

static GetFileVersionInfoSizeW_t pGetFileVersionInfoSizeW;
static GetFileVersionInfoW_t pGetFileVersionInfoW;
static VerQueryValueW_t pVerQueryValueW;

// Exports
__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR f, LPDWORD h) { return pGetFileVersionInfoSizeW(f, h); }
__declspec(dllexport) BOOL WINAPI GetFileVersionInfoW(LPCWSTR f, DWORD h, DWORD s, LPVOID d) { return pGetFileVersionInfoW(f, h, s, d); }
__declspec(dllexport) BOOL WINAPI VerQueryValueW(LPCVOID b, LPCWSTR s, LPVOID* d, PUINT l) { return pVerQueryValueW(b, s, d, l); }

// ============ Logging ============
static FILE *logfile = NULL;
static CRITICAL_SECTION logLock;
static char logDir[MAX_PATH];
static int pktCount = 0;

static void Log(const char *fmt, ...) {
    if (!logfile) return;
    EnterCriticalSection(&logLock);
    va_list args;
    va_start(args, fmt);
    DWORD t = GetTickCount();
    fprintf(logfile, "[%lu.%03lu] ", t/1000, t%1000);
    vfprintf(logfile, fmt, args);
    fprintf(logfile, "\n");
    fflush(logfile);
    va_end(args);
    LeaveCriticalSection(&logLock);
}

// ============ Packet saving ============
static void SavePacket(const char *tag, const char *buf, int len, struct sockaddr_in *addr) {
    EnterCriticalSection(&logLock);
    pktCount++;
    char fn[MAX_PATH];
    snprintf(fn, MAX_PATH, "%s\\%s_%04d_%dB.bin", logDir, tag, pktCount, len);
    FILE *f = fopen(fn, "wb");
    if (f) { fwrite(buf, 1, len, f); fclose(f); }

    if (addr) {
        Log("%s #%d: %d bytes from %s:%d", tag, pktCount, len,
            inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
    } else {
        Log("%s #%d: %d bytes", tag, pktCount, len);
    }

    // Log first 32 bytes hex
    char hex[256] = {0};
    int hexlen = len < 32 ? len : 32;
    for (int i = 0; i < hexlen; i++)
        sprintf(hex + i*3, "%02X ", (unsigned char)buf[i]);
    Log("  Hex: %s", hex);

    LeaveCriticalSection(&logLock);
}

// ============ Stack trace after recvfrom ============
static void LogStackTrace(void) {
    HANDLE process = GetCurrentProcess();
    HANDLE thread = GetCurrentThread();

    CONTEXT ctx;
    RtlCaptureContext(&ctx);

    STACKFRAME64 frame = {0};
    frame.AddrPC.Offset = ctx.Rip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = ctx.Rbp;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = ctx.Rsp;
    frame.AddrStack.Mode = AddrModeFlat;

    SymInitialize(process, NULL, TRUE);

    Log("  Call stack:");
    for (int i = 0; i < 20; i++) {
        if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, process, thread, &frame,
                        &ctx, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL))
            break;

        DWORD64 addr = frame.AddrPC.Offset;
        DWORD64 moduleBase = SymGetModuleBase64(process, addr);

        char moduleName[256] = "???";
        IMAGEHLP_MODULE64 modInfo = {0};
        modInfo.SizeOfStruct = sizeof(modInfo);
        if (SymGetModuleInfo64(process, addr, &modInfo))
            strncpy(moduleName, modInfo.ModuleName, 255);

        Log("    [%d] %s+0x%llX (0x%llX)", i, moduleName, addr - moduleBase, addr);
    }

    SymCleanup(process);
}

// ============ Inline hooks ============
typedef int (WSAAPI *recvfrom_t)(SOCKET, char*, int, int, struct sockaddr*, int*);
typedef int (WSAAPI *sendto_t)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WSAAPI *WSASendTo_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *WSARecvFrom_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

static recvfrom_t real_recvfrom;
static sendto_t real_sendto;
static WSASendTo_t real_WSASendTo;
static WSARecvFrom_t real_WSARecvFrom;

static unsigned char trampoline_recvfrom[32];
static unsigned char trampoline_sendto[32];
static unsigned char trampoline_WSASendTo[32];
static unsigned char trampoline_WSARecvFrom[32];

static int recvCount = 0;

int WSAAPI Hook_recvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen) {
    int r = ((recvfrom_t)trampoline_recvfrom)(s, buf, len, flags, from, fromlen);
    if (r > 0 && from && from->sa_family == AF_INET) {
        recvCount++;
        SavePacket("RECV", buf, r, (struct sockaddr_in*)from);
        // Log stack trace for first few receives to find the caller
        if (recvCount <= 5) {
            LogStackTrace();
        }
    }
    return r;
}

int WSAAPI Hook_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen) {
    if (to && to->sa_family == AF_INET)
        SavePacket("SEND", buf, len, (struct sockaddr_in*)to);
    return ((sendto_t)trampoline_sendto)(s, buf, len, flags, to, tolen);
}

int WSAAPI Hook_WSASendTo(SOCKET s, LPWSABUF bufs, DWORD cnt, LPDWORD sent, DWORD flags, const struct sockaddr *to, int tolen, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (to && to->sa_family == AF_INET) {
        for (DWORD i = 0; i < cnt; i++)
            SavePacket("WSEND", bufs[i].buf, bufs[i].len, (struct sockaddr_in*)to);
    }
    return ((WSASendTo_t)trampoline_WSASendTo)(s, bufs, cnt, sent, flags, to, tolen, ov, cr);
}

int WSAAPI Hook_WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD cnt, LPDWORD recv, LPDWORD flags, struct sockaddr *from, LPINT fromlen, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    int r = ((WSARecvFrom_t)trampoline_WSARecvFrom)(s, bufs, cnt, recv, flags, from, fromlen, ov, cr);
    if (r == 0 && recv && *recv > 0 && from && from->sa_family == AF_INET) {
        recvCount++;
        for (DWORD i = 0; i < cnt; i++) {
            if (bufs[i].len > 0)
                SavePacket("WRECV", bufs[i].buf, bufs[i].len < *recv ? bufs[i].len : *recv, (struct sockaddr_in*)from);
        }
        if (recvCount <= 5) {
            LogStackTrace();
        }
    }
    return r;
}

// ============ Trampoline / patching ============
static void MakeTrampoline(void *target, unsigned char *tramp) {
    DWORD old;
    VirtualProtect(target, 16, PAGE_EXECUTE_READWRITE, &old);
    memcpy(tramp, target, 16);
    // JMP to original+16
    tramp[16] = 0xFF; tramp[17] = 0x25; *(DWORD*)(tramp+18) = 0;
    *(UINT64*)(tramp+22) = (UINT64)target + 16;
    DWORD tmp;
    VirtualProtect(tramp, 32, PAGE_EXECUTE_READWRITE, &tmp);
    VirtualProtect(target, 16, old, &old);
}

static void PatchJmp(void *target, void *hook) {
    DWORD old;
    VirtualProtect(target, 16, PAGE_EXECUTE_READWRITE, &old);
    // JMP [rip+0]; <addr>
    unsigned char jmp[] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    memcpy(target, jmp, 6);
    *(UINT64*)((unsigned char*)target + 6) = (UINT64)hook;
    VirtualProtect(target, 16, old, &old);
}

static void InstallNetHooks(void) {
    HMODULE ws2 = LoadLibraryA("ws2_32.dll");
    if (!ws2) { Log("Failed to load ws2_32.dll"); return; }

    void *p;

    p = GetProcAddress(ws2, "recvfrom");
    if (p) { MakeTrampoline(p, trampoline_recvfrom); PatchJmp(p, Hook_recvfrom); real_recvfrom = (recvfrom_t)p; }

    p = GetProcAddress(ws2, "sendto");
    if (p) { MakeTrampoline(p, trampoline_sendto); PatchJmp(p, Hook_sendto); real_sendto = (sendto_t)p; }

    p = GetProcAddress(ws2, "WSASendTo");
    if (p) { MakeTrampoline(p, trampoline_WSASendTo); PatchJmp(p, Hook_WSASendTo); real_WSASendTo = (WSASendTo_t)p; }

    p = GetProcAddress(ws2, "WSARecvFrom");
    if (p) { MakeTrampoline(p, trampoline_WSARecvFrom); PatchJmp(p, Hook_WSARecvFrom); real_WSARecvFrom = (WSARecvFrom_t)p; }

    Log("Network hooks installed (sendto, recvfrom, WSASendTo, WSARecvFrom)");
}

// ============ DllMain ============
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);

        // Load real version.dll
        char sysDir[MAX_PATH];
        GetSystemDirectoryA(sysDir, MAX_PATH);
        strcat(sysDir, "\\version.dll");
        HMODULE realVersionDll = LoadLibraryA(sysDir);
        if (realVersionDll) {
            pGetFileVersionInfoSizeW = (GetFileVersionInfoSizeW_t)GetProcAddress(realVersionDll, "GetFileVersionInfoSizeW");
            pGetFileVersionInfoW = (GetFileVersionInfoW_t)GetProcAddress(realVersionDll, "GetFileVersionInfoW");
            pVerQueryValueW = (VerQueryValueW_t)GetProcAddress(realVersionDll, "VerQueryValueW");
        }

        // Init logging
        InitializeCriticalSection(&logLock);
        GetModuleFileNameA(NULL, logDir, MAX_PATH);
        char *sl = strrchr(logDir, '\\'); if (sl) *sl = 0;
        strcat(logDir, "\\nethook_logs");
        CreateDirectoryA(logDir, NULL);
        char lp[MAX_PATH]; snprintf(lp, MAX_PATH, "%s\\crypto_trace.log", logDir);
        logfile = fopen(lp, "w");
        Log("=== LoL Crypto Trace (version.dll proxy) ===");
        Log("PID: %lu", GetCurrentProcessId());

        InstallNetHooks();
    }
    else if (reason == DLL_PROCESS_DETACH) {
        Log("Unloading");
        if (logfile) fclose(logfile);
    }
    return TRUE;
}
