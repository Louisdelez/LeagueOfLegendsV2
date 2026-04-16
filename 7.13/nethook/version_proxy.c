/*
 * version.dll proxy for LoL 7.13 — minimal network capture hook (x86).
 *   gcc -shared -o version.dll version_proxy.c -lws2_32 -O2
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdarg.h>

static HMODULE realVersionDll = NULL;

typedef DWORD (WINAPI *GetFileVersionInfoSizeA_t)(LPCSTR, LPDWORD);
typedef BOOL  (WINAPI *GetFileVersionInfoA_t)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL  (WINAPI *VerQueryValueA_t)(LPCVOID, LPCSTR, LPVOID *, PUINT);
typedef DWORD (WINAPI *GetFileVersionInfoSizeW_t)(LPCWSTR, LPDWORD);
typedef BOOL  (WINAPI *GetFileVersionInfoW_t)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef BOOL  (WINAPI *VerQueryValueW_t)(LPCVOID, LPCWSTR, LPVOID *, PUINT);

static GetFileVersionInfoSizeA_t pGetFileVersionInfoSizeA;
static GetFileVersionInfoA_t     pGetFileVersionInfoA;
static VerQueryValueA_t          pVerQueryValueA;
static GetFileVersionInfoSizeW_t pGetFileVersionInfoSizeW;
static GetFileVersionInfoW_t     pGetFileVersionInfoW;
static VerQueryValueW_t          pVerQueryValueW;

__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeA(LPCSTR fn, LPDWORD h)    { return pGetFileVersionInfoSizeA ? pGetFileVersionInfoSizeA(fn, h) : 0; }
__declspec(dllexport) BOOL  WINAPI GetFileVersionInfoA(LPCSTR fn, DWORD h, DWORD sz, LPVOID d) { return pGetFileVersionInfoA ? pGetFileVersionInfoA(fn, h, sz, d) : FALSE; }
__declspec(dllexport) BOOL  WINAPI VerQueryValueA(LPCVOID b, LPCSTR s, LPVOID *p, PUINT l) { return pVerQueryValueA ? pVerQueryValueA(b, s, p, l) : FALSE; }
__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR fn, LPDWORD h)   { return pGetFileVersionInfoSizeW ? pGetFileVersionInfoSizeW(fn, h) : 0; }
__declspec(dllexport) BOOL  WINAPI GetFileVersionInfoW(LPCWSTR fn, DWORD h, DWORD sz, LPVOID d) { return pGetFileVersionInfoW ? pGetFileVersionInfoW(fn, h, sz, d) : FALSE; }
__declspec(dllexport) BOOL  WINAPI VerQueryValueW(LPCVOID b, LPCWSTR s, LPVOID *p, PUINT l) { return pVerQueryValueW ? pVerQueryValueW(b, s, p, l) : FALSE; }

static FILE *logfile = NULL;
static CRITICAL_SECTION logLock;
static char logDir[MAX_PATH];
static int pktCount = 0;

static void Log(const char *fmt, ...) {
    if (!logfile) return;
    EnterCriticalSection(&logLock);
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(logfile, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list ap; va_start(ap, fmt);
    vfprintf(logfile, fmt, ap);
    va_end(ap);
    fprintf(logfile, "\n");
    fflush(logfile);
    LeaveCriticalSection(&logLock);
}

static void SavePacket(const char *tag, const char *buf, int len, const struct sockaddr *addr) {
    pktCount++;
    char addrStr[64] = "?";
    if (addr && addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in*)addr;
        snprintf(addrStr, 64, "%s:%d", inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
    }
    if (logfile) {
        EnterCriticalSection(&logLock);
        fprintf(logfile, "  [%s #%d] %s %dB\n    ", tag, pktCount, addrStr, len);
        for (int i = 0; i < len && i < 64; i++)
            fprintf(logfile, "%02X ", (unsigned char)buf[i]);
        if (len > 64) fprintf(logfile, "...(+%d)", len-64);
        fprintf(logfile, "\n");
        fflush(logfile);
        LeaveCriticalSection(&logLock);
    }
    char fn[MAX_PATH];
    snprintf(fn, MAX_PATH, "%s\\%s_%04d_%dB.bin", logDir, tag, pktCount, len);
    FILE *f = fopen(fn, "wb");
    if (f) { fwrite(buf, 1, len, f); fclose(f); }
}

#define HOOK_SIZE 5
static BYTE tramp_sendto[32], tramp_recvfrom[32], tramp_WSASendTo[32], tramp_WSARecvFrom[32], tramp_connect[32];

typedef int (WINAPI *sendto_t)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WINAPI *recvfrom_t)(SOCKET, char*, int, int, struct sockaddr*, int*);
typedef int (WINAPI *WSASendTo_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WINAPI *WSARecvFrom_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WINAPI *connect_t)(SOCKET, const struct sockaddr*, int);

static sendto_t      real_sendto;
static recvfrom_t    real_recvfrom;
static WSASendTo_t   real_WSASendTo;
static WSARecvFrom_t real_WSARecvFrom;
static connect_t     real_connect;

static void MakeTrampoline5(void *func, BYTE *tramp) {
    memcpy(tramp, func, HOOK_SIZE);
    tramp[HOOK_SIZE] = 0xE9;
    DWORD rel = (DWORD)((BYTE*)func + HOOK_SIZE) - (DWORD)(tramp + HOOK_SIZE + 5);
    *(DWORD*)(tramp + HOOK_SIZE + 1) = rel;
    DWORD old;
    VirtualProtect(tramp, 32, PAGE_EXECUTE_READWRITE, &old);
    FlushInstructionCache(GetCurrentProcess(), tramp, 32);
}

static void PatchJmp5(void *target, void *dest) {
    DWORD old;
    VirtualProtect(target, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &old);
    BYTE *t = (BYTE*)target;
    t[0] = 0xE9;
    DWORD rel = (DWORD)dest - ((DWORD)target + 5);
    *(DWORD*)(t + 1) = rel;
    VirtualProtect(target, HOOK_SIZE, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, HOOK_SIZE);
}

int WINAPI Hook_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen) {
    if (to && to->sa_family == AF_INET) SavePacket("SEND", buf, len, to);
    return real_sendto(s, buf, len, flags, to, tolen);
}

int WINAPI Hook_recvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen) {
    int r = real_recvfrom(s, buf, len, flags, from, fromlen);
    if (r > 0) SavePacket("RECV", buf, r, from);
    return r;
}

int WINAPI Hook_WSASendTo(SOCKET s, LPWSABUF bufs, DWORD n, LPDWORD sent, DWORD flags, const struct sockaddr *to, int tolen, LPWSAOVERLAPPED ovl, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (to && to->sa_family == AF_INET) {
        for (DWORD i = 0; i < n; i++) {
            if (bufs[i].len > 0) SavePacket("WSASEND", bufs[i].buf, bufs[i].len, to);
        }
    }
    return real_WSASendTo(s, bufs, n, sent, flags, to, tolen, ovl, cr);
}

int WINAPI Hook_WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD n, LPDWORD rec, LPDWORD flags, struct sockaddr *from, LPINT fromlen, LPWSAOVERLAPPED ovl, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    int r = real_WSARecvFrom(s, bufs, n, rec, flags, from, fromlen, ovl, cr);
    if (r == 0 && rec && *rec > 0) {
        DWORD remaining = *rec;
        for (DWORD i = 0; i < n && remaining > 0; i++) {
            DWORD chunk = bufs[i].len < remaining ? bufs[i].len : remaining;
            if (chunk > 0) SavePacket("WSARECV", bufs[i].buf, chunk, from);
            remaining -= chunk;
        }
    }
    return r;
}

int WINAPI Hook_connect(SOCKET s, const struct sockaddr *addr, int addrlen) {
    if (addr && addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in*)addr;
        Log("CONNECT: socket=%lu -> %s:%d",
            (unsigned long)s, inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
    }
    return real_connect(s, addr, addrlen);
}

static void InstallNetHooks(void) {
    HMODULE ws2 = LoadLibraryA("ws2_32.dll");
    if (!ws2) { Log("Can't load ws2_32"); return; }
    void *p;
    p = GetProcAddress(ws2, "sendto");
    if (p) { MakeTrampoline5(p, tramp_sendto); real_sendto = (sendto_t)tramp_sendto; PatchJmp5(p, Hook_sendto); Log("Hook sendto @ %p", p); }
    p = GetProcAddress(ws2, "recvfrom");
    if (p) { MakeTrampoline5(p, tramp_recvfrom); real_recvfrom = (recvfrom_t)tramp_recvfrom; PatchJmp5(p, Hook_recvfrom); Log("Hook recvfrom @ %p", p); }
    p = GetProcAddress(ws2, "WSASendTo");
    if (p) { MakeTrampoline5(p, tramp_WSASendTo); real_WSASendTo = (WSASendTo_t)tramp_WSASendTo; PatchJmp5(p, Hook_WSASendTo); Log("Hook WSASendTo @ %p", p); }
    p = GetProcAddress(ws2, "WSARecvFrom");
    if (p) { MakeTrampoline5(p, tramp_WSARecvFrom); real_WSARecvFrom = (WSARecvFrom_t)tramp_WSARecvFrom; PatchJmp5(p, Hook_WSARecvFrom); Log("Hook WSARecvFrom @ %p", p); }
    p = GetProcAddress(ws2, "connect");
    if (p) { MakeTrampoline5(p, tramp_connect); real_connect = (connect_t)tramp_connect; PatchJmp5(p, Hook_connect); Log("Hook connect @ %p", p); }
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        char sysDir[MAX_PATH];
        GetSystemDirectoryA(sysDir, MAX_PATH);
        strcat(sysDir, "\\version.dll");
        realVersionDll = LoadLibraryA(sysDir);
        if (realVersionDll) {
            pGetFileVersionInfoSizeA = (GetFileVersionInfoSizeA_t)GetProcAddress(realVersionDll, "GetFileVersionInfoSizeA");
            pGetFileVersionInfoA     = (GetFileVersionInfoA_t    )GetProcAddress(realVersionDll, "GetFileVersionInfoA");
            pVerQueryValueA          = (VerQueryValueA_t         )GetProcAddress(realVersionDll, "VerQueryValueA");
            pGetFileVersionInfoSizeW = (GetFileVersionInfoSizeW_t)GetProcAddress(realVersionDll, "GetFileVersionInfoSizeW");
            pGetFileVersionInfoW     = (GetFileVersionInfoW_t    )GetProcAddress(realVersionDll, "GetFileVersionInfoW");
            pVerQueryValueW          = (VerQueryValueW_t         )GetProcAddress(realVersionDll, "VerQueryValueW");
        }
        InitializeCriticalSection(&logLock);
        GetModuleFileNameA(NULL, logDir, MAX_PATH);
        char *sl = strrchr(logDir, '\\'); if (sl) *sl = 0;
        strcat(logDir, "\\nethook_logs");
        CreateDirectoryA(logDir, NULL);
        char lp[MAX_PATH];
        snprintf(lp, MAX_PATH, "%s\\nethook.log", logDir);
        logfile = fopen(lp, "w");
        Log("=== LoL 7.13 NetHook (x86) ===");
        Log("PID %lu", GetCurrentProcessId());
        InstallNetHooks();
        Log("cmdline: %s", GetCommandLineA());
    }
    else if (reason == DLL_PROCESS_DETACH) {
        Log("Unloading");
        if (logfile) fclose(logfile);
        if (realVersionDll) FreeLibrary(realVersionDll);
    }
    return TRUE;
}
