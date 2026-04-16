// getproc_hook.c - version.dll proxy that hooks GetProcAddress
// When stub.dll calls GetProcAddress(ws2_32, "WSASendTo"), we return OUR function
// which logs the plaintext buffer before calling the real WSASendTo.
// This bypasses anti-debug since we're not a debugger — just a DLL proxy.
//
// Compile: gcc -shared -o version.dll getproc_hook.c -lws2_32

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

// ============ version.dll proxy exports ============
typedef DWORD (WINAPI *GetFileVersionInfoSizeW_t)(LPCWSTR, LPDWORD);
typedef BOOL (WINAPI *GetFileVersionInfoW_t)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef BOOL (WINAPI *VerQueryValueW_t)(LPCVOID, LPCWSTR, LPVOID*, PUINT);

static GetFileVersionInfoSizeW_t pGetFileVersionInfoSizeW;
static GetFileVersionInfoW_t pGetFileVersionInfoW;
static VerQueryValueW_t pVerQueryValueW;

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

static void SavePacket(const char *tag, const char *buf, int len) {
    EnterCriticalSection(&logLock);
    pktCount++;
    char fn[MAX_PATH];
    snprintf(fn, MAX_PATH, "%s\\%s_%04d_%dB.bin", logDir, tag, pktCount, len);
    FILE *f = fopen(fn, "wb");
    if (f) { fwrite(buf, 1, len, f); fclose(f); }

    Log("%s #%d: %d bytes", tag, pktCount, len);

    // Log first 48 bytes hex
    char hex[256] = {0};
    int hexlen = len < 48 ? len : 48;
    for (int i = 0; i < hexlen; i++)
        sprintf(hex + i*3, "%02X ", (unsigned char)buf[i]);
    Log("  %s", hex);

    LeaveCriticalSection(&logLock);
}

// ============ Real function pointers ============
typedef int (WSAAPI *WSASendTo_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *WSARecvFrom_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *sendto_t)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WSAAPI *recvfrom_t)(SOCKET, char*, int, int, struct sockaddr*, int*);

static WSASendTo_t real_WSASendTo = NULL;
static WSARecvFrom_t real_WSARecvFrom = NULL;
static sendto_t real_sendto = NULL;
static recvfrom_t real_recvfrom = NULL;

// ============ Our wrapper functions ============
int WSAAPI Hook_WSASendTo(SOCKET s, LPWSABUF bufs, DWORD cnt, LPDWORD sent, DWORD flags,
                          const struct sockaddr *to, int tolen, LPWSAOVERLAPPED ov,
                          LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    // Log the plaintext BEFORE it gets sent
    for (DWORD i = 0; i < cnt; i++) {
        if (bufs[i].len > 0 && bufs[i].buf) {
            SavePacket("SEND", bufs[i].buf, bufs[i].len);

            // Log the caller's return address (who called WSASendTo)
            void *retAddr = __builtin_return_address(0);
            void *retAddr2 = __builtin_return_address(1);
            Log("  Caller: %p → %p", retAddr, retAddr2);
        }
    }
    return real_WSASendTo(s, bufs, cnt, sent, flags, to, tolen, ov, cr);
}

int WSAAPI Hook_WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD cnt, LPDWORD recv, LPDWORD flags,
                            struct sockaddr *from, LPINT fromlen, LPWSAOVERLAPPED ov,
                            LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    int r = real_WSARecvFrom(s, bufs, cnt, recv, flags, from, fromlen, ov, cr);
    if (r == 0 && recv && *recv > 0) {
        for (DWORD i = 0; i < cnt; i++) {
            if (bufs[i].len > 0 && bufs[i].buf) {
                int recvLen = bufs[i].len < (int)*recv ? bufs[i].len : (int)*recv;
                SavePacket("RECV", bufs[i].buf, recvLen);
            }
        }
    }
    return r;
}

int WSAAPI Hook_sendto(SOCKET s, const char *buf, int len, int flags,
                       const struct sockaddr *to, int tolen) {
    if (buf && len > 0) {
        SavePacket("SEND_ST", buf, len);
        void *retAddr = __builtin_return_address(0);
        Log("  Caller: %p", retAddr);
    }
    return real_sendto(s, buf, len, flags, to, tolen);
}

int WSAAPI Hook_recvfrom(SOCKET s, char *buf, int len, int flags,
                         struct sockaddr *from, int *fromlen) {
    int r = real_recvfrom(s, buf, len, flags, from, fromlen);
    if (r > 0 && buf) {
        SavePacket("RECV_RF", buf, r);
    }
    return r;
}

// ============ GetProcAddress hook ============
typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);
static GetProcAddress_t real_GetProcAddress = NULL;
static unsigned char gpa_trampoline[32];

// Trampoline setup
static void MakeTrampoline(void *target, unsigned char *tramp) {
    DWORD old;
    VirtualProtect(target, 16, PAGE_EXECUTE_READWRITE, &old);
    memcpy(tramp, target, 16);
    tramp[16] = 0xFF; tramp[17] = 0x25; *(DWORD*)(tramp+18) = 0;
    *(UINT64*)(tramp+22) = (UINT64)target + 16;
    DWORD tmp;
    VirtualProtect(tramp, 32, PAGE_EXECUTE_READWRITE, &tmp);
    VirtualProtect(target, 16, old, &old);
}

static void PatchJmp(void *target, void *hook) {
    DWORD old;
    VirtualProtect(target, 16, PAGE_EXECUTE_READWRITE, &old);
    unsigned char jmp[] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    memcpy(target, jmp, 6);
    *(UINT64*)((unsigned char*)target + 6) = (UINT64)hook;
    VirtualProtect(target, 16, old, &old);
}

FARPROC WINAPI Hook_GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    // Call the real GetProcAddress first
    FARPROC result = ((GetProcAddress_t)gpa_trampoline)(hModule, lpProcName);

    if (lpProcName && result) {
        // Intercept network functions
        if (strcmp(lpProcName, "WSASendTo") == 0) {
            Log("*** GetProcAddress(WSASendTo) intercepted! Real=0x%p", result);
            real_WSASendTo = (WSASendTo_t)result;
            return (FARPROC)Hook_WSASendTo;
        }
        if (strcmp(lpProcName, "WSARecvFrom") == 0) {
            Log("*** GetProcAddress(WSARecvFrom) intercepted! Real=0x%p", result);
            real_WSARecvFrom = (WSARecvFrom_t)result;
            return (FARPROC)Hook_WSARecvFrom;
        }
        if (strcmp(lpProcName, "sendto") == 0) {
            Log("*** GetProcAddress(sendto) intercepted! Real=0x%p", result);
            real_sendto = (sendto_t)result;
            return (FARPROC)Hook_sendto;
        }
        if (strcmp(lpProcName, "recvfrom") == 0) {
            Log("*** GetProcAddress(recvfrom) intercepted! Real=0x%p", result);
            real_recvfrom = (recvfrom_t)result;
            return (FARPROC)Hook_recvfrom;
        }
    }

    return result;
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
        char lp[MAX_PATH]; snprintf(lp, MAX_PATH, "%s\\getproc_hook.log", logDir);
        logfile = fopen(lp, "w");
        Log("=== LoL GetProcAddress Hook (version.dll proxy) ===");
        Log("PID: %lu", GetCurrentProcessId());

        // Hook GetProcAddress in kernel32.dll
        HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
        if (kernel32) {
            void *gpa = (void*)GetProcAddress(kernel32, "GetProcAddress");
            if (gpa) {
                MakeTrampoline(gpa, gpa_trampoline);
                PatchJmp(gpa, Hook_GetProcAddress);
                Log("GetProcAddress hooked at %p", gpa);
            } else {
                Log("ERROR: GetProcAddress not found in kernel32");
            }
        }
    }
    else if (reason == DLL_PROCESS_DETACH) {
        Log("Unloading");
        if (logfile) fclose(logfile);
    }
    return TRUE;
}
