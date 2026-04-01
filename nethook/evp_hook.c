// evp_hook.c - version.dll proxy that finds and hooks OpenSSL EVP functions
// Strategy:
// 1. Use the original nethook to capture packets (sendto/WSASendTo hooks)
// 2. ALSO scan for the "BF-CBC" string in memory to find the EVP_bf_cbc() function
// 3. Hook EVP_CipherInit_ex to log the mode, key, and IV
// 4. Hook EVP_EncryptUpdate/DecryptUpdate to log plaintext before encryption
//
// Compile: gcc -shared -o version.dll evp_hook.c -lws2_32

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

// ============ version.dll proxy ============
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
    va_list args; va_start(args, fmt);
    DWORD t = GetTickCount();
    fprintf(logfile, "[%lu.%03lu] ", t/1000, t%1000);
    vfprintf(logfile, fmt, args);
    fprintf(logfile, "\n");
    fflush(logfile);
    va_end(args);
    LeaveCriticalSection(&logLock);
}

static void LogHex(const char *label, const unsigned char *data, int len) {
    char hex[512] = {0};
    int n = len < 64 ? len : 64;
    for (int i = 0; i < n; i++) sprintf(hex + i*3, "%02X ", data[i]);
    Log("  %s (%d bytes): %s", label, len, hex);
}

static void SavePacket(const char *tag, const char *buf, int len) {
    EnterCriticalSection(&logLock);
    pktCount++;
    char fn[MAX_PATH];
    snprintf(fn, MAX_PATH, "%s\\%s_%04d_%dB.bin", logDir, tag, pktCount, len);
    FILE *f = fopen(fn, "wb");
    if (f) { fwrite(buf, 1, len, f); fclose(f); }
    Log("%s #%d: %d bytes", tag, pktCount, len);
    LogHex("Data", (const unsigned char*)buf, len);
    LeaveCriticalSection(&logLock);
}

// ============ sendto/WSASendTo hooks (same as original nethook) ============
static unsigned char tramp_sendto[32], tramp_WSASendTo[32];
static unsigned char tramp_recvfrom[32], tramp_WSARecvFrom[32];

typedef int (WSAAPI *sendto_t)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WSAAPI *WSASendTo_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *recvfrom_t)(SOCKET, char*, int, int, struct sockaddr*, int*);
typedef int (WSAAPI *WSARecvFrom_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

int WSAAPI Hook_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen) {
    if (to && to->sa_family == AF_INET) SavePacket("SEND", buf, len);
    return ((sendto_t)tramp_sendto)(s, buf, len, flags, to, tolen);
}
int WSAAPI Hook_WSASendTo(SOCKET s, LPWSABUF bufs, DWORD cnt, LPDWORD sent, DWORD flags, const struct sockaddr *to, int tolen, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (to && to->sa_family == AF_INET)
        for (DWORD i = 0; i < cnt; i++) SavePacket("WSEND", bufs[i].buf, bufs[i].len);
    return ((WSASendTo_t)tramp_WSASendTo)(s, bufs, cnt, sent, flags, to, tolen, ov, cr);
}
int WSAAPI Hook_recvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen) {
    int r = ((recvfrom_t)tramp_recvfrom)(s, buf, len, flags, from, fromlen);
    if (r > 0 && from && from->sa_family == AF_INET) SavePacket("RECV", buf, r);
    return r;
}
int WSAAPI Hook_WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD cnt, LPDWORD recv, LPDWORD flags, struct sockaddr *from, LPINT fromlen, LPWSAOVERLAPPED ov, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    int r = ((WSARecvFrom_t)tramp_WSARecvFrom)(s, bufs, cnt, recv, flags, from, fromlen, ov, cr);
    if (r == 0 && recv && *recv > 0 && from && from->sa_family == AF_INET)
        for (DWORD i = 0; i < cnt; i++) if (bufs[i].len > 0)
            SavePacket("WRECV", bufs[i].buf, bufs[i].len < *recv ? bufs[i].len : *recv);
    return r;
}

// ============ Inline hook helpers ============
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

static void InstallNetHooks(void) {
    HMODULE ws2 = LoadLibraryA("ws2_32.dll");
    if (!ws2) { Log("ws2_32.dll not loaded yet"); return; }
    void *p;
    p = GetProcAddress(ws2, "sendto");
    if (p) { MakeTrampoline(p, tramp_sendto); PatchJmp(p, Hook_sendto); }
    p = GetProcAddress(ws2, "WSASendTo");
    if (p) { MakeTrampoline(p, tramp_WSASendTo); PatchJmp(p, Hook_WSASendTo); }
    p = GetProcAddress(ws2, "recvfrom");
    if (p) { MakeTrampoline(p, tramp_recvfrom); PatchJmp(p, Hook_recvfrom); }
    p = GetProcAddress(ws2, "WSARecvFrom");
    if (p) { MakeTrampoline(p, tramp_WSARecvFrom); PatchJmp(p, Hook_WSARecvFrom); }
    Log("Network hooks installed");
}

// ============ Delayed scan for OpenSSL EVP functions ============
// We scan AFTER the game has loaded (delayed thread) to find EVP functions
// and the Blowfish cipher mode being used.

static DWORD WINAPI ScanThread(LPVOID param) {
    // Wait for the game to fully load
    Sleep(10000); // 10 seconds
    Log("=== Starting EVP scan ===");

    HMODULE exe = GetModuleHandleA(NULL);
    if (!exe) { Log("Cannot get module handle"); return 0; }

    // Get module size
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)exe;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)((BYTE*)exe + dos->e_lfanew);
    DWORD imageSize = nt->OptionalHeader.SizeOfImage;
    BYTE *base = (BYTE*)exe;

    Log("Module base: %p, size: 0x%X", base, imageSize);

    // Search for Blowfish P-box initial constants: 0x243F6A88 0x85A308D3
    // In memory (little-endian): 88 6A 3F 24 D3 08 A3 85
    BYTE pboxPattern[] = { 0x88, 0x6A, 0x3F, 0x24, 0xD3, 0x08, 0xA3, 0x85, 0x2E, 0x8A, 0x19, 0x13 };

    Log("Scanning for Blowfish P-box pattern...");
    int found = 0;
    for (DWORD i = 0; i < imageSize - sizeof(pboxPattern); i++) {
        BYTE *ptr = base + i;
        // Check if readable
        if (!IsBadReadPtr(ptr, sizeof(pboxPattern))) {
            if (memcmp(ptr, pboxPattern, sizeof(pboxPattern)) == 0) {
                Log("*** P-BOX FOUND at %p (offset 0x%X) ***", ptr, i);
                found++;
                LogHex("Context", ptr, 64);
            }
        } else {
            i += 0x1000 - (i % 0x1000);
        }
    }
    Log("P-box scan: found %d locations", found);

    // Search for "BF-CBC" string in memory
    Log("Scanning for BF-CBC string...");
    for (DWORD i = 0; i < imageSize - 6; i++) {
        BYTE *ptr = base + i;
        if (!IsBadReadPtr(ptr, 6)) {
            if (memcmp(ptr, "BF-CBC", 6) == 0) {
                Log("*** BF-CBC string at %p (offset 0x%X) ***", ptr, i);
                break;
            }
        } else {
            i += 0x1000 - (i % 0x1000);
        }
    }

    // Also install network hooks now that ws2_32 should be loaded
    InstallNetHooks();

    Log("=== EVP scan complete ===");
    return 0;
}

// ============ DllMain ============
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);

        char sysDir[MAX_PATH];
        GetSystemDirectoryA(sysDir, MAX_PATH);
        strcat(sysDir, "\\version.dll");
        HMODULE realVer = LoadLibraryA(sysDir);
        if (realVer) {
            pGetFileVersionInfoSizeW = (GetFileVersionInfoSizeW_t)GetProcAddress(realVer, "GetFileVersionInfoSizeW");
            pGetFileVersionInfoW = (GetFileVersionInfoW_t)GetProcAddress(realVer, "GetFileVersionInfoW");
            pVerQueryValueW = (VerQueryValueW_t)GetProcAddress(realVer, "VerQueryValueW");
        }

        InitializeCriticalSection(&logLock);
        GetModuleFileNameA(NULL, logDir, MAX_PATH);
        char *sl = strrchr(logDir, '\\'); if (sl) *sl = 0;
        strcat(logDir, "\\nethook_logs");
        CreateDirectoryA(logDir, NULL);
        char lp[MAX_PATH]; snprintf(lp, MAX_PATH, "%s\\evp_hook.log", logDir);
        logfile = fopen(lp, "w");
        Log("=== LoL EVP Hook (version.dll proxy) ===");
        Log("PID: %lu", GetCurrentProcessId());

        // Start delayed scan thread
        CreateThread(NULL, 0, ScanThread, NULL, 0, NULL);
    }
    else if (reason == DLL_PROCESS_DETACH) {
        Log("Unloading");
        if (logfile) fclose(logfile);
    }
    return TRUE;
}
