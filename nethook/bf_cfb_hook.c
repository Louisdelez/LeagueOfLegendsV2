// bf_cfb_hook.c - Hook BF_cfb64_encrypt in LoLPrivate.exe
// FUN_1410f2ce0 at offset 0x10f2ce0 from image base
// Signature: void BF_cfb64_encrypt(BF_KEY *key, void *in, void *out, size_t len, int enc)
//
// Also hooks sendto/WSASendTo for packet capture.
// Compile: gcc -shared -o version.dll bf_cfb_hook.c -lws2_32 -O2

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

// version.dll proxy
typedef DWORD (WINAPI *GFVISW_t)(LPCWSTR, LPDWORD);
typedef BOOL (WINAPI *GFVIW_t)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef BOOL (WINAPI *VQV_t)(LPCVOID, LPCWSTR, LPVOID*, PUINT);
static GFVISW_t pGFVISW; static GFVIW_t pGFVIW; static VQV_t pVQV;
__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR f, LPDWORD h) { return pGFVISW(f, h); }
__declspec(dllexport) BOOL WINAPI GetFileVersionInfoW(LPCWSTR f, DWORD h, DWORD s, LPVOID d) { return pGFVIW(f, h, s, d); }
__declspec(dllexport) BOOL WINAPI VerQueryValueW(LPCVOID b, LPCWSTR s, LPVOID* d, PUINT l) { return pVQV(b, s, d, l); }

// Logging
static FILE *logfile = NULL;
static CRITICAL_SECTION logLock;
static char logDir[MAX_PATH];
static int cfbCallCount = 0;

static void Log(const char *fmt, ...) {
    if (!logfile) return;
    EnterCriticalSection(&logLock);
    va_list a; va_start(a, fmt);
    fprintf(logfile, "[%lu] ", GetTickCount());
    vfprintf(logfile, fmt, a);
    fprintf(logfile, "\n");
    fflush(logfile);
    va_end(a);
    LeaveCriticalSection(&logLock);
}

static void LogHex(const char *lbl, const void *data, int len) {
    char hex[512] = {0};
    int n = len < 64 ? len : 64;
    const unsigned char *p = (const unsigned char *)data;
    for (int i = 0; i < n; i++) sprintf(hex+i*3, "%02X ", p[i]);
    Log("  %s(%d): %s", lbl, len, hex);
}

// BF_cfb64_encrypt hook
typedef void (*BF_cfb64_encrypt_t)(void*, void*, void*, unsigned long long, int);
static unsigned char bf_trampoline[32];

void Hook_BF_cfb64_encrypt(void *key, void *in, void *out, unsigned long long len, int enc) {
    cfbCallCount++;
    if (cfbCallCount <= 50) {
        Log("BF_cfb64_encrypt #%d: key=%p in=%p out=%p len=%llu enc=%d",
            cfbCallCount, key, in, out, len, enc);

        // Log the IV (stored at key+8, 8 bytes)
        LogHex("IV(key+8)", (char*)key + 8, 8);

        // Log first 32 bytes of input
        LogHex("Input", in, (int)(len < 32 ? len : 32));

        // Log key structure header (first 16 bytes = initial state + current IV)
        LogHex("KeyHdr", key, 16);
    }

    // Call original
    ((BF_cfb64_encrypt_t)bf_trampoline)(key, in, out, len, enc);

    if (cfbCallCount <= 50) {
        LogHex("Output", out, (int)(len < 32 ? len : 32));
    }
}

// Inline hook helpers
static void MakeTrampoline(void *target, unsigned char *tramp) {
    DWORD old; VirtualProtect(target, 16, PAGE_EXECUTE_READWRITE, &old);
    memcpy(tramp, target, 16);
    tramp[16] = 0xFF; tramp[17] = 0x25; *(DWORD*)(tramp+18) = 0;
    *(UINT64*)(tramp+22) = (UINT64)target + 16;
    DWORD tmp; VirtualProtect(tramp, 32, PAGE_EXECUTE_READWRITE, &tmp);
    VirtualProtect(target, 16, old, &old);
}
static void PatchJmp(void *target, void *hook) {
    DWORD old; VirtualProtect(target, 16, PAGE_EXECUTE_READWRITE, &old);
    unsigned char jmp[] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    memcpy(target, jmp, 6);
    *(UINT64*)((char*)target + 6) = (UINT64)hook;
    VirtualProtect(target, 16, old, &old);
}

// Network hooks (same as before)
static unsigned char st_tramp[32], wst_tramp[32], rf_tramp[32], wrf_tramp[32];
typedef int (WSAAPI *sendto_t)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WSAAPI *WSASendTo_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
int WSAAPI Hook_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen) {
    if (to && to->sa_family == AF_INET && len > 0) { Log("SEND %d bytes", len); LogHex("Data", buf, len); }
    return ((sendto_t)st_tramp)(s, buf, len, flags, to, tolen);
}
int WSAAPI Hook_WSASendTo(SOCKET s, LPWSABUF b, DWORD c, LPDWORD sent, DWORD f, const struct sockaddr *to, int tl, LPWSAOVERLAPPED o, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (to && to->sa_family == AF_INET) for (DWORD i=0;i<c;i++) { Log("WSEND %d bytes", b[i].len); LogHex("Data", b[i].buf, b[i].len); }
    return ((WSASendTo_t)wst_tramp)(s, b, c, sent, f, to, tl, o, cr);
}

static DWORD WINAPI DelayedHook(LPVOID param) {
    Sleep(2000);

    // Hook BF_cfb64_encrypt at offset 0x10f2ce0 from exe base
    HMODULE exe = GetModuleHandleA(NULL);
    if (exe) {
        void *bf_cfb = (void*)((char*)exe + 0x10f2ce0);
        Log("Hooking BF_cfb64_encrypt at %p (exe+0x10f2ce0)", bf_cfb);
        MakeTrampoline(bf_cfb, bf_trampoline);
        PatchJmp(bf_cfb, Hook_BF_cfb64_encrypt);
        Log("BF_cfb64_encrypt hooked!");
    }

    // Hook network functions
    HMODULE ws2 = LoadLibraryA("ws2_32.dll");
    if (ws2) {
        void *p;
        p = GetProcAddress(ws2, "sendto");
        if (p) { MakeTrampoline(p, st_tramp); PatchJmp(p, Hook_sendto); }
        p = GetProcAddress(ws2, "WSASendTo");
        if (p) { MakeTrampoline(p, wst_tramp); PatchJmp(p, Hook_WSASendTo); }
        Log("Network hooks installed");
    }

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID res) {
    if (r == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        char sd[MAX_PATH]; GetSystemDirectoryA(sd, MAX_PATH); strcat(sd, "\\version.dll");
        HMODULE rv = LoadLibraryA(sd);
        if (rv) { pGFVISW=(GFVISW_t)GetProcAddress(rv,"GetFileVersionInfoSizeW"); pGFVIW=(GFVIW_t)GetProcAddress(rv,"GetFileVersionInfoW"); pVQV=(VQV_t)GetProcAddress(rv,"VerQueryValueW"); }
        InitializeCriticalSection(&logLock);
        GetModuleFileNameA(NULL, logDir, MAX_PATH);
        char *sl = strrchr(logDir, '\\'); if (sl) *sl = 0;
        strcat(logDir, "\\nethook_logs");
        CreateDirectoryA(logDir, NULL);
        char lp[MAX_PATH]; snprintf(lp, MAX_PATH, "%s\\bf_cfb.log", logDir);
        logfile = fopen(lp, "w");
        Log("=== BF_CFB Hook ===");
        Log("PID: %lu", GetCurrentProcessId());
        CreateThread(NULL, 0, DelayedHook, NULL, 0, NULL);
    }
    else if (r == DLL_PROCESS_DETACH) { if (logfile) fclose(logfile); }
    return TRUE;
}
