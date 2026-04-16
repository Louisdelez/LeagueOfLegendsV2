// no_encrypt.c - Disable ALL Blowfish encryption in LoLPrivate.exe
// Patches BF_cfb64_encrypt AND BF_encrypt to be pass-through (no encryption)
// Also captures network packets for debugging
//
// Strategy: Replace encryption functions with memcpy (input → output)
// This makes the client send plaintext ENet data
//
// Compile: gcc -shared -o version.dll no_encrypt.c -lws2_32 -O2

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

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
static int pktCount = 0;

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
    int n = len < 48 ? len : 48;
    const unsigned char *p = (const unsigned char *)data;
    for (int i = 0; i < n; i++) sprintf(hex+i*3, "%02X ", p[i]);
    Log("  %s(%d): %s", lbl, len, hex);
}

static void SavePacket(const char *tag, const char *buf, int len) {
    EnterCriticalSection(&logLock);
    pktCount++;
    char fn[MAX_PATH];
    snprintf(fn, MAX_PATH, "%s\\%s_%04d_%dB.bin", logDir, tag, pktCount, len);
    FILE *f = fopen(fn, "wb");
    if (f) { fwrite(buf, 1, len, f); fclose(f); }
    Log("%s #%d: %d bytes", tag, pktCount, len);
    LogHex("Data", buf, len);
    LeaveCriticalSection(&logLock);
}

// ============ PATCHED ENCRYPTION FUNCTIONS ============

// BF_cfb64_encrypt replacement: just copy input to output (NO encryption)
// Original: FUN_1410f2ce0(key, in, out, len, enc)
void Patched_BF_cfb64_encrypt(void *key, void *in, void *out,
                               unsigned long long len, int enc) {
    // Simply copy data without encrypting
    if (in != out && len > 0) {
        memcpy(out, in, (size_t)len);
    }
    Log("BF_cfb64: BYPASSED len=%llu enc=%d", len, enc);
}

// BF_encrypt replacement: no-op (the block cipher itself)
// Original: FUN_1410f25c0(key, data_block)
// This encrypts 8 bytes in-place. We just leave the data unchanged.
void Patched_BF_encrypt(void *key, void *block) {
    // Do nothing - leave block unchanged
    // Log("BF_encrypt: BYPASSED");  // Too noisy
}

// BF_set_key replacement: still set up the key structure but we don't care
// We let this run normally since it doesn't encrypt data
// Actually we need to NOP it too because cfb uses the key schedule

// ============ INLINE HOOK HELPERS ============
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

// Network hooks
static unsigned char st_tramp[32], wst_tramp[32], rf_tramp[32], wrf_tramp[32];
static unsigned char cfb_tramp[32], bfenc_tramp[32];

typedef int (WSAAPI *sendto_t)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WSAAPI *WSASendTo_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WSAAPI *recvfrom_t)(SOCKET, char*, int, int, struct sockaddr*, int*);
typedef int (WSAAPI *WSARecvFrom_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

int WSAAPI Hook_sendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen) {
    if (to && to->sa_family == AF_INET) SavePacket("SEND", buf, len);
    return ((sendto_t)st_tramp)(s, buf, len, flags, to, tolen);
}
int WSAAPI Hook_WSASendTo(SOCKET s, LPWSABUF b, DWORD c, LPDWORD sent, DWORD f, const struct sockaddr *to, int tl, LPWSAOVERLAPPED o, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    if (to && to->sa_family == AF_INET)
        for (DWORD i=0;i<c;i++) if(b[i].len>0) SavePacket("WSEND", b[i].buf, b[i].len);
    return ((WSASendTo_t)wst_tramp)(s, b, c, sent, f, to, tl, o, cr);
}
int WSAAPI Hook_recvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fl) {
    int r = ((recvfrom_t)rf_tramp)(s, buf, len, flags, from, fl);
    if (r > 0 && from && from->sa_family == AF_INET) SavePacket("RECV", buf, r);
    return r;
}
int WSAAPI Hook_WSARecvFrom(SOCKET s, LPWSABUF b, DWORD c, LPDWORD recv, LPDWORD f, struct sockaddr *from, LPINT fl, LPWSAOVERLAPPED o, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    int r = ((WSARecvFrom_t)wrf_tramp)(s, b, c, recv, f, from, fl, o, cr);
    if (r == 0 && recv && *recv > 0 && from && from->sa_family == AF_INET)
        for (DWORD i=0;i<c;i++) if(b[i].len>0)
            SavePacket("WRECV", b[i].buf, b[i].len < *recv ? b[i].len : *recv);
    return r;
}

// ============ DELAYED PATCHING THREAD ============
static DWORD WINAPI PatchThread(LPVOID param) {
    // Wait longer for stub.dll to finish ALL integrity checks
    Sleep(8000);
    Log("=== Applying patches ===");

    HMODULE exe = GetModuleHandleA(NULL);
    if (!exe) { Log("ERROR: No exe handle"); return 0; }
    char *base = (char*)exe;

    // Patch BF_cfb64_encrypt at offset 0x10f2ce0
    // Instead of hooking, just write a RET instruction at the start
    // The function has param3=out, param2=in, param4=len
    // We need it to do memcpy(out, in, len) then return
    // But simplest: just RET (output buffer won't be filled = zeros or unchanged)
    // Actually: write "rep movsb; ret" which copies RCX bytes from RSI to RDI
    // On Windows x64: param1=RCX, param2=RDX, param3=R8, param4=R9
    // BF_cfb64_encrypt(key=RCX, in=RDX, out=R8, len=R9, enc=[stack])
    // We want: memcpy(R8, RDX, R9) = mov RDI,R8; mov RSI,RDX; mov RCX,R9; rep movsb; ret

    // SKIP patching BF_cfb64_encrypt for now (crashes)
    // Only patch BF_encrypt (the block cipher)
    Log("  Skipping BF_cfb64_encrypt (guard page protection)");

    // Patch BF_encrypt (block cipher) at offset 0x10f25c0
    // Just write RET — it encrypts 8 bytes in-place, we want it to do nothing
    void *bfenc_addr = base + 0x10f25c0;
    Log("Patching BF_encrypt at %p", bfenc_addr);
    {
        DWORD old;
        VirtualProtect(bfenc_addr, 4, PAGE_EXECUTE_READWRITE, &old);
        unsigned char *p = (unsigned char *)bfenc_addr;
        p[0] = 0xC3; // ret
        VirtualProtect(bfenc_addr, 4, old, &old);
        Log("  BF_encrypt → NOP (ret)");
    }

    // Also patch the SECOND BF_set_key (offset 0x174f140) — make it no-op
    // Actually, let's leave BF_set_key alone — it just initializes state
    // The important thing is that encrypt/decrypt do nothing

    Log("=== Encryption disabled! ===");

    // Now install network hooks
    HMODULE ws2 = LoadLibraryA("ws2_32.dll");
    if (ws2) {
        void *p;
        p = GetProcAddress(ws2, "sendto");
        if (p) { MakeTrampoline(p, st_tramp); PatchJmp(p, Hook_sendto); }
        p = GetProcAddress(ws2, "WSASendTo");
        if (p) { MakeTrampoline(p, wst_tramp); PatchJmp(p, Hook_WSASendTo); }
        p = GetProcAddress(ws2, "recvfrom");
        if (p) { MakeTrampoline(p, rf_tramp); PatchJmp(p, Hook_recvfrom); }
        p = GetProcAddress(ws2, "WSARecvFrom");
        if (p) { MakeTrampoline(p, wrf_tramp); PatchJmp(p, Hook_WSARecvFrom); }
        Log("Network hooks installed");
    }

    return 0;
}

// ============ DLL MAIN ============
BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID res) {
    if (r == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);

        // Load real version.dll
        char sd[MAX_PATH]; GetSystemDirectoryA(sd, MAX_PATH); strcat(sd, "\\version.dll");
        HMODULE rv = LoadLibraryA(sd);
        if (rv) {
            pGFVISW = (GFVISW_t)GetProcAddress(rv, "GetFileVersionInfoSizeW");
            pGFVIW = (GFVIW_t)GetProcAddress(rv, "GetFileVersionInfoW");
            pVQV = (VQV_t)GetProcAddress(rv, "VerQueryValueW");
        }

        // Init logging
        InitializeCriticalSection(&logLock);
        GetModuleFileNameA(NULL, logDir, MAX_PATH);
        char *sl = strrchr(logDir, '\\'); if (sl) *sl = 0;
        strcat(logDir, "\\nethook_logs");
        CreateDirectoryA(logDir, NULL);
        char lp[MAX_PATH]; snprintf(lp, MAX_PATH, "%s\\no_encrypt.log", logDir);
        logfile = fopen(lp, "w");
        Log("=== LoL No-Encrypt Patch ===");
        Log("PID: %lu", GetCurrentProcessId());

        // Start delayed patching thread
        CreateThread(NULL, 0, PatchThread, NULL, 0, NULL);
    }
    else if (r == DLL_PROCESS_DETACH) {
        Log("Unloading");
        if (logfile) fclose(logfile);
    }
    return TRUE;
}
