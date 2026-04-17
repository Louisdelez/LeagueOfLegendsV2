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

// Diagnostic detour for the handler at RVA 0x3EF8F0 (writes state flag via
// the deobfuscation chain). Answers: does the handler fire naturally after
// auth, or is the caller chain never reached?
static BYTE tramp_3EF8F0[32];
static volatile DWORD g_tramp_3EF8F0_addr = 0;
static volatile int g_handler_hits = 0;

void __attribute__((cdecl, used)) LogFrom3EF8F0(DWORD this_ptr, DWORD ret_addr) {
    int h = ++g_handler_hits;
    if (h <= 20) {
        // Dump the first 16 bytes at ECX. Use IsBadReadPtr as a cheap
        // safety check — deprecated but adequate for a diagnostic hook.
        BYTE *ob = (BYTE*)this_ptr;
        char hex[64] = {0};
        if (this_ptr && !IsBadReadPtr(ob, 16)) {
            for (int i = 0; i < 16; i++) {
                char tmp[4];
                snprintf(tmp, 4, "%02X ", ob[i]);
                strcat(hex, tmp);
            }
        } else {
            strcpy(hex, "<bad ptr>");
        }
        Log("HANDLER: 0x3EF8F0 fire #%d ret=%p this=%p [%s]",
            h, (void*)ret_addr, (void*)this_ptr, hex);
    } else if (h == 100) {
        Log("HANDLER: suppressing further hits");
    }
}

// Naked assembly detour: preserves all regs/flags, calls LogFrom3EF8F0 with
// (ECX_on_entry, return_address), then jumps to the trampoline (which runs
// the original stolen bytes and falls through to 0x3EF8F0 + 5).
extern void Detour_3EF8F0(void);
__asm__(
    ".text\n"
    ".globl _Detour_3EF8F0\n"
    "_Detour_3EF8F0:\n"
    "    pushal\n"
    "    pushfl\n"
    "    mov 36(%esp), %eax\n"      // [esp+32 (pushal) + 4 (pushfl)] = ret addr
    "    push %eax\n"
    "    push %ecx\n"                // 'this' (still intact)
    "    call _LogFrom3EF8F0\n"
    "    add $8, %esp\n"
    "    popfl\n"
    "    popal\n"
    "    jmp *_g_tramp_3EF8F0_addr\n"
);

// Second detour: on the vtable method @ RVA 0x76EE20 (virtual packet handler).
// This is the class method that onpacket-received; its arg [ebp+0xC] is the
// packet pointer. We log ecx (this) + the packet bytes to determine whether
// this vtable entry is the real post-auth packet dispatch entry.
static BYTE tramp_76EE20[32];
static volatile DWORD g_tramp_76EE20_addr = 0;
static volatile int g_hits_76EE20 = 0;

void __attribute__((cdecl, used)) LogFrom76EE20(DWORD this_ptr, DWORD arg_pkt, DWORD ret_addr) {
    int h = ++g_hits_76EE20;
    if (h <= 20) {
        BYTE *pkt = (BYTE*)arg_pkt;
        char hex[80] = {0};
        if (arg_pkt && !IsBadReadPtr(pkt, 24)) {
            for (int i = 0; i < 24; i++) {
                char tmp[4];
                snprintf(tmp, 4, "%02X ", pkt[i]);
                strcat(hex, tmp);
            }
        } else {
            strcpy(hex, "<bad ptr>");
        }
        Log("VT76EE20 #%d ret=%p this=%p pkt=%p [%s]",
            h, (void*)ret_addr, (void*)this_ptr, (void*)arg_pkt, hex);
    }
}

extern void Detour_76EE20(void);
__asm__(
    ".text\n"
    ".globl _Detour_76EE20\n"
    "_Detour_76EE20:\n"
    // Stack at entry: [esp]=retaddr, [esp+4]=arg0 (stdcall/thiscall layout
    // with arg passed on stack). For thiscall this = ecx, 1st stack arg is
    // at [esp+4]. We grab both.
    "    pushal\n"
    "    pushfl\n"
    "    mov 36(%esp), %eax\n"      // retaddr
    "    push %eax\n"
    "    mov 40(%esp), %eax\n"      // arg0 at [esp+36(pushal+fl)+4(retaddr)] = 40
    "    push %eax\n"
    "    push %ecx\n"                // this
    "    call _LogFrom76EE20\n"
    "    add $12, %esp\n"
    "    popfl\n"
    "    popal\n"
    "    jmp *_g_tramp_76EE20_addr\n"
);

// Detour on the pre-dispatch fn @ RVA 0x5BA9A0. Prologue:
//   55            push ebp
//   8B EC         mov ebp, esp
//   83 E4 F8      and esp, -8          (alignment)
// First complete-instruction boundary at offset 6, so we steal 6 bytes.
static BYTE tramp_5BA9A0[32];
static volatile DWORD g_tramp_5BA9A0_addr = 0;
static volatile int g_hits_5BA9A0 = 0;

void __attribute__((cdecl, used)) LogFrom5BA9A0(DWORD this_ptr, DWORD arg0, DWORD ret_addr) {
    int h = ++g_hits_5BA9A0;
    if (h <= 20) {
        BYTE *pkt = (BYTE*)arg0;
        char hex[80] = {0};
        if (arg0 && !IsBadReadPtr(pkt, 24)) {
            for (int i = 0; i < 24; i++) {
                char tmp[4]; snprintf(tmp, 4, "%02X ", pkt[i]);
                strcat(hex, tmp);
            }
        } else { strcpy(hex, "<bad>"); }
        Log("PREDISP 5BA9A0 #%d ret=%p this=%p arg=%p [%s]",
            h, (void*)ret_addr, (void*)this_ptr, (void*)arg0, hex);
    }
}

// Blowfish::Decrypt detour @ RVA 0x32FDA0.
// Signature: thiscall — ecx=BF context, [esp+4]=buf ptr, [esp+8]=len
// We log BEFORE decryption (ciphertext). After trampoline runs and returns,
// the buffer will contain plaintext — we could log that too but it's complex.
static volatile DWORD g_tramp_BFDec_addr = 0;
static volatile int g_hits_BFDec = 0;

void __attribute__((cdecl, used)) LogFromBFDecrypt(DWORD this_ptr, DWORD buf, DWORD len, DWORD ret) {
    int h = ++g_hits_BFDec;
    if (h <= 30) {
        BYTE *p = (BYTE*)buf;
        int show = (int)len;
        if (show > 32) show = 32;
        char hex[128] = {0};
        if (buf && !IsBadReadPtr(p, (unsigned)show)) {
            for (int i = 0; i < show; i++) {
                char tmp[4]; snprintf(tmp, 4, "%02X ", p[i]);
                strcat(hex, tmp);
            }
        } else { strcpy(hex, "<bad>"); }
        Log("BFDEC #%d ret=%p this=%p buf=%p len=%lu [%s]",
            h, (void*)ret, (void*)this_ptr, (void*)buf, len, hex);
    }
}

extern void Detour_BFDecrypt(void);
__asm__(
    ".text\n"
    ".globl _Detour_BFDecrypt\n"
    "_Detour_BFDecrypt:\n"
    "    pushal\n"
    "    pushfl\n"
    // After pushal(32) + pushfl(4) = 36 bytes pushed.
    // Original stack: [ESP+36]=retaddr, [ESP+40]=buf, [ESP+44]=len
    // Push args right-to-left for cdecl: ret, len, buf, this
    "    mov 36(%esp), %eax\n"      // retaddr
    "    push %eax\n"
    "    mov 48(%esp), %eax\n"      // len (was +44, +4 from 1 push = +48)
    "    push %eax\n"
    "    mov 48(%esp), %eax\n"      // buf (was +40, +8 from 2 pushes = +48)
    "    push %eax\n"
    "    push %ecx\n"                // this
    "    call _LogFromBFDecrypt\n"
    "    add $16, %esp\n"
    "    popfl\n"
    "    popal\n"
    "    jmp *_g_tramp_BFDec_addr\n"
);

extern void Detour_5BA9A0(void);
__asm__(
    ".text\n"
    ".globl _Detour_5BA9A0\n"
    "_Detour_5BA9A0:\n"
    "    pushal\n"
    "    pushfl\n"
    "    mov 36(%esp), %eax\n"      // retaddr
    "    push %eax\n"
    "    mov 40(%esp), %eax\n"      // arg0 on stack
    "    push %eax\n"
    "    push %ecx\n"                // this
    "    call _LogFrom5BA9A0\n"
    "    add $12, %esp\n"
    "    popfl\n"
    "    popal\n"
    "    jmp *_g_tramp_5BA9A0_addr\n"
);

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

// Like MakeTrampoline5 but steals N bytes (for prologues whose instruction
// boundaries don't align at 5 bytes). Callers must also overwrite N bytes
// at the target with a 5-byte jmp + (N-5) NOPs.
static void MakeTrampolineN(void *func, BYTE *tramp, int n) {
    memcpy(tramp, func, n);
    tramp[n] = 0xE9;
    DWORD rel = (DWORD)((BYTE*)func + n) - (DWORD)(tramp + n + 5);
    *(DWORD*)(tramp + n + 1) = rel;
    DWORD old;
    VirtualProtect(tramp, 32, PAGE_EXECUTE_READWRITE, &old);
    FlushInstructionCache(GetCurrentProcess(), tramp, 32);
}

static void PatchJmpN(void *target, void *dest, int n) {
    DWORD old;
    VirtualProtect(target, n, PAGE_EXECUTE_READWRITE, &old);
    BYTE *t = (BYTE*)target;
    t[0] = 0xE9;
    *(DWORD*)(t + 1) = (DWORD)dest - ((DWORD)target + 5);
    for (int i = 5; i < n; i++) t[i] = 0x90;
    VirtualProtect(target, n, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, n);
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

// Watchdog thread: after a warmup delay, continuously write 1 to the state
// flag at VA 0x01AA4254 (relative to the preferred PE base 0x00400000).
// If this unblocks "Query Status Req started", the flag is the real gate.
static DWORD WINAPI FlagWatchdog(LPVOID arg) {
    HMODULE hExe = GetModuleHandleA(NULL);
    if (!hExe) { Log("WD: no exe handle"); return 0; }
    BYTE *base = (BYTE*)hExe;
    // PE preferred base is 0x00400000 for this binary. The static VA 0x01AA4254
    // was taken from a preferred-base disassembly, so RVA = VA - 0x00400000.
    DWORD flagRVA = 0x01AA4254 - 0x00400000;
    BYTE *flag = base + flagRVA;
    Log("WD: start, hExe=%p, flag=%p (RVA 0x%08lX)", base, flag, flagRVA);
    DWORD oldProt;
    if (!VirtualProtect(flag, 4, PAGE_READWRITE, &oldProt)) {
        Log("WD: VirtualProtect err=%lu", GetLastError());
        return 0;
    }
    Log("WD: initial value=%08lX", *(volatile DWORD*)flag);
    Sleep(3000); // let client boot + handshake
    Log("WD: post-sleep value=%08lX, begin continuous poke", *(volatile DWORD*)flag);
    for (int i = 0; i < 100; i++) {
        *(volatile DWORD*)flag = 1;
        Sleep(100);
    }
    Log("WD: done, final=%08lX", *(volatile DWORD*)flag);
    return 0;
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

        // Force exit from the "Query Status Req started" wait loop by NOPing
        // out the 6-byte long `je 0x4A9BA0` at RVA 0x4A9C99. Sequence:
        //   cmp dword ptr [0x1AA4254], 0   ; 83 3D 54 42 AA 01 00
        //   je  0x4A9BA0 (loop back)       ; 0F 84 01 FF FF FF    ← patch target
        // After patch, the cmp falls through unconditionally → control reaches
        // the "Query Status Req ended" log regardless of flag value.
        //
        // (Prior approaches — flipping the jnz at 0x5BAAAC, direct flag pokes,
        // forcing the handler 0x3EF8F0 — all failed: handler never runs, flag
        // never naturally set, NOPing its guard breaks auth.)
        //
        // Additional pattern-scan for the 0x5BAAAC jnz is retained for
        // diagnostics but no bytes are modified there.
        {
            HMODULE hExe = GetModuleHandleA(NULL);
            if (hExe) {
                BYTE *base = (BYTE*)hExe;
                DWORD scanStart = 0x5BA000, scanEnd = 0x5BB000;
                int hits = 0;
                DWORD firstHit = 0;
                for (DWORD off = scanStart; off < scanEnd; off++) {
                    BYTE *q = base + off;
                    if (q[0] == 0x84 && q[1] == 0xC0 &&
                        q[2] == 0x75 &&
                        q[4] == 0x8B && q[5] == 0xCF &&
                        q[6] == 0xE8) {
                        hits++;
                        if (firstHit == 0) firstHit = off;
                        Log("PATCH: found pattern @RVA 0x%06lX (jnz +%02X)", off, q[3]);
                        // PATCH1 disabled: NOPing jnz breaks auth. 0x9499F4 is
                        // likely a format validator — returns 0 for valid 7.13
                        // packets, non-zero for invalid. Next: detour 0x9499F4.
                        (void)off;
                    }
                }
                Log("PATCH: scan done, %d hits in [0x%06lX..0x%06lX]", hits, scanStart, scanEnd);

                // NEW PATCH: NOP out the long `je 0x4A9BA0` at RVA 0x4A9C99.
                // Pattern (after PE relocation): cmp [flag_runtime], 0 ; je long
                //   83 3D <flag_VA_little_endian> 00 0F 84 <rel32>
                // We compute the runtime VA of the flag from the preferred-base
                // VA 0x01AA4254 (→ runtime VA = base + RVA = hExe + 0x016A4254).
                {
                    DWORD flagRuntimeVA = (DWORD)base + (0x01AA4254 - 0x00400000);
                    BYTE needle[9] = {
                        0x83, 0x3D,
                        (BYTE)(flagRuntimeVA),
                        (BYTE)(flagRuntimeVA >> 8),
                        (BYTE)(flagRuntimeVA >> 16),
                        (BYTE)(flagRuntimeVA >> 24),
                        0x00, 0x0F, 0x84
                    };
                    DWORD p2Start = 0x4A9C00, p2End = 0x4A9D00;
                    int p2Hits = 0;
                    Log("PATCH2: scanning for cmp [0x%08lX],0;je-long — needle %02X%02X%02X%02X%02X%02X%02X%02X%02X",
                        flagRuntimeVA, needle[0], needle[1], needle[2], needle[3], needle[4], needle[5], needle[6], needle[7], needle[8]);
                    for (DWORD off = p2Start; off < p2End - sizeof(needle); off++) {
                        BYTE *q = base + off;
                        int match = 1;
                        for (unsigned i = 0; i < sizeof(needle); i++) {
                            if (q[i] != needle[i]) { match = 0; break; }
                        }
                        if (match) {
                            p2Hits++;
                            BYTE *je = q + 7;    // 0F 84 rel32 (6 bytes)
                            Log("PATCH2: found cmp+je @RVA 0x%06lX, je@0x%06lX rel=%02X%02X%02X%02X",
                                off, off + 7, je[2], je[3], je[4], je[5]);
                            DWORD oldProt;
                            if (VirtualProtect(je, 6, PAGE_EXECUTE_READWRITE, &oldProt)) {
                                for (int i = 0; i < 6; i++) je[i] = 0x90;
                                FlushInstructionCache(GetCurrentProcess(), je, 6);
                                VirtualProtect(je, 6, oldProt, &oldProt);
                                Log("PATCH2: NOPed 6 bytes @RVA 0x%06lX (bypass flag gate)", off + 7);
                            } else {
                                Log("PATCH2: VirtualProtect err=%lu", GetLastError());
                            }
                        }
                    }
                    Log("PATCH2: scan done, %d hits", p2Hits);
                }

                // PATCH3: bypass the "Waiting for server response..." wait
                // loop. At RVA 0x4AA090 (pre-reloc VA 0x8AA090):
                //   cmp byte ptr [0x1E84F73], 0  ; 80 3D <byte_VA> 00
                //   jne 0x8AA0E9                 ; 75 50 (short jne, NOT long)
                // Convert `75 rel8` to `EB rel8` (unconditional short jmp,
                // same target) → always skip the busy-wait loop.
                {
                    DWORD flag2RuntimeVA = (DWORD)base + (0x01E84F73 - 0x00400000);
                    BYTE needle[8] = {
                        0x80, 0x3D,
                        (BYTE)(flag2RuntimeVA),
                        (BYTE)(flag2RuntimeVA >> 8),
                        (BYTE)(flag2RuntimeVA >> 16),
                        (BYTE)(flag2RuntimeVA >> 24),
                        0x00, 0x75                // cmp ..., 0 ; jne short
                    };
                    DWORD p3Start = 0x4AA000, p3End = 0x4AA200;
                    int p3Hits = 0;
                    Log("PATCH3: scanning for cmp byte [0x%08lX],0;jne-short", flag2RuntimeVA);
                    for (DWORD off = p3Start; off < p3End - sizeof(needle); off++) {
                        BYTE *q = base + off;
                        int match = 1;
                        for (unsigned i = 0; i < sizeof(needle); i++) {
                            if (q[i] != needle[i]) { match = 0; break; }
                        }
                        if (match) {
                            p3Hits++;
                            Log("PATCH3: found pattern @RVA 0x%06lX (NOT patching)", off);
                        }
                    }
                    Log("PATCH3: scan done, %d hits (DISABLED — keep client in wait loop)", p3Hits);
                }
                // PATCH3+4 DISABLED: keeping client alive in "Waiting for server
                // response..." loop so we can observe BF::Decrypt hits from game
                // content packets the server sends post-Patience.
#if 0
                // PATCH4: bypass the "Server/Client mismatch" log + shutdown.
                // At RVA 0x4AA844:
                //   cmp byte ptr [0x1E84F72], 0   ; 80 3D <byte_VA> 00
                //   jne 0x8AA8B0 (skip mismatch)  ; 75 63 (short)
                // Convert 75→EB: always skip the mismatch path, client proceeds.
                {
                    DWORD vfRuntimeVA = (DWORD)base + (0x01E84F72 - 0x00400000);
                    BYTE needle[8] = {
                        0x80, 0x3D,
                        (BYTE)(vfRuntimeVA),
                        (BYTE)(vfRuntimeVA >> 8),
                        (BYTE)(vfRuntimeVA >> 16),
                        (BYTE)(vfRuntimeVA >> 24),
                        0x00, 0x75
                    };
                    DWORD p4Start = 0x4AA700, p4End = 0x4AA900;
                    int p4Hits = 0;
                    Log("PATCH4: scanning for cmp byte [0x%08lX],0;jne-short (version-mismatch gate)",
                        vfRuntimeVA);
                    for (DWORD off = p4Start; off < p4End - sizeof(needle); off++) {
                        BYTE *q = base + off;
                        int match = 1;
                        for (unsigned i = 0; i < sizeof(needle); i++) {
                            if (q[i] != needle[i]) { match = 0; break; }
                        }
                        if (match) {
                            p4Hits++;
                            BYTE *jne = q + 7;
                            Log("PATCH4: found cmp+jne-short @RVA 0x%06lX rel8=%02X",
                                off, jne[1]);
                            DWORD oldProt;
                            if (VirtualProtect(jne, 2, PAGE_EXECUTE_READWRITE, &oldProt)) {
                                jne[0] = 0xEB;
                                FlushInstructionCache(GetCurrentProcess(), jne, 2);
                                VirtualProtect(jne, 2, oldProt, &oldProt);
                                Log("PATCH4: jne->jmp @RVA 0x%06lX (skip mismatch shutdown)",
                                    off + 7);
                            } else {
                                Log("PATCH4: VirtualProtect err=%lu", GetLastError());
                            }
                        }
                    }
                    Log("PATCH4: scan done, %d hits", p4Hits);
                }
#endif
                // Also dump 32 bytes around the originally-guessed RVA for reference
                BYTE *ref = base + 0x5BAAA0;
                char hex[128] = {0};
                for (int i = 0; i < 32; i++) {
                    char tmp[4];
                    snprintf(tmp, 4, "%02X ", ref[i]);
                    strcat(hex, tmp);
                }
                Log("PATCH: @0x5BAAA0: %s", hex);
            }
        }

        // Watchdog thread disabled (see notes above).
        (void)FlagWatchdog;

        // Install diagnostic detour on handler at RVA 0x3EF8F0 to see if it
        // fires naturally.
        {
            HMODULE hExe = GetModuleHandleA(NULL);
            if (hExe) {
                BYTE *target = (BYTE*)hExe + 0x3EF8F0;
                // Verify prologue: 55 8B EC 6A FF (push ebp; mov ebp,esp; push -1)
                Log("DETOUR: @0x3EF8F0 bytes: %02X %02X %02X %02X %02X",
                    target[0], target[1], target[2], target[3], target[4]);
                if (target[0] == 0x55 && target[1] == 0x8B && target[2] == 0xEC) {
                    MakeTrampoline5(target, tramp_3EF8F0);
                    g_tramp_3EF8F0_addr = (DWORD)tramp_3EF8F0;
                    PatchJmp5(target, (void*)Detour_3EF8F0);
                    Log("DETOUR: installed, trampoline=%p, detour=%p",
                        tramp_3EF8F0, (void*)Detour_3EF8F0);
                } else {
                    Log("DETOUR: prologue mismatch, skipping install");
                }

                // Install Blowfish::Decrypt detour @ 0x32FDA0 (6-byte steal)
                // This is THE choke point for all incoming encrypted packets.
                {
                    BYTE *tgtBF = (BYTE*)hExe + 0x32FDA0;
                    Log("BFDECRYPT: @0x32FDA0 bytes: %02X %02X %02X %02X %02X %02X",
                        tgtBF[0], tgtBF[1], tgtBF[2], tgtBF[3], tgtBF[4], tgtBF[5]);
                    if (tgtBF[0] == 0x55 && tgtBF[1] == 0x8B && tgtBF[2] == 0xEC &&
                        tgtBF[3] == 0x83 && tgtBF[4] == 0xE4 && tgtBF[5] == 0xF8) {
                        static BYTE tramp_BFDec[32];
                        MakeTrampolineN(tgtBF, tramp_BFDec, 6);
                        g_tramp_BFDec_addr = (DWORD)tramp_BFDec;
                        PatchJmpN(tgtBF, (void*)Detour_BFDecrypt, 6);
                        Log("BFDECRYPT: installed, trampoline=%p", tramp_BFDec);
                    } else {
                        Log("BFDECRYPT: prologue mismatch, skipping");
                    }
                }

                // Install pre-dispatch detour @ 0x5BA9A0 (6-byte steal)
                BYTE *tgt2 = (BYTE*)hExe + 0x5BA9A0;
                Log("DETOUR2: @0x5BA9A0 bytes: %02X %02X %02X %02X %02X %02X",
                    tgt2[0], tgt2[1], tgt2[2], tgt2[3], tgt2[4], tgt2[5]);
                if (tgt2[0] == 0x55 && tgt2[1] == 0x8B && tgt2[2] == 0xEC &&
                    tgt2[3] == 0x83 && tgt2[4] == 0xE4 && tgt2[5] == 0xF8) {
                    MakeTrampolineN(tgt2, tramp_5BA9A0, 6);
                    g_tramp_5BA9A0_addr = (DWORD)tramp_5BA9A0;
                    PatchJmpN(tgt2, (void*)Detour_5BA9A0, 6);
                    Log("DETOUR2: installed, trampoline=%p, detour=%p",
                        tramp_5BA9A0, (void*)Detour_5BA9A0);
                } else {
                    Log("DETOUR2: prologue mismatch, skipping");
                }
            }
        }
    }
    else if (reason == DLL_PROCESS_DETACH) {
        Log("Unloading");
        if (logfile) fclose(logfile);
        if (realVersionDll) FreeLibrary(realVersionDll);
    }
    return TRUE;
}
