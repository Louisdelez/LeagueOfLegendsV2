/*
 * version.dll proxy — loaded automatically by the game at startup.
 * Forwards all version.dll calls to the real system DLL while
 * installing our sendto/recvfrom hooks before any networking starts.
 *
 * Build: gcc -shared -o version.dll version_proxy.c -lws2_32 -O2
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdarg.h>

// === Real version.dll forwarding ===
static HMODULE realVersionDll = NULL;

// We only need to forward a few commonly used version.dll exports
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

// Exported forwarded functions
__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeA(LPCSTR fn, LPDWORD h) {
    return pGetFileVersionInfoSizeA ? pGetFileVersionInfoSizeA(fn, h) : 0;
}
__declspec(dllexport) BOOL WINAPI GetFileVersionInfoA(LPCSTR fn, DWORD h, DWORD sz, LPVOID d) {
    return pGetFileVersionInfoA ? pGetFileVersionInfoA(fn, h, sz, d) : FALSE;
}
__declspec(dllexport) BOOL WINAPI VerQueryValueA(LPCVOID b, LPCSTR s, LPVOID *p, PUINT l) {
    return pVerQueryValueA ? pVerQueryValueA(b, s, p, l) : FALSE;
}
__declspec(dllexport) DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR fn, LPDWORD h) {
    return pGetFileVersionInfoSizeW ? pGetFileVersionInfoSizeW(fn, h) : 0;
}
__declspec(dllexport) BOOL WINAPI GetFileVersionInfoW(LPCWSTR fn, DWORD h, DWORD sz, LPVOID d) {
    return pGetFileVersionInfoW ? pGetFileVersionInfoW(fn, h, sz, d) : FALSE;
}
__declspec(dllexport) BOOL WINAPI VerQueryValueW(LPCVOID b, LPCWSTR s, LPVOID *p, PUINT l) {
    return pVerQueryValueW ? pVerQueryValueW(b, s, p, l) : FALSE;
}

// === Network Hook (same as nethook.c) ===
typedef int (WINAPI *sendto_t)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (WINAPI *recvfrom_t)(SOCKET, char*, int, int, struct sockaddr*, int*);
typedef int (WINAPI *WSASendTo_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WINAPI *WSARecvFrom_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr*, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

typedef int (WINAPI *send_t)(SOCKET, const char*, int, int);
typedef int (WINAPI *WSASend_t)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WINAPI *connect_t)(SOCKET, const struct sockaddr*, int);

static sendto_t      real_sendto = NULL;
static recvfrom_t    real_recvfrom = NULL;
static WSASendTo_t   real_WSASendTo = NULL;
static WSARecvFrom_t real_WSARecvFrom = NULL;
static send_t        real_send = NULL;
static WSASend_t     real_WSASend = NULL;
static connect_t     real_connect = NULL;

static FILE *logfile = NULL;
static CRITICAL_SECTION logLock;
static int pktCount = 0;
static char logDir[MAX_PATH];
static BYTE tramp_sendto[32];
static BYTE tramp_recvfrom[32];
static BYTE tramp_WSASendTo[32];
static BYTE tramp_WSARecvFrom[32];
static BYTE tramp_send[32];
static BYTE tramp_WSASend[32];
static BYTE tramp_connect[32];

static void Log(const char *fmt, ...) {
    if (!logfile) return;
    EnterCriticalSection(&logLock);
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(logfile, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list a; va_start(a, fmt); vfprintf(logfile, fmt, a); va_end(a);
    fprintf(logfile, "\n"); fflush(logfile);
    LeaveCriticalSection(&logLock);
}

static void SavePacket(const char *tag, const char *buf, int len, const struct sockaddr *addr) {
    pktCount++;
    char fn[MAX_PATH];
    snprintf(fn, MAX_PATH, "%s\\%s_%04d_%dB.bin", logDir, tag, pktCount, len);
    FILE *f = fopen(fn, "wb");
    if (f) { fwrite(buf, 1, len, f); fclose(f); }

    char addrStr[64] = "?";
    if (addr && addr->sa_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in*)addr;
        snprintf(addrStr, 64, "%s:%d", inet_ntoa(s->sin_addr), ntohs(s->sin_port));
    }
    Log("%s #%d: %dB %s", tag, pktCount, len, addrStr);

    // Hex dump first 64 bytes
    if (logfile) {
        EnterCriticalSection(&logLock);
        fprintf(logfile, "  ");
        for (int i = 0; i < len && i < 64; i++) {
            fprintf(logfile, "%02X ", (unsigned char)buf[i]);
            if (i == 7 || i == 15 || i == 31 || i == 47) fprintf(logfile, " ");
        }
        if (len > 64) fprintf(logfile, "...");
        fprintf(logfile, "\n"); fflush(logfile);
        LeaveCriticalSection(&logLock);
    }
}

// Scan heap for active BF_KEY (modified P-box, not the static Pi values)
static int pboxScanned = 0;
static void ScanPBox(void) {
    if (pboxScanned) return;
    pboxScanned = 1;

    Log("Scanning heap for active BF_KEY structures...");

    MEMORY_BASIC_INFORMATION mbi;
    BYTE *addr = NULL;
    int found = 0;

    // Blowfish S-box initial value: 0xD1310BA6 (the FIRST S-box entry)
    // After BF_set_key, both P-box and S-box are modified
    // A real BF_KEY: 18 uint32 P-box + 1024 uint32 S-box = 4168 bytes
    // We look for 4168-byte aligned structures where P[0] != 0x243F6A88 (not initial)

    while (VirtualQuery(addr, &mbi, sizeof(mbi)) && found < 10) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) &&
            mbi.RegionSize >= 4168) {

            BYTE *regionBase = (BYTE*)mbi.BaseAddress;
            SIZE_T regionSize = mbi.RegionSize;

            // Scan with 4-byte alignment for speed
            for (SIZE_T j = 0; j + 4168 <= regionSize && found < 10; j += 4) {
                BYTE *ptr = regionBase + j;
                if (IsBadReadPtr(ptr, 4168)) break;

                DWORD *P = (DWORD*)ptr;

                // Skip initial/uninitialized
                if (P[0] == 0x243F6A88) continue;  // Initial Pi value
                if (P[0] == 0 || P[0] == 0xFFFFFFFF) continue;

                // Check: P-box should have 18 diverse uint32 values
                // followed by S-box with 1024 diverse values
                // A real BF_KEY has high entropy in all values
                int zeroCount = 0;
                for (int k = 0; k < 18; k++)
                    if (P[k] == 0) zeroCount++;
                if (zeroCount > 4) continue;  // Too many zeros

                // Check S-box: first entry should not be initial value
                DWORD *S = (DWORD*)(ptr + 72);
                if (S[0] == 0xD1310BA6) continue;  // Initial S-box
                if (S[0] == 0) continue;

                // Check S-box entropy: sample a few values
                int sZeros = 0;
                for (int k = 0; k < 16; k++)
                    if (S[k * 64] == 0) sZeros++;
                if (sZeros > 4) continue;

                // This looks like a real BF_KEY!
                found++;
                Log("*** BF_KEY #%d at %p ***", found, ptr);

                // Dump P-box (18 uint32 = 72 bytes)
                char hex[512] = {0};
                for (int k = 0; k < 72; k++)
                    sprintf(hex + k*3, "%02X ", ptr[k]);
                Log("  P-box: %s", hex);

                // Dump first 32 bytes of S-box
                hex[0] = 0;
                for (int k = 0; k < 32; k++)
                    sprintf(hex + k*3, "%02X ", ptr[72 + k]);
                Log("  S-box[0:32]: %s", hex);

                // Try to find IV: look backwards for EVP_CIPHER_CTX
                // cipher_data at offset ~0x58 in EVP_CIPHER_CTX
                for (int backoff = 0x50; backoff <= 0x70; backoff += 8) {
                    BYTE *ctxGuess = ptr - backoff;
                    if (!IsBadReadPtr(ctxGuess, backoff + 8)) {
                        // Check if ctxGuess+backoff points back to ptr
                        UINT64 ptrVal = *(UINT64*)(ctxGuess + backoff);
                        if (ptrVal == (UINT64)ptr) {
                            Log("  EVP_CTX at %p (cipher_data at +0x%X)", ctxGuess, backoff);
                            // IV is typically at offset 0x18 (oiv) and 0x28 (iv)
                            hex[0] = 0;
                            for (int k = 0; k < 8; k++)
                                sprintf(hex + k*3, "%02X ", ctxGuess[0x18 + k]);
                            Log("  oiv: %s", hex);
                            hex[0] = 0;
                            for (int k = 0; k < 8; k++)
                                sprintf(hex + k*3, "%02X ", ctxGuess[0x28 + k]);
                            Log("  iv:  %s", hex);
                        }
                    }
                }
            }
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }

    Log("Heap scan done: found %d BF_KEY", found);
}

int WINAPI Hook_sendto(SOCKET s, const char *buf, int len, int flags,
                       const struct sockaddr *to, int tolen) {
    if (to && to->sa_family == AF_INET) {
        SavePacket("SEND", buf, len, to);
        // Compare consecutive 519B packets to find constant vs variable bytes
        static unsigned char prevPacket[519];
        static int hasPrev = 0;
        if (len == 519 && pktCount <= 10) {
            if (hasPrev) {
                int constBytes = 0, varBytes = 0;
                char constMap[200] = {0};
                for (int i = 0; i < 519; i++) {
                    if ((unsigned char)buf[i] == prevPacket[i]) constBytes++;
                    else varBytes++;
                }
                Log("  DIFF: %d constant, %d variable bytes (of 519)", constBytes, varBytes);
                // Log which byte positions are constant
                char positions[2000] = {0};
                int pos = 0;
                for (int i = 0; i < 519 && pos < 1900; i++) {
                    if ((unsigned char)buf[i] == prevPacket[i])
                        pos += sprintf(positions + pos, "%d ", i);
                }
                Log("  CONST positions: %s", positions);
            }
            memcpy(prevPacket, buf, 519);
            hasPrev = 1;
        }
        if (0 && len == 519 && pktCount <= 3) { // DISABLED
            Log("  === MEMORY SCAN for MTU+Window LE (E4030000 00800000 20000000) ===");
            // Try LITTLE-ENDIAN: MTU=996=E403, Window=32768=00800000, Chan=32=20000000
            BYTE pattern[] = { 0xE4, 0x03, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00 };
            MEMORY_BASIC_INFORMATION mbi;
            BYTE *addr = NULL;
            int found = 0;
            while (VirtualQuery(addr, &mbi, sizeof(mbi)) && found < 20) {
                if (mbi.State == MEM_COMMIT && mbi.RegionSize > 0 &&
                    (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_READONLY))) {
                    BYTE *base = (BYTE*)mbi.BaseAddress;
                    SIZE_T size = mbi.RegionSize;
                    for (SIZE_T i = 0; i + 48 <= size; i++) {
                        if (!IsBadReadPtr(base + i, 64) &&
                            base[i] == 0xE4 && base[i+1] == 0x03 &&
                            base[i+2] == 0x00 && base[i+3] == 0x00 &&
                            base[i+4] == 0x00 && base[i+5] == 0x80 &&
                            base[i+6] == 0x00 && base[i+7] == 0x00 &&
                            base[i+8] == 0x20 && base[i+9] == 0x00 &&
                            base[i+10] == 0x00 && base[i+11] == 0x00) {
                            BYTE *p = base + i;
                            // WindowSize+ChannelCount found!
                            // MTU should be 4 bytes before: p[-4] p[-3] = 03 E4
                            int hasMtu = 1; // We're already matching MTU in the pattern
                            found++;
                            if (found <= 10) {
                                char hex[512] = {0};
                                int start = (i >= 16) ? -16 : 0;
                                for (int j = 0; j < 64; j++)
                                    sprintf(hex + j*3, "%02X ", p[start + j]);
                                Log("    WIN+CHAN at %p MTU_ok=%d: %s", p, hasMtu, hex);
                                if (hasMtu) {
                                    Log("    *** FULL ENet CONNECT PLAINTEXT FOUND! ***");
                                    // Save 128 bytes starting 16 before
                                    char fn[MAX_PATH];
                                    snprintf(fn, MAX_PATH, "%s\\CONNECT_PLAIN_%p.bin", logDir, p-16);
                                    FILE *f = fopen(fn, "wb");
                                    if (f) { fwrite(p - 16, 1, 128, f); fclose(f); }
                                }
                            }
                        }
                    }
                }
                addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
            }
            Log("  Scan done: %d matches", found);
        }
    }
    return real_sendto(s, buf, len, flags, to, tolen);
}

int WINAPI Hook_recvfrom(SOCKET s, char *buf, int len, int flags,
                         struct sockaddr *from, int *fromlen) {
    int r = real_recvfrom(s, buf, len, flags, from, fromlen);
    if (r > 0 && from && from->sa_family == AF_INET)
        SavePacket("RECV", buf, r, from);
    return r;
}

int WINAPI Hook_WSASendTo(SOCKET s, LPWSABUF bufs, DWORD bufCount, LPDWORD bytesSent,
                          DWORD flags, const struct sockaddr *to, int tolen,
                          LPWSAOVERLAPPED ovl, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    for (DWORD i = 0; i < bufCount; i++) {
        if (bufs[i].len > 0 && to)
            SavePacket("WSASEND", bufs[i].buf, bufs[i].len, to);
    }
    return real_WSASendTo(s, bufs, bufCount, bytesSent, flags, to, tolen, ovl, cr);
}

int WINAPI Hook_WSARecvFrom(SOCKET s, LPWSABUF bufs, DWORD bufCount, LPDWORD bytesRecv,
                            LPDWORD flags, struct sockaddr *from, LPINT fromlen,
                            LPWSAOVERLAPPED ovl, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    int r = real_WSARecvFrom(s, bufs, bufCount, bytesRecv, flags, from, fromlen, ovl, cr);
    if (r == 0 && bytesRecv && *bytesRecv > 0 && from && from->sa_family == AF_INET) {
        SavePacket("WSARECV", bufs[0].buf, *bytesRecv, from);
    }
    return r;
}

static int sendCallLogged = 0;
int WINAPI Hook_send(SOCKET s, const char *buf, int len, int flags) {
    struct sockaddr_in addr = {0};
    int addrlen = sizeof(addr);
    getpeername(s, (struct sockaddr*)&addr, &addrlen);
    SavePacket("SEND_C", buf, len, (struct sockaddr*)&addr);
    // Log call stack for first 5 UDP-sized sends
    if (sendCallLogged < 5 && (len == 519 || (len > 100 && len < 600))) {
        sendCallLogged++;
        void *ret0 = __builtin_return_address(0);
        void *ret1 = __builtin_return_address(1);
        HMODULE mod0 = NULL, mod1 = NULL;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)ret0, &mod0);
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)ret1, &mod1);
        char n0[256]={0}, n1[256]={0};
        if(mod0) GetModuleFileNameA(mod0, n0, 256);
        if(mod1) GetModuleFileNameA(mod1, n1, 256);
        Log("  send() CALL STACK (len=%d):", len);
        Log("    ret0=%p %s +0x%llX", ret0, n0, (UINT64)ret0-(UINT64)mod0);
        Log("    ret1=%p %s +0x%llX", ret1, n1, (UINT64)ret1-(UINT64)mod1);
    }
    return real_send(s, buf, len, flags);
}

int WINAPI Hook_WSASend(SOCKET s, LPWSABUF bufs, DWORD bufCount, LPDWORD bytesSent,
                        DWORD flags, LPWSAOVERLAPPED ovl, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr) {
    struct sockaddr_in addr = {0};
    int addrlen = sizeof(addr);
    getpeername(s, (struct sockaddr*)&addr, &addrlen);
    for (DWORD i = 0; i < bufCount; i++) {
        if (bufs[i].len > 0)
            SavePacket("WSASEND_C", bufs[i].buf, bufs[i].len, (struct sockaddr*)&addr);
    }
    return real_WSASend(s, bufs, bufCount, bytesSent, flags, ovl, cr);
}

int WINAPI Hook_connect(SOCKET s, const struct sockaddr *addr, int addrlen) {
    if (addr && addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in*)addr;
        Log("CONNECT: socket=%llu to %s:%d", (unsigned long long)s,
            inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));
    }
    return real_connect(s, addr, addrlen);
}

// Copy 16 bytes (covers the first 3 instructions of sendto cleanly)
#define HOOK_SIZE 16

static void MakeTrampoline(void *func, BYTE *tramp) {
    memcpy(tramp, func, HOOK_SIZE);
    // jmp [rip+0] to (func + HOOK_SIZE)
    tramp[HOOK_SIZE] = 0xFF; tramp[HOOK_SIZE+1] = 0x25;
    *(DWORD*)(tramp+HOOK_SIZE+2) = 0;
    *(void**)(tramp+HOOK_SIZE+6) = (BYTE*)func + HOOK_SIZE;
    DWORD old; VirtualProtect(tramp, 32, PAGE_EXECUTE_READWRITE, &old);
    FlushInstructionCache(GetCurrentProcess(), tramp, 32);
}

static void PatchJmp(void *target, void *dest) {
    DWORD old;
    VirtualProtect(target, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &old);
    // jmp [rip+0] + 8-byte address = 14 bytes, pad remaining with NOPs
    BYTE patch[HOOK_SIZE];
    memset(patch, 0x90, HOOK_SIZE); // NOP fill
    patch[0] = 0xFF; patch[1] = 0x25;
    *(DWORD*)(patch+2) = 0;
    *(void**)(patch+6) = dest;
    memcpy(target, patch, HOOK_SIZE);
    VirtualProtect(target, HOOK_SIZE, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, HOOK_SIZE);
}

static void InstallNetHooks(void) {
    HMODULE ws2 = LoadLibraryA("ws2_32.dll");
    if (!ws2) { Log("Cannot load ws2_32.dll"); return; }

    void *pSend = (void*)GetProcAddress(ws2, "sendto");
    void *pRecv = (void*)GetProcAddress(ws2, "recvfrom");
    void *pWSASend = (void*)GetProcAddress(ws2, "WSASendTo");
    void *pWSARecv = (void*)GetProcAddress(ws2, "WSARecvFrom");
    Log("sendto=%p recvfrom=%p WSASendTo=%p WSARecvFrom=%p", pSend, pRecv, pWSASend, pWSARecv);

    if (pSend) {
        MakeTrampoline(pSend, tramp_sendto);
        real_sendto = (sendto_t)tramp_sendto;
        PatchJmp(pSend, Hook_sendto);
        Log("Hooked sendto!");
    }
    if (pRecv) {
        MakeTrampoline(pRecv, tramp_recvfrom);
        real_recvfrom = (recvfrom_t)tramp_recvfrom;
        PatchJmp(pRecv, Hook_recvfrom);
        Log("Hooked recvfrom!");
    }
    if (pWSASend) {
        MakeTrampoline(pWSASend, tramp_WSASendTo);
        real_WSASendTo = (WSASendTo_t)tramp_WSASendTo;
        PatchJmp(pWSASend, Hook_WSASendTo);
        Log("Hooked WSASendTo!");
    }
    if (pWSARecv) {
        MakeTrampoline(pWSARecv, tramp_WSARecvFrom);
        real_WSARecvFrom = (WSARecvFrom_t)tramp_WSARecvFrom;
        PatchJmp(pWSARecv, Hook_WSARecvFrom);
        Log("Hooked WSARecvFrom!");
    }

    // DON'T hook send/WSASend/connect — they break SSL/TLS
    // Only log connect calls for debugging (without hooking)
    Log("Not hooking send/WSASend/connect (TCP) to avoid breaking SSL");
    Log("Only UDP hooks active: sendto, recvfrom, WSASendTo, WSARecvFrom");
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);

        // Load real version.dll from system directory
        char sysDir[MAX_PATH];
        GetSystemDirectoryA(sysDir, MAX_PATH);
        strcat(sysDir, "\\version.dll");
        realVersionDll = LoadLibraryA(sysDir);
        if (realVersionDll) {
            pGetFileVersionInfoSizeA = (GetFileVersionInfoSizeA_t)GetProcAddress(realVersionDll, "GetFileVersionInfoSizeA");
            pGetFileVersionInfoA = (GetFileVersionInfoA_t)GetProcAddress(realVersionDll, "GetFileVersionInfoA");
            pVerQueryValueA = (VerQueryValueA_t)GetProcAddress(realVersionDll, "VerQueryValueA");
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
        char lp[MAX_PATH]; snprintf(lp, MAX_PATH, "%s\\nethook.log", logDir);
        logfile = fopen(lp, "w");
        Log("=== LoL NetHook (version.dll proxy) ===");
        Log("PID: %lu", GetCurrentProcessId());
        Log("Real version.dll: %s", sysDir);

        // Install network hooks
        InstallNetHooks();
    }
    else if (reason == DLL_PROCESS_DETACH) {
        Log("Unloading");
        if (logfile) fclose(logfile);
        if (realVersionDll) FreeLibrary(realVersionDll);
    }
    return TRUE;
}
