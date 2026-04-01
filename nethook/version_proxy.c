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

// Global buffer for echo injection
static char lastSendBuf[1024];
static int lastSendLen = 0;
static int injectMode = 0;
static int injectCount = 0;

// CRC BYPASS: patch the nonce check EARLY (in DllMain, before stub.dll protects memory)
static int crcPatched = 0;
static void PatchCrcCheckEarly(void) {
    if (crcPatched) return;
    HMODULE hMod = GetModuleHandleA(NULL); // main exe
    if (!hMod) return;

    BYTE *target = (BYTE*)hMod + 0x572827;

    // Verify bytes
    if (target[0] == 0x44 && target[1] == 0x3B && target[2] == 0xE0 &&
        target[3] == 0x0F && target[4] == 0x94 && target[5] == 0xC0) {
        DWORD oldProtect;
        if (VirtualProtect(target, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            target[0] = 0x90; target[1] = 0x90; target[2] = 0x90;
            target[3] = 0xB0; target[4] = 0x01; target[5] = 0x90;
            VirtualProtect(target, 6, oldProtect, &oldProtect);
            crcPatched = 1;
            // Can't use Log() here (logfile not open yet), use OutputDebugString
            OutputDebugStringA("*** CRC CHECK PATCHED IN DllMain! ***");
        }
    }
}

int WINAPI Hook_sendto(SOCKET s, const char *buf, int len, int flags,
                       const struct sockaddr *to, int tolen) {
    if (to && to->sa_family == AF_INET) {
        SavePacket("SEND", buf, len, to);
        // Patch CRC check on first sendto (game is already initialized by now)
        // Try to patch CRC (may already be done in DllMain)
        if (!crcPatched) {
            PatchCrcCheckEarly();
        }
        if (crcPatched) {
            Log("CRC PATCH: ACTIVE (patched successfully!)");
        } else {
            // Read the bytes to check current state
            HMODULE hMod = GetModuleHandleA(NULL);
            if (hMod) {
                BYTE *t = (BYTE*)hMod + 0x572827;
                Log("CRC PATCH: FAILED. Bytes: %02X %02X %02X %02X %02X %02X",
                    t[0], t[1], t[2], t[3], t[4], t[5]);
            }
        }

        // Save ONLY the first 519B sendto for echo injection (the CONNECT)
        if (len == 519 && lastSendLen == 0) {
            memcpy(lastSendBuf, buf, len);
            lastSendLen = len;
            Log("Captured first 519B CONNECT for echo injection");
        }
        // Capture RBX register - should be param_1 of NET_58e860
        if (len == 519 && pktCount <= 3) {
            register void* rbx_val asm("rbx");
            register void* r12_val asm("r12");
            register void* r13_val asm("r13");
            register void* r14_val asm("r14");
            register void* r15_val asm("r15");
            register void* rdi_val asm("rdi");
            register void* rsi_val asm("rsi");
            Log("  REGISTERS: RBX=%p R12=%p R13=%p R14=%p R15=%p RDI=%p RSI=%p",
                rbx_val, r12_val, r13_val, r14_val, r15_val, rdi_val, rsi_val);

            // Find the crypto context by navigating the std::map at param_1+0x120
            // std::map layout: [size(8)][root_ptr(8)][...][...]
            // The map is at param_1+0x120, with root at param_1+0x128
            // A map node has: [left(8)][parent(8)][right(8)][color(1)][padding(7)][key(8)][value(8)]
            // The value is a pointer to the crypto context
            static int cryptoDumped = 0;
            if (!cryptoDumped) {
                cryptoDumped = 1;
                unsigned char *mapArea = (unsigned char*)rbx_val + 0x120;
                if (!IsBadReadPtr(mapArea, 0x10)) {
                    UINT64 mapSize = *(UINT64*)mapArea;
                    UINT64 rootNode = *(UINT64*)(mapArea + 8);
                    Log("  MAP: size=%llu root=%p", mapSize, (void*)rootNode);

                    if (mapSize > 0 && rootNode > 0x10000 && !IsBadReadPtr((void*)rootNode, 0x30)) {
                        // Navigate: the root's left child is the first real node
                        UINT64 left = *(UINT64*)rootNode;
                        Log("  Root left child: %p", (void*)left);

                        if (left > 0x10000 && !IsBadReadPtr((void*)left, 0x50)) {
                            // Node layout: left(8) parent(8) right(8) color(4) pad(4) key(8) value(8)
                            // Try different offsets for the value
                            // Dump the TREE KEY at node+0x20 (8 bytes) - critical for recv crypto lookup
                            if (!IsBadReadPtr((void*)(left + 0x20), 8)) {
                                UINT64 treeKey = *(UINT64*)(left + 0x20);
                                Log("  TREE_KEY at node+0x20 = 0x%016llX (%lld)", treeKey, treeKey);
                            }
                            for (int voff = 0x20; voff <= 0x40; voff += 8) {
                                UINT64 val = *(UINT64*)(left + voff);
                                if (val > 0x10000 && !IsBadReadPtr((void*)val, 0x20)) {
                                    unsigned char *ctx = (unsigned char*)val;
                                    // Dump first 32 bytes — should contain IV at +8
                                    Log("  Node+0x%02X -> %p: %02X%02X%02X%02X %02X%02X%02X%02X | %02X%02X%02X%02X %02X%02X%02X%02X",
                                        voff, (void*)val,
                                        ctx[0],ctx[1],ctx[2],ctx[3],ctx[4],ctx[5],ctx[6],ctx[7],
                                        ctx[8],ctx[9],ctx[10],ctx[11],ctx[12],ctx[13],ctx[14],ctx[15]);
                                    // Check if +16 looks like P-box (should be modified Blowfish values)
                                    // P-box[0] should NOT be 0x243F6A88 (initial) if key was set
                                    UINT32 p0 = *(UINT32*)(ctx + 16);
                                    if (p0 != 0x243F6A88 && p0 != 0 && p0 != 0xFFFFFFFF) {
                                        Log("    *** POSSIBLE BF_KEY! P[0]=0x%08X (not initial) ***", p0);
                                        Log("    IV (bytes 8-15): %02X %02X %02X %02X %02X %02X %02X %02X",
                                            ctx[8],ctx[9],ctx[10],ctx[11],ctx[12],ctx[13],ctx[14],ctx[15]);
                                        // Save the crypto context to file
                                        char fn[MAX_PATH];
                                        snprintf(fn, MAX_PATH, "%s\\CRYPTO_CTX_%p.bin", logDir, (void*)val);
                                        FILE *f = fopen(fn, "wb");
                                        if (f) { fwrite(ctx, 1, 4200, f); fclose(f); }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // RBX = param_1. Read the crypto context at param_1 + 0x120.
            unsigned char *p1 = (unsigned char*)rbx_val;
            if (p1 && !IsBadReadPtr(p1 + 0x120, 8)) {
                // param_1 + 0x120 is the crypto map/tree pointer
                // The crypto context is looked up from this map
                // Let's dump the area around +0x120 to understand the structure
                Log("  === CRYPTO CONTEXT (param_1 + 0x100 to +0x180) ===");
                if (!IsBadReadPtr(p1 + 0x100, 0x80)) {
                    for (int row = 0; row < 8; row++) {
                        char hex[128] = {0};
                        for (int j = 0; j < 16; j++)
                            sprintf(hex + j*3, "%02X ", p1[0x100 + row*16 + j]);
                        Log("    +0x%03X: %s", 0x100 + row*16, hex);
                    }
                }
                // Follow the pointer at +0x128 (the map/tree root)
                UINT64 mapPtr = *(UINT64*)(p1 + 0x128);
                if (mapPtr > 0x10000 && !IsBadReadPtr((void*)mapPtr, 0x40)) {
                    Log("  Map root at %p:", (void*)mapPtr);
                    // A std::map node has: [left][parent][right][color][key][value]
                    // value is what we want - the crypto context pointer
                    // Let's dump the node
                    char hex[256] = {0};
                    for (int j = 0; j < 64; j++)
                        sprintf(hex + j*3, "%02X ", ((unsigned char*)mapPtr)[j]);
                    Log("    %s", hex);

                    // Try following pointers to find the crypto context
                    // The value pointer should lead to a BF_KEY structure
                    for (int off = 0; off < 64; off += 8) {
                        UINT64 val = *(UINT64*)(mapPtr + off);
                        if (val > 0x10000 && !IsBadReadPtr((void*)val, 32)) {
                            unsigned char *ctx = (unsigned char*)val;
                            // Check if this looks like a BF_KEY: offset +16 should have P-box
                            // Or check if +0 and +8 are the IV (small values)
                            Log("    +%02X -> %p: %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X",
                                off, (void*)val,
                                ctx[0],ctx[1],ctx[2],ctx[3],ctx[4],ctx[5],ctx[6],ctx[7],
                                ctx[8],ctx[9],ctx[10],ctx[11],ctx[12],ctx[13],ctx[14],ctx[15]);
                        }
                    }
                }
            }
            if (p1 && !IsBadReadPtr(p1, 0xE0)) {
                UINT64 qbase = *(UINT64*)(p1 + 0xB8);
                UINT64 qidx  = *(UINT64*)(p1 + 0xC0);
                UINT64 qmask = *(UINT64*)(p1 + 0xC8);
                UINT64 qcount = *(UINT64*)(p1 + 0xD0);
                Log("  QUEUE: base=%p idx=%llu mask=%llu count=%llu", (void*)qbase, qidx, qmask, qcount);

                // The last dequeued entry is at index (qidx-1) & mask
                // But mask might be 0 (wrong offset). Try reading queue entries directly.
                // The queue base points to an array of pointers.
                if (qbase > 0x10000 && !IsBadReadPtr((void*)qbase, 64)) {
                    // Read entry [0] in detail (the last dequeued packet)
                    UINT64 entry0 = *(UINT64*)qbase;
                    if (entry0 > 0x10000 && !IsBadReadPtr((void*)entry0, 0x300)) {
                        Log("  QUEUE ENTRY [0] at %p (full dump, 768 bytes):", (void*)entry0);
                        unsigned char *ep = (unsigned char*)entry0;
                        for (int row = 0; row < 48; row++) {
                            char hex[128] = {0};
                            for (int j = 0; j < 16; j++)
                                sprintf(hex + j*3, "%02X ", ep[row*16 + j]);
                            Log("    +0x%03X: %s", row*16, hex);
                        }
                        // Save to file
                        char fn[MAX_PATH];
                        snprintf(fn, MAX_PATH, "%s\\QUEUE_ENTRY_%p.bin", logDir, (void*)entry0);
                        FILE *f = fopen(fn, "wb");
                        if (f) { fwrite(ep, 1, 0x300, f); fclose(f); }
                    }
                }

                // Also try: the entry the send loop just read
                // From Ghidra: puVar2 = *(ptr*)(qbase + ((qidx-1) & qmask) * 8)
                // If mask=0, try mask=7 (power of 2 - 1 for 8 entries)
                for (UINT64 testMask = 0; testMask <= 15; testMask++) {
                    UINT64 entryIdx = (qidx - 1) & testMask;
                    if (!IsBadReadPtr((void*)(qbase + entryIdx * 8), 8)) {
                        UINT64 entryPtr = *(UINT64*)(qbase + entryIdx * 8);
                        if (entryPtr > 0x10000 && !IsBadReadPtr((void*)entryPtr, 32)) {
                            Log("  entry(mask=%llu, idx=%llu): %p first8=%02X%02X%02X%02X%02X%02X%02X%02X",
                                testMask, entryIdx, (void*)entryPtr,
                                ((unsigned char*)entryPtr)[0], ((unsigned char*)entryPtr)[1],
                                ((unsigned char*)entryPtr)[2], ((unsigned char*)entryPtr)[3],
                                ((unsigned char*)entryPtr)[4], ((unsigned char*)entryPtr)[5],
                                ((unsigned char*)entryPtr)[6], ((unsigned char*)entryPtr)[7]);
                        }
                    }
                }
            }

            // Try each register as param_1 and read the queue structure
            void* candidates[] = { rbx_val, r12_val, r13_val, r14_val, r15_val, rdi_val, rsi_val };
            const char* names[] = { "RBX", "R12", "R13", "R14", "R15", "RDI", "RSI" };
            for (int ci = 0; ci < 7; ci++) {
                unsigned char *p = (unsigned char*)candidates[ci];
                if (p && !IsBadReadPtr(p + 0xB8, 32)) {
                    // Read queue structure: base at +0xB8, index at +0xC0, mask at +0xC8, count at +0xD0
                    UINT64 qbase = *(UINT64*)(p + 0xB8);
                    UINT64 qidx = *(UINT64*)(p + 0xC0);
                    UINT64 qmask = *(UINT64*)(p + 0xC8);
                    UINT64 qcount = *(UINT64*)(p + 0xD0);
                    if (qbase > 0x10000 && qmask > 0 && qmask < 0x10000 && qcount < 1000) {
                        Log("  *** QUEUE FOUND via %s! base=%p idx=%llu mask=%llu count=%llu ***",
                            names[ci], (void*)qbase, qidx, qmask, qcount);
                        // Read the current queue entry
                        UINT64 entry_ptr = *(UINT64*)(qbase + ((qidx - 1) & qmask) * 8);
                        if (entry_ptr > 0x10000 && !IsBadReadPtr((void*)entry_ptr, 128)) {
                            char hex[512] = {0};
                            for (int j = 0; j < 128; j++)
                                sprintf(hex + j*3, "%02X ", ((unsigned char*)entry_ptr)[j]);
                            Log("  QUEUE ENTRY: %s", hex);
                        }
                    }
                }
            }
        }
        // Dump buffer context: 128 bytes before and after the buffer
        if (0 && len == 519 && pktCount <= 3) { // DISABLED
            // Try reading BEFORE the buffer - might contain plaintext header/structure
            Log("  === BUFFER CONTEXT (128B before buf) ===");
            unsigned char *pre = (unsigned char*)buf - 128;
            if (!IsBadReadPtr(pre, 128)) {
                char hex[512] = {0};
                for (int i = 0; i < 128; i++) sprintf(hex+i*3, "%02X ", pre[i]);
                Log("  PRE: %s", hex);
            }
            // Also dump 64 bytes AFTER the buffer
            unsigned char *post = (unsigned char*)buf + 519;
            if (!IsBadReadPtr(post, 64)) {
                char hex[256] = {0};
                for (int i = 0; i < 64; i++) sprintf(hex+i*3, "%02X ", post[i]);
                Log("  POST: %s", hex);
            }
        }
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

// BF_encrypt(zeros) for key 17BLOhi6KZsTtldTsizvHg==
static const BYTE bf_enc_zeros[8] = {0xF9, 0xED, 0x26, 0xC0, 0xF2, 0x2A, 0x52, 0xB4};

static int recvCallLogged = 0;

// (moved to before Hook_sendto)

int WINAPI Hook_recvfrom(SOCKET s, char *buf, int len, int flags,
                         struct sockaddr *from, int *fromlen) {
    int r = real_recvfrom(s, buf, len, flags, from, fromlen);
    if (r > 0 && from && from->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in*)from;
        int isLocalhost = (ntohl(sin->sin_addr.s_addr) == 0x7F000001); // 127.0.0.1

        // INJECTION: Replace server response with echo of client's last sendto
        if (isLocalhost && injectMode && lastSendLen > 8 && injectCount < 500) {
            int echoLen = lastSendLen - 8;  // strip LNPBlob (8 bytes)
            if (echoLen > 0 && echoLen <= len) {
                memcpy(buf, lastSendBuf + 8, echoLen);
                r = echoLen;
                injectCount++;
                if (injectCount <= 5) {
                    Log("INJECT_ECHO #%d: replaced %dB server data with %dB echo", injectCount, r, echoLen);
                }
            }
        }

        if (isLocalhost) {
            // Detailed logging for packets from our server
            Log("RECV_SERVER #%d: %dB from 127.0.0.1:%d",
                pktCount + 1, r, ntohs(sin->sin_port));

            // Hex dump first 32 bytes
            if (logfile) {
                EnterCriticalSection(&logLock);
                fprintf(logfile, "  RAW[0:32]: ");
                for (int i = 0; i < r && i < 32; i++)
                    fprintf(logfile, "%02X ", (unsigned char)buf[i]);
                fprintf(logfile, "\n");

                // XOR first 8 bytes with BF_encrypt(zeros) to decrypt header
                if (r >= 8) {
                    BYTE decrypted[8];
                    for (int i = 0; i < 8; i++)
                        decrypted[i] = (unsigned char)buf[i] ^ bf_enc_zeros[i];
                    fprintf(logfile, "  XOR_DEC[0:8]: ");
                    for (int i = 0; i < 8; i++)
                        fprintf(logfile, "%02X ", decrypted[i]);
                    fprintf(logfile, "\n");

                    // ENet encrypted header: first 2 bytes = sessionID (LE), byte 2 or 3 = command
                    // After XOR: decrypted[0..1] = sessionID, decrypted[2] = possible cmd byte
                    UINT16 sessionID = decrypted[0] | (decrypted[1] << 8);
                    BYTE cmdByte = decrypted[2];
                    fprintf(logfile, "  Decrypted: SessionID=0x%04X (%d), CmdByte=0x%02X (%d)\n",
                            sessionID, sessionID, cmdByte, cmdByte);

                    // Also try big-endian sessionID interpretation
                    UINT16 sessionBE = (decrypted[0] << 8) | decrypted[1];
                    fprintf(logfile, "  Alt (BE): SessionID=0x%04X, Cmd[2]=0x%02X Cmd[3]=0x%02X\n",
                            sessionBE, decrypted[2], decrypted[3]);
                }
                fflush(logfile);
                LeaveCriticalSection(&logLock);
            }

            // Log return addresses to find which function processes recv data
            if (recvCallLogged < 10) {
                recvCallLogged++;
                void *ret0 = __builtin_return_address(0);
                void *ret1 = __builtin_return_address(1);
                HMODULE mod0 = NULL, mod1 = NULL;
                GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)ret0, &mod0);
                GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)ret1, &mod1);
                char n0[256]={0}, n1[256]={0};
                if(mod0) GetModuleFileNameA(mod0, n0, 256);
                if(mod1) GetModuleFileNameA(mod1, n1, 256);
                Log("  recvfrom CALLSTACK:");
                Log("    ret0=%p %s +0x%llX", ret0, n0, (UINT64)ret0-(UINT64)mod0);
                Log("    ret1=%p %s +0x%llX", ret1, n1, (UINT64)ret1-(UINT64)mod1);
            }

            // Save with decrypted cmd byte in filename
            BYTE cmdTag = 0;
            if (r >= 8) {
                cmdTag = (unsigned char)buf[2] ^ bf_enc_zeros[2]; // decrypted byte 2
            }
            pktCount++;
            char fn[MAX_PATH];
            snprintf(fn, MAX_PATH, "%s\\RECV_SRV_%04d_%dB_cmd%02X.bin",
                     logDir, pktCount, r, cmdTag);
            FILE *f = fopen(fn, "wb");
            if (f) { fwrite(buf, 1, r, f); fclose(f); }

            // Also log via standard SavePacket for the hex dump
            // (don't increment pktCount again, just log)
            char addrStr[64];
            snprintf(addrStr, 64, "127.0.0.1:%d", ntohs(sin->sin_port));
            Log("RECV_SRV #%d: %dB %s cmd=0x%02X", pktCount, r, addrStr, cmdTag);
        } else {
            // Non-localhost: use standard logging
            SavePacket("RECV", buf, r, from);
        }
    }
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

        // PATCH CRC CHECK IMMEDIATELY - before stub.dll loads and sets guard pages!
        PatchCrcCheckEarly();

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
