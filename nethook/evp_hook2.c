// evp_hook2.c - version.dll proxy that monitors Blowfish key setup and captures IV
// Strategy:
// 1. Install network hooks (sendto/WSASendTo) immediately when ws2_32 loads
// 2. After 5s delay, scan memory for P-box locations
// 3. Monitor P-box memory for changes (= BF_set_key was called)
// 4. When P-box changes, dump the new P-box values and try to find the IV
// 5. Also scan for EVP_CIPHER_CTX structures which contain the IV
//
// The EVP_CIPHER_CTX structure (OpenSSL) contains:
//   - cipher pointer (points to EVP_CIPHER with "BF-CBC" etc.)
//   - key_len, iv_len
//   - iv[EVP_MAX_IV_LENGTH] = the actual IV being used!
//   - buf, num, final etc.
//
// Compile: gcc -shared -o version.dll evp_hook2.c -lws2_32 -O2

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
    char hex[1024] = {0};
    int n = len < 128 ? len : 128;
    for (int i = 0; i < n; i++) sprintf(hex + i*3, "%02X ", data[i]);
    Log("  %s (%dB): %s", label, len, hex);
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

// ============ Network hooks ============
static unsigned char tramp_sendto[32], tramp_WSASendTo[32], tramp_recvfrom[32], tramp_WSARecvFrom[32];
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

// ============ Hook helpers ============
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
    *(UINT64*)((unsigned char*)target + 6) = (UINT64)hook;
    VirtualProtect(target, 16, old, &old);
}

static int hooksInstalled = 0;
static void InstallNetHooks(void) {
    if (hooksInstalled) return;
    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    if (!ws2) ws2 = LoadLibraryA("ws2_32.dll");
    if (!ws2) return;
    void *p;
    p = GetProcAddress(ws2, "sendto");
    if (p) { MakeTrampoline(p, tramp_sendto); PatchJmp(p, Hook_sendto); }
    p = GetProcAddress(ws2, "WSASendTo");
    if (p) { MakeTrampoline(p, tramp_WSASendTo); PatchJmp(p, Hook_WSASendTo); }
    p = GetProcAddress(ws2, "recvfrom");
    if (p) { MakeTrampoline(p, tramp_recvfrom); PatchJmp(p, Hook_recvfrom); }
    p = GetProcAddress(ws2, "WSARecvFrom");
    if (p) { MakeTrampoline(p, tramp_WSARecvFrom); PatchJmp(p, Hook_WSARecvFrom); }
    hooksInstalled = 1;
    Log("Network hooks installed");
}

// ============ EVP_CIPHER_CTX scanner ============
// OpenSSL EVP_CIPHER_CTX contains an IV at a known offset.
// For OpenSSL 1.1.x, the structure is approximately:
//   offset 0x00: const EVP_CIPHER *cipher
//   offset 0x08: ENGINE *engine
//   offset 0x10: int encrypt
//   offset 0x14: int buf_len
//   offset 0x18: unsigned char oiv[EVP_MAX_IV_LENGTH]  ← original IV (16 bytes)
//   offset 0x28: unsigned char iv[EVP_MAX_IV_LENGTH]   ← current IV (16 bytes)
//   offset 0x38: unsigned char buf[EVP_MAX_BLOCK_LENGTH]
//   offset 0x48: int num
//   offset 0x4C: int key_len
//   offset 0x50: unsigned long flags
//   offset 0x58: void *cipher_data ← points to BF_KEY structure
//
// BF_KEY structure (OpenSSL):
//   BF_LONG P[BF_ROUNDS + 2]  = uint32[18]  = 72 bytes
//   BF_LONG S[4 * 256]        = uint32[1024] = 4096 bytes
//   Total: 4168 bytes
//
// We can find active BF_KEY by looking for modified P-box values
// (not the initial Pi digits)

static BYTE *pboxAddr1 = NULL;
static BYTE *pboxAddr2 = NULL;
static BYTE pboxSnapshot1[72]; // 18 uint32 = 72 bytes for P-box
static BYTE pboxSnapshot2[72];

static DWORD WINAPI MonitorThread(LPVOID param) {
    Log("=== Monitor thread started ===");

    // Install net hooks immediately, then retry every second
    for (int retry = 0; retry < 10; retry++) {
        InstallNetHooks();
        if (hooksInstalled) break;
        Sleep(500);
    }

    HMODULE exe = GetModuleHandleA(NULL);
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)exe;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)((BYTE*)exe + dos->e_lfanew);
    DWORD imageSize = nt->OptionalHeader.SizeOfImage;
    BYTE *base = (BYTE*)exe;
    Log("Module: %p size=0x%X", base, imageSize);

    // Find P-box locations
    BYTE pboxPattern[] = { 0x88, 0x6A, 0x3F, 0x24, 0xD3, 0x08, 0xA3, 0x85, 0x2E, 0x8A, 0x19, 0x13 };
    int pboxCount = 0;

    for (DWORD i = 0; i < imageSize - sizeof(pboxPattern); i++) {
        BYTE *ptr = base + i;
        if (!IsBadReadPtr(ptr, sizeof(pboxPattern))) {
            if (memcmp(ptr, pboxPattern, sizeof(pboxPattern)) == 0) {
                if (pboxCount == 0) { pboxAddr1 = ptr; memcpy(pboxSnapshot1, ptr, 72); }
                if (pboxCount == 1) { pboxAddr2 = ptr; memcpy(pboxSnapshot2, ptr, 72); }
                Log("P-box #%d at %p (offset 0x%X)", pboxCount, ptr, i);
                pboxCount++;
            }
        } else {
            i += 0x1000 - (i % 0x1000);
        }
    }

    // Skip heavy heap scan — it causes DirectX init to fail
    // Just monitor P-box changes instead
    goto monitor;
    // Now scan the HEAP for BF_KEY structures (modified P-boxes)
    // A modified P-box will NOT start with 0x243F6A88 (the Pi constant)
    // Instead it will have the key-mixed values
    // We search for structures where:
    // - 18 uint32 values (P-box) followed by 1024 uint32 values (S-boxes)
    // - The P-box values are NOT the initial Pi values
    // - The structure is 4168 bytes total

    Log("Scanning heap for active BF_KEY structures...");

    // Scan all readable memory regions
    MEMORY_BASIC_INFORMATION mbi;
    BYTE *addr = NULL;
    int bfKeyCount = 0;

    while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
            BYTE *regionBase = (BYTE*)mbi.BaseAddress;
            SIZE_T regionSize = mbi.RegionSize;

            // Skip the exe's .rdata section (contains the static P-box)
            if (regionBase >= base && regionBase < base + imageSize) {
                addr = regionBase + regionSize;
                continue;
            }

            for (SIZE_T j = 0; j + 4168 <= regionSize; j += 4) {
                BYTE *ptr = regionBase + j;
                if (IsBadReadPtr(ptr, 4168)) break;

                // Check if this looks like a BF_KEY with modified P-box
                DWORD *P = (DWORD*)ptr;

                // The P-box should NOT be the initial values
                if (P[0] == 0x243F6A88) continue; // Still initial values

                // But should have reasonable uint32 values (not zeros, not all FF)
                if (P[0] == 0 && P[1] == 0) continue;
                if (P[0] == 0xFFFFFFFF) continue;

                // Check S-box pattern: S-boxes follow P-box at offset 72
                // S-box[0] initial value: 0xD1310BA6
                DWORD *S = (DWORD*)(ptr + 72);

                // If S-box values are also modified (not initial), this could be a BF_KEY
                if (S[0] != 0xD1310BA6 && S[0] != 0 && S[0] != 0xFFFFFFFF) {
                    // Potential BF_KEY found!
                    bfKeyCount++;
                    Log("*** POTENTIAL BF_KEY #%d at %p ***", bfKeyCount, ptr);
                    LogHex("P-box (first 32B)", ptr, 32);
                    LogHex("S-box start (16B)", ptr + 72, 16);

                    // Now look BACKWARDS for the EVP_CIPHER_CTX
                    // The cipher_data pointer in EVP_CIPHER_CTX points to this BF_KEY
                    // Search nearby memory for a pointer to this address
                    UINT64 bfKeyAddr = (UINT64)ptr;
                    BYTE *searchStart = ptr - 256;
                    if (searchStart < regionBase) searchStart = regionBase;

                    for (int k = 0; k < 256; k += 8) {
                        if (!IsBadReadPtr(searchStart + k, 8)) {
                            if (*(UINT64*)(searchStart + k) == bfKeyAddr) {
                                Log("  Pointer to BF_KEY at %p (offset -%d from key)", searchStart + k, (int)(ptr - searchStart - k));
                                // This might be the cipher_data field of EVP_CIPHER_CTX
                                // The IV would be at offset -0x30 from cipher_data (approximately)
                                BYTE *ctxBase = searchStart + k - 0x58; // cipher_data is at offset 0x58
                                if (!IsBadReadPtr(ctxBase, 0x60)) {
                                    Log("  Possible EVP_CIPHER_CTX at %p:", ctxBase);
                                    LogHex("  oiv (original IV)", ctxBase + 0x18, 16);
                                    LogHex("  iv (current IV)", ctxBase + 0x28, 16);
                                    LogHex("  Full CTX", ctxBase, 96);
                                }
                            }
                        }
                    }

                    if (bfKeyCount >= 5) break; // Limit output
                }
            }
        }
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }

    Log("Found %d potential BF_KEY structures on heap", bfKeyCount);

monitor:
    // Keep monitoring - try to install hooks periodically
    for (int iter = 0; iter < 30; iter++) {
        Sleep(2000);
        InstallNetHooks();

        // Check if P-box values changed (key was set)
        if (pboxAddr1 && !IsBadReadPtr(pboxAddr1, 72)) {
            if (memcmp(pboxAddr1, pboxSnapshot1, 72) != 0) {
                Log("*** P-BOX #1 CHANGED! Key was set! ***");
                LogHex("New P-box", pboxAddr1, 72);
                memcpy(pboxSnapshot1, pboxAddr1, 72);
            }
        }
    }

    Log("=== Monitor thread finished ===");
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
        char lp[MAX_PATH]; snprintf(lp, MAX_PATH, "%s\\evp_hook2.log", logDir);
        logfile = fopen(lp, "w");
        Log("=== LoL EVP Hook v2 ===");
        Log("PID: %lu", GetCurrentProcessId());
        CreateThread(NULL, 0, MonitorThread, NULL, 0, NULL);
    }
    else if (reason == DLL_PROCESS_DETACH) {
        Log("Unloading");
        if (logfile) fclose(logfile);
    }
    return TRUE;
}
