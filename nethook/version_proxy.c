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
#include <tlhelp32.h>

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

// Forward declarations (defined later in the file)
static void Log(const char *fmt, ...);
static volatile BYTE *connStructAddr = NULL;  // connection struct address, captured in sendto hook
static volatile UINT32 g_connToken = 0;       // connection token from first 519B packet

// === BLOWFISH + CRC FIXUP ===
// Compact Blowfish implementation for CRC nonce fixup on server packets.
// Key: 17BLOhi6KZsTtldTsizvHg== (base64) = D7B048862E9B4CB6D359BCAE239BF887 (hex, 16 bytes)

// Blowfish initial P-array and S-boxes (pi hex digits)
static const UINT32 bf_init_P[18] = {
    0x243F6A88,0x85A308D3,0x13198A2E,0x03707344,0xA4093822,0x299F31D0,
    0x082EFA98,0xEC4E6C89,0x452821E6,0x38D01377,0xBE5466CF,0x34E90C6C,
    0xC0AC29B7,0xC97C50DD,0x3F84D5B5,0xB5470917,0x9216D5D9,0x8979FB1B
};

// S-box initial values (standard Blowfish, from pi)
// These are 4 x 256 = 1024 uint32 values.
// For brevity, we generate them at init time by including the standard values.
// Actually, Blowfish S-boxes are fixed constants. We include them inline.
#include "bf_sbox.h"  // will create this file with the 1024 uint32 S-box values

// Our BF key schedule
static UINT32 hook_P[18];
static UINT32 hook_S[4][256];
static int hookBfReady = 0;

static void HookBF_Encrypt(UINT32 *xl, UINT32 *xr) {
    UINT32 Xl = *xl, Xr = *xr, t;
    for (int i = 0; i < 16; i++) {
        Xl ^= hook_P[i];
        UINT32 f = ((hook_S[0][(Xl>>24)&0xFF] + hook_S[1][(Xl>>16)&0xFF]) ^ hook_S[2][(Xl>>8)&0xFF]) + hook_S[3][Xl&0xFF];
        Xr ^= f;
        t = Xl; Xl = Xr; Xr = t;
    }
    t = Xl; Xl = Xr; Xr = t;
    Xr ^= hook_P[16]; Xl ^= hook_P[17];
    *xl = Xl; *xr = Xr;
}

static void HookBF_Decrypt(UINT32 *xl, UINT32 *xr) {
    UINT32 Xl = *xl, Xr = *xr, t;
    for (int i = 17; i > 1; i--) {
        Xl ^= hook_P[i];
        UINT32 f = ((hook_S[0][(Xl>>24)&0xFF] + hook_S[1][(Xl>>16)&0xFF]) ^ hook_S[2][(Xl>>8)&0xFF]) + hook_S[3][Xl&0xFF];
        Xr ^= f;
        t = Xl; Xl = Xr; Xr = t;
    }
    t = Xl; Xl = Xr; Xr = t;
    Xr ^= hook_P[1]; Xl ^= hook_P[0];
    *xl = Xl; *xr = Xr;
}

static void HookBF_Init(const BYTE *key, int keyLen) {
    memcpy(hook_P, bf_init_P, sizeof(hook_P));
    memcpy(hook_S, bf_init_S, sizeof(hook_S));
    // XOR P-array with key
    for (int i = 0, j = 0; i < 18; i++) {
        UINT32 d = 0;
        for (int k = 0; k < 4; k++) { d = (d << 8) | key[j]; j = (j + 1) % keyLen; }
        hook_P[i] ^= d;
    }
    // Encrypt-and-replace P-array
    UINT32 l = 0, r = 0;
    for (int i = 0; i < 18; i += 2) {
        HookBF_Encrypt(&l, &r);
        hook_P[i] = l; hook_P[i+1] = r;
    }
    // Encrypt-and-replace S-boxes
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 256; j += 2) {
            HookBF_Encrypt(&l, &r);
            hook_S[i][j] = l; hook_S[i][j+1] = r;
        }
    hookBfReady = 1;
}

// CFB encrypt (block-by-block, IV=0, only full 8-byte blocks)
// Matches game's FUN_1410f41e0 mode=2: remaining bytes are NOT encrypted
static void HookCFB_Encrypt(BYTE *data, int len) {
    BYTE iv[8] = {0};
    int fullBlocks = len / 8;
    for (int b = 0; b < fullBlocks; b++) {
        int i = b * 8;
        UINT32 l = (iv[0]<<24)|(iv[1]<<16)|(iv[2]<<8)|iv[3];
        UINT32 r = (iv[4]<<24)|(iv[5]<<16)|(iv[6]<<8)|iv[7];
        HookBF_Encrypt(&l, &r);
        BYTE ks[8] = {l>>24,l>>16,l>>8,l, r>>24,r>>16,r>>8,r};
        for (int j = 0; j < 8; j++)
            data[i+j] ^= ks[j];
        // Feedback = ciphertext (after XOR)
        memcpy(iv, data + i, 8);
    }
    // Remaining bytes (len % 8) are NOT encrypted
}

// CFB decrypt (block-by-block, IV=0, only full 8-byte blocks)
static void HookCFB_Decrypt(BYTE *data, int len) {
    BYTE iv[8] = {0};
    int fullBlocks = len / 8;
    for (int b = 0; b < fullBlocks; b++) {
        int i = b * 8;
        // Save ciphertext for feedback BEFORE XOR
        BYTE ct[8];
        memcpy(ct, data + i, 8);
        UINT32 l = (iv[0]<<24)|(iv[1]<<16)|(iv[2]<<8)|iv[3];
        UINT32 r = (iv[4]<<24)|(iv[5]<<16)|(iv[6]<<8)|iv[7];
        HookBF_Encrypt(&l, &r);
        BYTE ks[8] = {l>>24,l>>16,l>>8,l, r>>24,r>>16,r>>8,r};
        for (int j = 0; j < 8; j++)
            data[i+j] ^= ks[j];
        // Feedback = original ciphertext
        memcpy(iv, ct, 8);
    }
    // Remaining bytes pass through unmodified
}

static void ReverseBytes(BYTE *data, int len) {
    for (int i = 0; i < len / 2; i++) {
        BYTE t = data[i]; data[i] = data[len-1-i]; data[len-1-i] = t;
    }
}

// Double CFB decrypt: CFB-decrypt → reverse → CFB-decrypt
static void HookDoubleCFB_Decrypt(BYTE *data, int len) {
    HookCFB_Decrypt(data, len);
    ReverseBytes(data, len);
    HookCFB_Decrypt(data, len);
}

// Double CFB encrypt: CFB-encrypt → reverse → CFB-encrypt
static void HookDoubleCFB_Encrypt(BYTE *data, int len) {
    HookCFB_Encrypt(data, len);
    ReverseBytes(data, len);
    HookCFB_Encrypt(data, len);
}

// CRC-32 table (poly 0x04C11DB7, unreflected)
static UINT32 crc_table[256];
static void InitCrcTable(void) {
    for (int i = 0; i < 256; i++) {
        UINT32 c = (UINT32)i << 24;
        for (int j = 0; j < 8; j++)
            c = (c & 0x80000000) ? ((c << 1) ^ 0x04C11DB7) : (c << 1);
        crc_table[i] = c;
    }
}

// LoL CRC byte: crc = ((crc << 8) | byte) ^ table[crc >> 24]
static UINT32 LolCrcByte(UINT32 crc, BYTE b) {
    return ((crc << 8) | b) ^ crc_table[(crc >> 24) & 0xFF];
}

// Compute CRC nonce for a decrypted packet
// Decrypted format: [2B peerID LE][4B nonce][1B flags][payload...]
// Returns the correct 4-byte nonce value (as stored in packet)
static UINT32 ComputeCrcNonce(const BYTE *decrypted, int len) {
    BYTE peerLo = decrypted[0];
    BYTE peerHi = decrypted[1];
    // Build CRC struct fields:
    // param[0..7] = local_c8 = *(conn+0x138) = 1 as uint64 LE
    BYTE local_c8[8] = {1, 0, 0, 0, 0, 0, 0, 0};
    // param[8] = peerLo, param[9] = peerHi
    // *(uint64*)(param+0x18) = 0xFFFFFFFFFFFFFFFF

    // Init from peerLo (param[8]):
    UINT32 crc = ((UINT32)peerLo | 0xFFFFFF00) ^ 0xB1F740B4;
    // Feed peerHi (param[9]):
    crc = LolCrcByte(crc, peerHi);
    // Feed local_c8 (param[0..7]):
    for (int i = 0; i < 8; i++) crc = LolCrcByte(crc, local_c8[i]);
    // Feed *(uint64*)(param+0x18) = 0xFFFFFFFFFFFFFFFF LE bytes:
    for (int i = 0; i < 8; i++) crc = LolCrcByte(crc, 0xFF);
    // Feed payload (bytes after 7-byte header)
    if (len > 7) {
        for (int i = 7; i < len; i++) crc = LolCrcByte(crc, decrypted[i]);
    }
    UINT32 nonce = ~crc;
    // Try both: write htonl variant. If CRC check fails, packet is silently dropped.
    // We need to figure out which one passes. Add logging to detect.
    return htonl(nonce);
}

// Fix CRC nonce in an encrypted server packet using the GAME'S OWN CRC function
// This guarantees the nonce matches exactly what the client expects.
static int crcFixupLogCount = 0;
static int FixCrcNonce(BYTE *buf, int len) {
    if (!hookBfReady || len < 8) return 0;

    HMODULE hExe = GetModuleHandleA(NULL);
    if (!hExe) return 0;

    // Format: entire packet is Double-CFB encrypted: [2B peerID][4B nonce][1B flags][body...]
    BYTE *work = (BYTE*)_alloca(len);
    memcpy(work, buf, len);
    HookDoubleCFB_Decrypt(work, len);

    // After decrypt: work[0..1]=peerID, work[2..5]=CRC nonce, work[6]=flags, work[7+]=body
    if (crcFixupLogCount < 10) {
        crcFixupLogCount++;
        char hexdump[128] = {0};
        int hoff = 0;
        for (int i = 0; i < len && i < 20 && hoff < 100; i++)
            hoff += snprintf(hexdump + hoff, sizeof(hexdump) - hoff, "%02X ", work[i]);
        Log("CRC_DBG #%d: len=%d dec: %s", crcFixupLogCount, len, hexdump);
    }

    // Build CRC struct for game's CRC function
    BYTE crcStruct[0x60];
    memset(crcStruct, 0, sizeof(crcStruct));
    UINT64 local_c8_val = 1;
    if (connStructAddr && !IsBadReadPtr((void*)(connStructAddr + 0x138), 8))
        local_c8_val = *(UINT64*)(connStructAddr + 0x138);
    *(UINT64*)(crcStruct + 0x00) = local_c8_val;
    crcStruct[0x08] = work[0]; // peerLo
    crcStruct[0x09] = work[1]; // peerHi
    *(UINT64*)(crcStruct + 0x18) = 0xFFFFFFFFFFFFFFFF;
    int payloadLen = (len > 7) ? (len - 7) : 0;
    *(UINT64*)(crcStruct + 0x48) = (UINT64)(work + 7);
    *(UINT16*)(crcStruct + 0x52) = (UINT16)payloadLen;

    typedef int (__fastcall *crc_fn_t)(BYTE*);
    crc_fn_t CrcFn = (crc_fn_t)((BYTE*)hExe + 0x577F10);
    int nonce = CrcFn(crcStruct);

    if (crcFixupLogCount <= 10)
        Log("CRC_DBG: peer=%02X%02X flags=0x%02X nonce=0x%08X", work[0], work[1], work[6], (UINT32)nonce);

    *(int*)(work + 2) = nonce;
    HookDoubleCFB_Encrypt(work, len);
    memcpy(buf, work, len);
    return 1;
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
static BYTE tramp_InitSecCtx[32];

// Forward declarations
static void Log(const char *fmt, ...);
static void MakeTrampoline(void *target, BYTE *tramp);
static void PatchJmp(void *target, void *dest);
static DWORD WINAPI TlsBypassThread(LPVOID param);
static DWORD GetSyscallNumber(const char *funcName);
typedef LONG (NTAPI *NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
static NtProtectVirtualMemory_t MakeSyscallStub(DWORD sysnum);

// Patch the embedded Riot CA cert with our FakeLCU cert
static void PatchRiotCA(void) {
    HMODULE hExe = GetModuleHandleA(NULL);
    if (!hExe) return;

    // Riot CA cert "LoL Game Engineering Certificate Authority" at RVA 0x19EEBD0 (1060 bytes DER)
    // Also the rclient cert at RVA 0x19EE230 (1241 bytes)
    BYTE *riotCA = (BYTE*)hExe + 0x19EEBD0;
    int riotCASize = 1060;

    // Verify it's still the Riot CA (check first few bytes of DER)
    if (riotCA[0] != 0x30 || riotCA[1] != 0x82) {
        Log("PatchRiotCA: bytes at RVA 0x19EEBD0 = %02X %02X (expected 30 82), skipping",
            riotCA[0], riotCA[1]);
        return;
    }

    // Read our FakeLCU cert from cert.pem
    FILE *f = fopen("cert.pem", "r");
    if (!f) f = fopen("D:\\LeagueOfLegendsV2\\fakeLcu.crt", "r");
    if (!f) { Log("PatchRiotCA: can't open cert file"); return; }

    char pem[4096] = {0};
    fread(pem, 1, sizeof(pem)-1, f);
    fclose(f);

    // Decode PEM to DER (skip BEGIN/END lines, base64 decode)
    BYTE der[2048];
    int derLen = 0;
    {
        // Simple base64 decode
        static const BYTE b64[] = {
            ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
            ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
            ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
            ['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
            ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
            ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
            ['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
            ['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63
        };
        char *p = pem;
        while (*p && strncmp(p, "-----BEGIN", 10) != 0) p++;
        while (*p && *p != '\n') p++; // skip BEGIN line
        p++;
        int bits = 0, nbits = 0;
        while (*p && strncmp(p, "-----END", 8) != 0) {
            if (*p == '\n' || *p == '\r' || *p == ' ') { p++; continue; }
            if (*p == '=') { p++; continue; }
            bits = (bits << 6) | b64[(unsigned char)*p];
            nbits += 6;
            if (nbits >= 8) {
                nbits -= 8;
                der[derLen++] = (BYTE)(bits >> nbits);
                bits &= (1 << nbits) - 1;
            }
            p++;
        }
    }

    Log("PatchRiotCA: our cert DER=%dB, Riot CA=%dB", derLen, riotCASize);

    if (derLen > riotCASize) {
        Log("PatchRiotCA: our cert is LARGER than Riot CA, can't patch");
        return;
    }

    // Patch in memory: replace Riot CA with our cert, zero-pad remainder
    // Use direct syscall to bypass stub.dll guard pages
    DWORD sysnum = GetSyscallNumber("NtProtectVirtualMemory");
    DWORD oldProt = 0;
    int patched = 0;
    if (sysnum != 0) {
        NtProtectVirtualMemory_t NtProt = MakeSyscallStub(sysnum);
        if (NtProt) {
            void *baseAddr = (void*)riotCA;
            SIZE_T regionSize = riotCASize;
            LONG status = NtProt((HANDLE)-1, &baseAddr, &regionSize, PAGE_READWRITE, &oldProt);
            Log("PatchRiotCA: NtProtect status=0x%08X oldProt=0x%X", status, oldProt);
            if (status == 0) {
                patched = 1;
            }
            VirtualFree((void*)NtProt, 0, MEM_RELEASE);
        }
    }
    if (!patched && VirtualProtect(riotCA, riotCASize, PAGE_READWRITE, &oldProt)) {
        patched = 1;
    }
    if (patched) {
        memcpy(riotCA, der, derLen);
        memset(riotCA + derLen, 0, riotCASize - derLen);
        // Fix the DER length field to match original size
        // Actually, keep original cert structure but just replace the content
        // The zero padding will make the cert invalid, but the TLS lib should
        // use the size from the DER header, not the allocated size
        VirtualProtect(riotCA, riotCASize, oldProt, &oldProt);
        Log("*** PatchRiotCA: REPLACED Riot CA with our cert! ***");
    } else {
        Log("PatchRiotCA: VirtualProtect failed (err=%lu)", GetLastError());
    }
}

// Schannel TLS bypass: hook InitializeSecurityContextW
typedef LONG (WINAPI *InitSecCtxW_fn)(void*, void*, void*, ULONG, ULONG, ULONG, void*, ULONG, void*, void*, ULONG*, void*);
static InitSecCtxW_fn real_InitSecCtxW = NULL;
static int tlsHookCount = 0;

LONG WINAPI Hook_InitSecCtxW(void *p1, void *p2, void *p3, ULONG fContextReq,
    ULONG r1, ULONG TargetDataRep, void *pInput, ULONG r2,
    void *pNewCtx, void *pOutput, ULONG *pfContextAttr, void *ptsExpiry) {

    // Add ISC_REQ_MANUAL_CRED_VALIDATION to disable automatic cert validation
    // ISC_REQ_MANUAL_CRED_VALIDATION = 0x00080000
    fContextReq |= 0x00080000;

    LONG result = real_InitSecCtxW(p1, p2, p3, fContextReq, r1, TargetDataRep,
                                    pInput, r2, pNewCtx, pOutput, pfContextAttr, ptsExpiry);

    tlsHookCount++;
    if (tlsHookCount <= 20) {
        Log("InitSecCtx #%d: flags=0x%08X result=0x%08X", tlsHookCount, fContextReq, result);
    }

    // If the result is SEC_E_UNTRUSTED_ROOT or similar cert error, change to OK
    if (result == (LONG)0x80090325 ||   // SEC_E_UNTRUSTED_ROOT
        result == (LONG)0x80090326 ||   // SEC_E_CERT_UNKNOWN
        result == (LONG)0x80090328) {   // SEC_E_WRONG_PRINCIPAL
        Log("  TLS cert error 0x%08X → forcing SEC_I_CONTINUE_NEEDED", result);
        result = 0x00090312;  // SEC_I_CONTINUE_NEEDED
    }

    return result;
}

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
static volatile void *recvHostStruct = NULL;
UINT64 g_x509Vtable = 0;
UINT64 g_ourCertHandle = 0;
static int injectCount = 0;
// connStructAddr declared earlier (forward declaration)
static volatile int crcDumpCount = 0;

// CRC BYPASS via Hardware Breakpoint + Vectored Exception Handler
// This does NOT modify any code pages, so stub.dll guard pages can't detect it.
static volatile DWORD hwBpThreadIds[64] = {0};
static volatile int hwBpThreadCount = 0;
static volatile int pendingDr0Setup = 0;
//
// Target: RVA 0x572827 = "CMP R12D,EAX" (44 3B E0) in FUN_1405725f0
// After this instruction: "SETE AL" (0F 94 C0) at RVA 0x57282A
// We set a HW breakpoint on the SETE instruction and force AL=1 (always pass CRC)
//
// The CMP sets ZF=1 if CRC matches. SETE AL sets AL=1 if ZF=1.
// We skip SETE and just set AL=1, making the CRC always "match".

static int crcPatched = 0;
static void *vehHandle = NULL;
static BYTE *crcBreakpointAddr = NULL;  // Address of SETE AL (0F 94 C0) = base + 0x57282A

static LONG CALLBACK CrcBypassVEH(PEXCEPTION_POINTERS exc) {
    // Handle SINGLE_STEP exceptions (both DR0 setup and CRC bypass)
    if (exc->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP &&
        crcBreakpointAddr != NULL) {

        // Check if this is our TF-triggered setup (RIP is NOT at our target)
        if (pendingDr0Setup && (BYTE*)exc->ContextRecord->Rip != crcBreakpointAddr) {
            exc->ContextRecord->Dr0 = (DWORD64)crcBreakpointAddr;
            exc->ContextRecord->Dr7 = (exc->ContextRecord->Dr7 & ~0xF) | 0x1;
            exc->ContextRecord->Dr7 &= ~(0xF << 16);
            pendingDr0Setup = 0;

            if (hwBpThreadCount < 64) {
                hwBpThreadIds[hwBpThreadCount++] = GetCurrentThreadId();
            }

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // Hardware breakpoint hit at CRC check
        if ((BYTE*)exc->ContextRecord->Rip == crcBreakpointAddr) {
            // We're at "SETE AL" (0F 94 C0, 3 bytes)
            // Force AL = 1 (CRC always valid) and skip the instruction
            exc->ContextRecord->Rax = (exc->ContextRecord->Rax & ~0xFFULL) | 1;
            exc->ContextRecord->Rip += 3;  // skip SETE AL (3 bytes)

            // Re-enable the hardware breakpoint (single-step clears it)
            exc->ContextRecord->Dr0 = (DWORD64)crcBreakpointAddr;
            exc->ContextRecord->Dr7 |= 0x1;  // enable DR0 local

            if (!crcPatched) {
                crcPatched = 1;
                OutputDebugStringA("*** CRC BYPASS VEH: First hit! AL forced to 1 ***");
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void EnsureHwBpOnThisThread(void);  // forward declaration

static void SetHardwareBreakpoint(void) {
    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) return;

    // Point at SETE AL instruction (RVA 0x57282A = 0x572827 + 3)
    crcBreakpointAddr = (BYTE*)hMod + 0x57282A;

    // Verify the target bytes: 0F 94 C0 = SETE AL
    if (crcBreakpointAddr[0] == 0x0F && crcBreakpointAddr[1] == 0x94 && crcBreakpointAddr[2] == 0xC0) {
        OutputDebugStringA("*** CRC target bytes verified: 0F 94 C0 (SETE AL) ***");
    } else {
        char msg[128];
        snprintf(msg, sizeof(msg), "*** CRC target bytes MISMATCH: %02X %02X %02X ***",
            crcBreakpointAddr[0], crcBreakpointAddr[1], crcBreakpointAddr[2]);
        OutputDebugStringA(msg);
        // Still try - bytes may be readable but not match our expectation
    }

    // Register VEH (first handler, priority over SEH)
    vehHandle = AddVectoredExceptionHandler(1, CrcBypassVEH);

    // Set hardware breakpoint on the CURRENT thread via real handle
    EnsureHwBpOnThisThread();

    // Also try all threads
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        Log("CreateToolhelp32Snapshot failed (err=%lu)", GetLastError());
        return;
    }

    DWORD myPid = GetCurrentProcessId();
    DWORD myTid = GetCurrentThreadId();
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    int threadCount = 0;
    int totalThreads = 0;
    int openFails = 0;

    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == myPid && te.th32ThreadID != myTid) {
                totalThreads++;
                HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (hThread) {
                    SuspendThread(hThread);
                    CONTEXT ctx;
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    if (GetThreadContext(hThread, &ctx)) {
                        ctx.Dr0 = (DWORD64)crcBreakpointAddr;
                        ctx.Dr7 = (ctx.Dr7 & ~0xF) | 0x1;
                        ctx.Dr7 &= ~(0xF << 16);
                        SetThreadContext(hThread, &ctx);
                        threadCount++;
                    }
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                } else {
                    openFails++;
                }
            }
            te.dwSize = sizeof(te);
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    Log("HW Breakpoint: %d/%d threads set (OpenThread fails: %d)", threadCount, totalThreads, openFails);
}

static volatile int hwBpInstalled = 0;

// EnsureHwBpOnThisThread: set DR0/DR7 directly via inline assembly
// This bypasses ALL Windows API hooks including stub.dll
// Note: writing DR registers from ring 3 causes #GP, so we use the VEH trick:
// We set the TF (trap flag) bit to trigger SINGLE_STEP exception, then in
// the VEH handler we set DR0/DR7 in the exception context.

static void EnsureHwBpOnThisThread(void) {
    if (!crcBreakpointAddr) return;
    DWORD tid = GetCurrentThreadId();

    // Check if already installed on this thread
    for (int i = 0; i < hwBpThreadCount; i++) {
        if (hwBpThreadIds[i] == tid) return;
    }

    // Set Trap Flag (TF=1) to trigger SINGLE_STEP on next instruction
    // Our VEH will see SINGLE_STEP with RIP != crcBreakpointAddr
    // and check pendingSetup flag to know it should set DR0
    pendingDr0Setup = 1;
    __asm__ volatile (
        "pushfq\n\t"
        "orq $0x100, (%%rsp)\n\t"   // Set TF (bit 8)
        "popfq\n\t"
        "nop\n\t"                    // TF fires after this NOP
        ::: "memory", "cc"
    );
    // After the NOP, SINGLE_STEP fires and our VEH sets DR0
}
// ============================================================
// DIRECT SYSCALL to NtProtectVirtualMemory
// Bypasses ALL user-mode hooks (stub.dll, etc.)
// ============================================================

// Read the syscall number from ntdll's NtProtectVirtualMemory export.
// The function starts with: mov r10,rcx / mov eax,SYSCALL_NUM / ...
static DWORD GetSyscallNumber(const char *funcName) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    BYTE *func = (BYTE*)GetProcAddress(ntdll, funcName);
    if (!func) { Log("Syscall %s: export not found!", funcName); return 0; }

    Log("Syscall %s: func at %p, bytes: %02X %02X %02X %02X %02X %02X %02X %02X",
        funcName, func, func[0], func[1], func[2], func[3], func[4], func[5], func[6], func[7]);

    // Check if the in-memory function is not hooked
    if (func[0] == 0x4C && func[1] == 0x8B && func[2] == 0xD1 && func[3] == 0xB8) {
        DWORD num = *(DWORD*)(func + 4);
        Log("Syscall %s: standard pattern (in-memory), num=0x%X", funcName, num);
        return num;
    }

    // Function is hooked! Read syscall number from ntdll.dll FILE on disk instead.
    Log("Syscall %s: HOOKED (starts with %02X %02X), reading from disk...", funcName, func[0], func[1]);

    // Get the RVA of the function
    BYTE *ntdllBase = (BYTE*)ntdll;
    DWORD funcRVA = (DWORD)(func - ntdllBase);
    Log("Syscall %s: ntdll base=%p, func RVA=0x%X", funcName, ntdllBase, funcRVA);

    // Read the original bytes from ntdll.dll on disk
    char ntdllPath[MAX_PATH];
    GetSystemDirectoryA(ntdllPath, MAX_PATH);
    strcat(ntdllPath, "\\ntdll.dll");

    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        Log("Syscall %s: can't open %s (err=%lu)", funcName, ntdllPath, GetLastError());
        return 0;
    }

    // Parse PE headers to convert RVA to file offset
    BYTE peHeader[4096];
    DWORD bytesRead;
    ReadFile(hFile, peHeader, sizeof(peHeader), &bytesRead, NULL);

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)peHeader;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64*)(peHeader + dos->e_lfanew);
    IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER*)((BYTE*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

    DWORD fileOffset = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (funcRVA >= sections[i].VirtualAddress &&
            funcRVA < sections[i].VirtualAddress + sections[i].Misc.VirtualSize) {
            fileOffset = funcRVA - sections[i].VirtualAddress + sections[i].PointerToRawData;
            break;
        }
    }

    if (fileOffset == 0) {
        Log("Syscall %s: can't find section for RVA 0x%X", funcName, funcRVA);
        CloseHandle(hFile);
        return 0;
    }

    // Read the original (unhooked) function bytes from disk
    BYTE origBytes[16];
    SetFilePointer(hFile, fileOffset, NULL, FILE_BEGIN);
    ReadFile(hFile, origBytes, sizeof(origBytes), &bytesRead, NULL);
    CloseHandle(hFile);

    Log("Syscall %s: disk bytes at offset 0x%X: %02X %02X %02X %02X %02X %02X %02X %02X",
        funcName, fileOffset,
        origBytes[0], origBytes[1], origBytes[2], origBytes[3],
        origBytes[4], origBytes[5], origBytes[6], origBytes[7]);

    // Should be: 4C 8B D1 B8 xx xx xx xx
    if (origBytes[0] == 0x4C && origBytes[1] == 0x8B && origBytes[2] == 0xD1 && origBytes[3] == 0xB8) {
        DWORD num = *(DWORD*)(origBytes + 4);
        Log("Syscall %s: from disk, num=0x%X", funcName, num);
        return num;
    }

    Log("Syscall %s: unexpected disk bytes, pattern not found!", funcName);
    return 0;
}

// Direct syscall for NtProtectVirtualMemory
// Uses dynamically allocated executable shellcode to avoid inline asm issues
// NTSTATUS NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
//     PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
typedef LONG (NTAPI *NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

static NtProtectVirtualMemory_t MakeSyscallStub(DWORD sysnum) {
    // Allocate RWX page for our tiny syscall stub
    BYTE *stub = (BYTE*)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!stub) return NULL;

    int i = 0;
    // mov r10, rcx  (Windows syscall convention)
    stub[i++] = 0x4C; stub[i++] = 0x8B; stub[i++] = 0xD1;
    // mov eax, sysnum
    stub[i++] = 0xB8;
    *(DWORD*)(stub + i) = sysnum; i += 4;
    // syscall
    stub[i++] = 0x0F; stub[i++] = 0x05;
    // ret
    stub[i++] = 0xC3;

    return (NtProtectVirtualMemory_t)stub;
}

static void PatchCrcCheckEarly(void) {
    if (crcPatched || hwBpInstalled) return;
    hwBpInstalled = 1;

    HMODULE hMod = GetModuleHandleA(NULL);
    if (!hMod) return;

    BYTE *target = (BYTE*)hMod + 0x572827;
    if (target[0] != 0x44 || target[1] != 0x3B || target[2] != 0xE0) {
        if (target[0] == 0x90 && target[3] == 0xB0) {
            crcPatched = 1;
            Log("CRC already patched!");
            return;
        }
        Log("CRC target bytes unexpected: %02X %02X %02X %02X %02X %02X",
            target[0], target[1], target[2], target[3], target[4], target[5]);
        return;
    }

    Log("CRC target verified: %02X %02X %02X at %p", target[0], target[1], target[2], target);

    // Method 1: Direct syscall to NtProtectVirtualMemory (bypasses all user-mode hooks)
    DWORD sysnum = GetSyscallNumber("NtProtectVirtualMemory");
    if (sysnum != 0) {
        Log("NtProtectVirtualMemory syscall number: 0x%X", sysnum);

        NtProtectVirtualMemory_t NtProtect = MakeSyscallStub(sysnum);
        if (!NtProtect) {
            Log("Failed to allocate syscall stub!");
            goto try_virtualprotect;
        }

        void *baseAddr = (void*)target;
        SIZE_T regionSize = 6;
        DWORD oldProtect = 0;

        LONG status = NtProtect((HANDLE)-1, &baseAddr, &regionSize,
                                PAGE_EXECUTE_READWRITE, &oldProtect);
        Log("Direct syscall NtProtectVirtualMemory status: 0x%08X (oldProtect=0x%X)", status, oldProtect);

        if (status == 0) {  // STATUS_SUCCESS
            target[0] = 0x90; target[1] = 0x90; target[2] = 0x90;
            target[3] = 0xB0; target[4] = 0x01; target[5] = 0x90;
            DWORD dummy;
            baseAddr = (void*)target;
            regionSize = 6;
            NtProtect((HANDLE)-1, &baseAddr, &regionSize, oldProtect, &dummy);
            VirtualFree((void*)NtProtect, 0, MEM_RELEASE);
            crcPatched = 1;
            Log("*** CRC PATCHED via NtProtectVirtualMemory! ***");
            Log("Bytes now: %02X %02X %02X %02X %02X %02X",
                target[0], target[1], target[2], target[3], target[4], target[5]);
            return;
        }
        Log("NtProtect failed (0x%08X), trying NtWriteVirtualMemory...", status);
        VirtualFree((void*)NtProtect, 0, MEM_RELEASE);

        // Method 1b: NtWriteVirtualMemory (writes to memory directly, different kernel path)
        DWORD writeSysnum = GetSyscallNumber("NtWriteVirtualMemory");
        if (writeSysnum != 0) {
            Log("NtWriteVirtualMemory syscall number: 0x%X", writeSysnum);

            // NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, Size, *Written)
            typedef LONG (NTAPI *NtWriteVM_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
            NtWriteVM_t NtWrite = (NtWriteVM_t)MakeSyscallStub(writeSysnum);
            if (NtWrite) {
                BYTE patch[] = {0x90, 0x90, 0x90, 0xB0, 0x01, 0x90};
                SIZE_T written = 0;
                LONG wStatus = NtWrite((HANDLE)-1, target, patch, 6, &written);
                Log("NtWriteVirtualMemory status: 0x%08X (written=%llu)", wStatus, (unsigned long long)written);

                if (wStatus == 0 && target[0] == 0x90) {
                    VirtualFree((void*)NtWrite, 0, MEM_RELEASE);
                    crcPatched = 1;
                    Log("*** CRC PATCHED via NtWriteVirtualMemory! ***");
                    return;
                }
                VirtualFree((void*)NtWrite, 0, MEM_RELEASE);
            }
        }

        // Method 1c: Try NtProtect with PAGE_READWRITE (less suspicious than RWX)
        {
            NtProtectVirtualMemory_t NtProt2 = MakeSyscallStub(sysnum);
            if (NtProt2) {
                void *ba2 = (void*)target;
                SIZE_T rs2 = 0x1000;  // full page
                DWORD op2 = 0;
                LONG s2 = NtProt2((HANDLE)-1, &ba2, &rs2, PAGE_READWRITE, &op2);
                Log("NtProtect(PAGE_RW, page) status: 0x%08X (old=0x%X)", s2, op2);
                if (s2 == 0) {
                    target[0] = 0x90; target[1] = 0x90; target[2] = 0x90;
                    target[3] = 0xB0; target[4] = 0x01; target[5] = 0x90;
                    DWORD d2;
                    ba2 = (void*)target;
                    rs2 = 0x1000;
                    NtProt2((HANDLE)-1, &ba2, &rs2, op2, &d2);
                    VirtualFree((void*)NtProt2, 0, MEM_RELEASE);
                    crcPatched = 1;
                    Log("*** CRC PATCHED via NtProtect(PAGE_RW)! ***");
                    return;
                }
                VirtualFree((void*)NtProt2, 0, MEM_RELEASE);
            }
        }
    }

    // Method 2: VirtualProtect (may work if stub.dll hasn't hooked it yet)
    try_virtualprotect:
    {
        DWORD oldProtect;
        if (VirtualProtect(target, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            target[0] = 0x90; target[1] = 0x90; target[2] = 0x90;
            target[3] = 0xB0; target[4] = 0x01; target[5] = 0x90;
            VirtualProtect(target, 6, oldProtect, &oldProtect);
            crcPatched = 1;
            Log("CRC PATCHED via VirtualProtect!");
            return;
        }
        Log("VirtualProtect failed (err=%lu)", GetLastError());
    }

    // Method 3: Hardware breakpoints (last resort)
    Log("Falling back to HW breakpoint method...");
    SetHardwareBreakpoint();
}

int WINAPI Hook_sendto(SOCKET s, const char *buf, int len, int flags,
                       const struct sockaddr *to, int tolen) {
    if (to && to->sa_family == AF_INET) {
        Log("SEND socket=%llu len=%d", (unsigned long long)s, len);
        SavePacket("SEND", buf, len, to);
        // Add our cert to TLS trust store on first sendto (TLS engine is initialized by now)
        {
            static int certAdded = 0;
            if (!certAdded) {
                certAdded = 1;
                HMODULE hExe2 = GetModuleHandleA(NULL);
                typedef void (*AddCA_t)(int, void**, int);
                AddCA_t AddCA = (AddCA_t)((BYTE*)hExe2 + 0x168A4F0);
                // Read our cert
                FILE *cf2 = fopen("cert.pem", "r");
                if (cf2) {
                    char pm[4096]={0}; fread(pm,1,4095,cf2); fclose(cf2);
                    static BYTE dr[2048]; int dl=0;
                    static const BYTE b[256]={['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63};
                    char *p=pm; while(*p&&strncmp(p,"-----BEGIN",10)!=0)p++; while(*p&&*p!='\n')p++; if(*p)p++;
                    int bits=0,nb=0;
                    while(*p&&strncmp(p,"-----END",8)!=0){if(*p=='\n'||*p=='\r'||*p==' '||*p=='='){p++;continue;}bits=(bits<<6)|b[(unsigned char)*p];nb+=6;if(nb>=8){nb-=8;dr[dl++]=(BYTE)(bits>>nb);bits&=(1<<nb)-1;}p++;}
                    if (dl > 0) {
                        void *cp2 = dr;
                        Log("  >>> Adding our cert (%dB) to TLS trust store <<<", dl);
                        AddCA(0, &cp2, dl);
                        Log("  >>> CERT ADDED TO TRUST STORE! <<<");
                    }
                }
            }
        }
        // Hook Schannel on first sendto
        if (!real_InitSecCtxW) {
            HMODULE hSec = GetModuleHandleA("secur32.dll");
            if (!hSec) hSec = GetModuleHandleA("sspicli.dll");
            if (hSec) {
                void *pISCW = (void*)GetProcAddress(hSec, "InitializeSecurityContextW");
                if (pISCW) {
                    MakeTrampoline(pISCW, tramp_InitSecCtx);
                    real_InitSecCtxW = (InitSecCtxW_fn)tramp_InitSecCtx;
                    PatchJmp(pISCW, Hook_InitSecCtxW);
                    Log("*** Hooked InitializeSecurityContextW → TLS bypass! ***");
                }
            }
        }
        // Inject our cert into BoringSSL trust store on first sendto
        {
            static int certDone = 0;
            if (!certDone) {
                certDone = 1;
                HMODULE hExe = GetModuleHandleA(NULL);
                // FUN_14168a4f0 parses DER cert and returns a CRYPTO_BUFFER handle
                typedef void* (*ParseCert_t)(void*, void**, int);
                ParseCert_t ParseCert = (ParseCert_t)((BYTE*)hExe + 0x168A4F0);
                // FUN_1401e2190 is std::vector::push_back
                typedef void (*VecPush_t)(void*, void*, void*);
                VecPush_t VecPush = (VecPush_t)((BYTE*)hExe + 0x1E2190);

                FILE *cf = fopen("cert.pem", "r");
                if (cf) {
                    char pm[4096]={0}; fread(pm,1,4095,cf); fclose(cf);
                    static BYTE dr[2048]; int dl=0;
                    static const BYTE b64[256]={['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63};
                    char *p=pm; while(*p&&strncmp(p,"-----BEGIN",10)!=0)p++; while(*p&&*p!='\n')p++; if(*p)p++;
                    int bits=0,nb=0;
                    while(*p&&strncmp(p,"-----END",8)!=0){if(*p=='\n'||*p=='\r'||*p==' '||*p=='='){p++;continue;}bits=(bits<<6)|b64[(unsigned char)*p];nb+=6;if(nb>=8){nb-=8;dr[dl++]=(BYTE)(bits>>nb);bits&=(1<<nb)-1;}p++;}

                    if (dl > 0) {
                        // Allocate a persistent context (heap, not stack)
                        // FUN_1416c9b30 uses param_1 as context (if non-NULL) or &local_48
                        // We need a heap-allocated context so the result persists
                        static UINT64 ourCtx[4] = {0}; // persistent context
                        static UINT64 riotCtx[4] = {0};

                        void *certPtr = dr;
                        void *handle = ParseCert(ourCtx, &certPtr, dl);
                        Log("  CERT: ParseCert(ourCtx) returned handle=%p ctx=[%llX,%llX]",
                            handle, ourCtx[0], ourCtx[1]);

                        if (handle || ourCtx[0]) {
                            // Parse Riot CA too
                            BYTE *riotCA = (BYTE*)hExe + 0x19EEBD0;
                            void *riotPtr = riotCA;
                            void *riotHandle = ParseCert(riotCtx, &riotPtr, 1060);
                            Log("  CERT: Riot CA handle=%p ctx=[%llX,%llX]",
                                riotHandle, riotCtx[0], riotCtx[1]);

                            Log("  CERT: ourHandle=%p riotHandle=%p", (void*)ourCtx[0], (void*)riotCtx[0]);

                            // Examine CRYPTO_BUFFER structure of our handle
                            UINT64 *ourCB = (UINT64*)ourCtx[0];
                            if (ourCB) {
                                Log("  CERT: ourCB struct: [%p, %llu, %p, %llu, %p, %p]",
                                    (void*)ourCB[0], ourCB[1], (void*)ourCB[2], ourCB[3],
                                    (void*)ourCB[4], (void*)ourCB[5]);
                                // Capture vtable for background scan
                                g_x509Vtable = ourCB[4];
                                g_ourCertHandle = ourCtx[0];
                                Log("  CERT: vtable=0x%llX handle=%p saved for thread", g_x509Vtable, (void*)g_ourCertHandle);
                                // Check if ourCB[0] points to our DER data
                                if ((void*)ourCB[0] != NULL && ourCB[1] > 0 && ourCB[1] < 4096) {
                                    BYTE *derCheck = (BYTE*)ourCB[0];
                                    if (derCheck[0] == 0x30 && derCheck[1] == 0x82) {
                                        Log("  CERT: ourCB.data=%p len=%llu → DER valid (30 82)!", (void*)ourCB[0], ourCB[1]);
                                    }
                                }
                            }

                            // Scan heap for a pointer to Riot CA DER in .rdata
                            // The original CRYPTO_BUFFER has data_ptr = riotCA (.rdata address)
                            BYTE *riotCAaddr = (BYTE*)hExe + 0x19EEBD0;
                            UINT64 target = (UINT64)riotCAaddr;
                            Log("  CERT: Handles ready. Background thread will do heap scan.");
                            // Heap scan moved to CertInjectionThread (background)
                            if (0) { // DISABLED in sendto - too slow
                            Log("  CERT: Scanning heap for ptr to Riot CA DER at %p...", riotCAaddr);

                            MEMORY_BASIC_INFORMATION mbi;
                            int hits = 0;
                            void *foundCB = NULL;

                            // Search heap for DER byte PATTERN (not pointer)
                            // BoringSSL copies DER bytes to heap
                            BYTE *scan = NULL;

                            while (VirtualQuery(scan, &mbi, sizeof(mbi)) && hits < 3) {
                                if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE) && mbi.RegionSize >= 1060) {
                                    BYTE *base = (BYTE*)mbi.BaseAddress;
                                    SIZE_T size = mbi.RegionSize;
                                    // Skip binary image
                                    if (base > (BYTE*)hExe && base < (BYTE*)hExe + 0x20000000) {
                                        scan = base + mbi.RegionSize; continue;
                                    }
                                    for (SIZE_T j = 0; j + 1060 <= size && hits < 3; j += 4) {
                                        // Match first 8 bytes of Riot CA DER
                                        if (*(UINT64*)(base + j) == *(UINT64*)riotCAaddr &&
                                            memcmp(base + j, riotCAaddr, 64) == 0) {
                                            hits++;
                                            foundCB = base + j;
                                            Log("  CERT: Riot CA DER copy at heap %p (hit #%d)", foundCB, hits);
                                        }
                                    } // close if (!(base in image))
                                }
                                scan = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
                            }

                            if (foundCB) {
                                // foundCB points to the CRYPTO_BUFFER for Riot CA
                                // Now search for a pointer TO this CRYPTO_BUFFER (the vector entry)
                                UINT64 cbAddr = (UINT64)foundCB;
                                // But the vector might point to a wrapper object, not directly to the CB
                                // Let's first check: search for pointer to foundCB in heap
                                // Search for a pointer TO foundCB (the CRYPTO_BUFFER.data field)
                                UINT64 cbDataAddr = (UINT64)foundCB;
                                Log("  CERT: Searching for CRYPTO_BUFFER with data=%p...", foundCB);
                                scan = NULL;
                                int vecHits = 0;
                                void *cbObj = NULL;
                                while (VirtualQuery(scan, &mbi, sizeof(mbi)) && vecHits < 5) {
                                    if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE) && mbi.RegionSize >= 64) {
                                        BYTE *base = (BYTE*)mbi.BaseAddress;
                                        SIZE_T size = mbi.RegionSize;
                                        if (base > (BYTE*)hExe && base < (BYTE*)hExe + 0x20000000) {
                                            scan = base + mbi.RegionSize; continue;
                                        }
                                        for (SIZE_T j = 0; j + 32 <= size && vecHits < 5; j += 8) {
                                            // CRYPTO_BUFFER: {data_ptr, len, pool_ptr, refcount}
                                            // Check: data_ptr == foundCB AND len == 1060
                                            if (*(UINT64*)(base+j) == cbDataAddr) {
                                                UINT64 len = *(UINT64*)(base+j+8);
                                                if (len == 1060) {
                                                    vecHits++;
                                                    cbObj = base + j;
                                                    Log("  CERT: CRYPTO_BUFFER at %p: data=%p len=%llu",
                                                        cbObj, foundCB, len);
                                                    // Now search for pointer to THIS cbObj (in the trust vector)
                                                    UINT64 cbObjAddr = (UINT64)cbObj;
                                                    BYTE *scan2 = NULL;
                                                    int tvHits = 0;
                                                    MEMORY_BASIC_INFORMATION mbi2;
                                                    while (VirtualQuery(scan2, &mbi2, sizeof(mbi2)) && tvHits < 3) {
                                                        if (mbi2.State == MEM_COMMIT && (mbi2.Protect & PAGE_READWRITE) && mbi2.RegionSize >= 64) {
                                                            BYTE *b2 = (BYTE*)mbi2.BaseAddress;
                                                            SIZE_T s2 = mbi2.RegionSize;
                                                            if (b2 > (BYTE*)hExe && b2 < (BYTE*)hExe + 0x20000000) {
                                                                scan2 = b2 + s2; continue;
                                                            }
                                                            for (SIZE_T k = 0; k + 8 <= s2 && tvHits < 3; k += 8) {
                                                                if (*(UINT64*)(b2+k) == cbObjAddr) {
                                                                    tvHits++;
                                                                    Log("  CERT: TRUST VECTOR ENTRY at %p → cbObj %p",
                                                                        b2+k, cbObj);
                                                                    // The vector struct is 24B before the first entry
                                                                    // Or: search for begin_ptr pointing near this
                                                                }
                                                            }
                                                        }
                                                        scan2 = (BYTE*)mbi2.BaseAddress + mbi2.RegionSize;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    scan = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
                                }
                                if (!vecHits) Log("  CERT: No CRYPTO_BUFFER found");
                            } else {
                                Log("  CERT: No CRYPTO_BUFFER found with Riot CA data ptr");
                            }
                            } // end if(0) DISABLED
                        }
                    }
                }
            }
        }
        // Patch CRC check on first sendto (game is already initialized by now)
        if (!crcPatched && !hwBpInstalled) {
            Log("About to call PatchCrcCheckEarly...");
            PatchCrcCheckEarly();
            Log("PatchCrcCheckEarly returned OK");
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

        // Save EVERY sendto for echo (capture latest packet of each size)
        if (len > 0 && len <= 1024) {
            memcpy(lastSendBuf, buf, len);
            lastSendLen = len;
        }
        // Capture connection token from first 519B packet (bytes 8-11)
        if (len == 519 && g_connToken == 0) {
            g_connToken = *(UINT32*)(buf + 8);
            Log("CONN_TOKEN captured: 0x%08X", g_connToken);
        }
        // Decrypt client packets using GAME's own BF context (not ours)
        if (len > 27) {
            static int clientDecLog = 0;
            if (clientDecLog < 15) {
                HMODULE gBase = GetModuleHandleA(NULL);
                void *bfCtxSend = NULL;
                if (connStructAddr && !IsBadReadPtr((void*)(connStructAddr + 0x120), 16)) {
                    BYTE *cb = (BYTE*)connStructAddr + 0x120;
                    if (cb[0] != 0) {
                        void **tp = (void**)(cb + 8);
                        if (!IsBadReadPtr(tp, 8) && *tp) {
                            BYTE *rn = (BYTE*)(*(void**)(*tp));
                            if (!IsBadReadPtr(rn, 0x30) && *(UINT64*)(rn+0x20)==1)
                                bfCtxSend = *(void**)(rn + 0x28);
                        }
                    }
                }

                int encLen = len - 8;
                if (encLen > 0 && encLen < 1024 && bfCtxSend && gBase) {
                    clientDecLog++;
                    BYTE *dec = (BYTE*)_alloca(encLen);
                    memcpy(dec, buf + 8, encLen);

                    // Use GAME's BF decrypt function
                    typedef void (*bf_cfb_t)(void*, BYTE*, UINT64, int);
                    bf_cfb_t BfDec = (bf_cfb_t)((BYTE*)gBase + 0x10F2A10);
                    BfDec(bfCtxSend, dec, (UINT64)encLen, 2); // pass 1
                    ReverseBytes(dec, encLen);
                    BfDec(bfCtxSend, dec, (UINT64)encLen, 2); // pass 2

                    BYTE flags = (encLen >= 7) ? dec[6] : 0;
                    char hexdump[200] = {0};
                    int hoff = 0;
                    for (int i = 0; i < encLen && i < 32 && hoff < 180; i++)
                        hoff += snprintf(hexdump + hoff, sizeof(hexdump) - hoff, "%02X ", dec[i]);
                    // Log conn offsets that control cursor behavior
                    UINT16 c144 = 0, c146 = 0;
                    if (connStructAddr && !IsBadReadPtr((void*)(connStructAddr+0x144), 4)) {
                        c144 = *(UINT16*)(connStructAddr + 0x144);
                        c146 = *(UINT16*)(connStructAddr + 0x146);
                    }
                    Log("CLIENT_GAMEDEC #%d: %dB c144=%d c146=%d flags=0x%02X(cmd=%d) %s",
                        clientDecLog, len, c144, c146, flags, flags & 0x7F, hexdump);
                }
            }
        }
        // Log 36B packets (potential KeyCheck from client)
        if (len == 36) {
            static int kc36count = 0;
            kc36count++;
            if (kc36count <= 5) {
                Log("  CLIENT KC 36B #%d raw: %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X",
                    kc36count,
                    (BYTE)buf[12], (BYTE)buf[13], (BYTE)buf[14], (BYTE)buf[15],
                    (BYTE)buf[16], (BYTE)buf[17], (BYTE)buf[18], (BYTE)buf[19],
                    (BYTE)buf[20], (BYTE)buf[21], (BYTE)buf[22], (BYTE)buf[23],
                    (BYTE)buf[24], (BYTE)buf[25], (BYTE)buf[26], (BYTE)buf[27],
                    (BYTE)buf[28], (BYTE)buf[29], (BYTE)buf[30], (BYTE)buf[31],
                    (BYTE)buf[32], (BYTE)buf[33], (BYTE)buf[34], (BYTE)buf[35]);
            }
        }
        // Capture RBX register - should be param_1 (connection struct)
        if (len == 519 && pktCount <= 3) {
            register void* rbx_val asm("rbx");
            if (!connStructAddr) {
                connStructAddr = (BYTE*)rbx_val;
                Log("  CONN STRUCT captured: %p", connStructAddr);
            }
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
    // Ensure HW breakpoint on this thread (recv thread handles CRC check)
    if (hwBpInstalled && !crcPatched) {
        EnsureHwBpOnThisThread();
    }
    int r = real_recvfrom(s, buf, len, flags, from, fromlen);
    if (r > 0 && from && from->sa_family == AF_INET) {
        struct sockaddr_in *sinCheck = (struct sockaddr_in*)from;
        if (ntohl(sinCheck->sin_addr.s_addr) == 0x7F000001)
            Log("RECV socket=%llu len=%d bufsize=%d", (unsigned long long)s, r, len);
        struct sockaddr_in *sin = (struct sockaddr_in*)from;
        int isLocalhost = (ntohl(sin->sin_addr.s_addr) == 0x7F000001); // 127.0.0.1

        // SMART HYBRID: echo small packets (pings), CRC-fix large ones (game data)
        // During handshake: echo everything. After handshake: echo only pings.
        if (isLocalhost && lastSendLen > 8) {
            static int totalRecv = 0;
            static int echoCount = 0;
            static int fixupCount = 0;
            static int handshakeDone = 0;
            totalRecv++;

            // Handshake phase: echo everything for first 30 packets
            if (!handshakeDone && echoCount < 30) {
                int echoLen = lastSendLen - 8;
                if (echoLen > 0 && echoLen <= len) {
                    memcpy(buf, lastSendBuf + 8, echoLen);
                    r = echoLen;
                    echoCount++;
                    if (echoCount <= 5)
                        Log("ECHO #%d: %dB (handshake)", echoCount, r);
                    if (echoCount >= 30) {
                        handshakeDone = 1;
                        Log("=== HANDSHAKE DONE after %d echoes, entering smart mode ===", echoCount);
                    }
                }
            }
            // After handshake: check for CAFE magic (CRC-format packet from server)
            else if (handshakeDone) {
                static int postHsLog = 0;
                if (postHsLog < 30) {
                    postHsLog++;
                    Log("POST_HS #%d: recv %dB first2=%02X%02X", postHsLog, r,
                        r >= 1 ? (BYTE)buf[0] : 0, r >= 2 ? (BYTE)buf[1] : 0);
                }
                if (r >= 4 && (BYTE)buf[0] == 0xCA && (BYTE)buf[1] == 0xFE) {
                    // Server packet: [2B CAFE][4B header][encrypted: [4B nonce][1B flags][body]]
                    // Strip CAFE, replace header with connection token, fix CRC
                    int totalLen = r - 2; // after CAFE strip
                    BYTE *pkt = (BYTE*)_alloca(totalLen);
                    memcpy(pkt, buf + 2, totalLen);
                    // Replace header with connection token (what echo uses)
                    if (g_connToken != 0)
                        *(UINT32*)(pkt) = g_connToken;
                    // pkt[0..3] = connection token (matches echo format)
                    // pkt[4+]  = encrypted data

                    int encLen = totalLen - 4;
                    if (encLen < 5) { goto cafe_done; } // need nonce(4)+flags(1)

                    // Server now sends PLAINTEXT (not encrypted) — no decrypt needed
                    BYTE *encPart = pkt + 4;
                    // encPart[0..3]=nonce, encPart[4]=flags, encPart[5+]=body

                    // Find game's BF context
                    HMODULE gameBase = GetModuleHandleA(NULL);
                    void *bfCtx = NULL;
                    if (connStructAddr && !IsBadReadPtr((void*)(connStructAddr + 0x120), 16)) {
                        BYTE *cb = (BYTE*)connStructAddr + 0x120;
                        if (cb[0] != 0) {
                            void **tp = (void**)(cb + 8);
                            if (!IsBadReadPtr(tp, 8) && *tp) {
                                BYTE *rn = (BYTE*)(*(void**)(*tp));
                                if (!IsBadReadPtr(rn, 0x30) && *(UINT64*)(rn+0x20)==1)
                                    bfCtx = *(void**)(rn + 0x28);
                            }
                        }
                    }

                    if (bfCtx && gameBase) {
                        // Build CRC struct: peerID from header bytes 0-1
                        BYTE crcStruct[0x60];
                        memset(crcStruct, 0, sizeof(crcStruct));
                        UINT64 lc8 = 1;
                        if (connStructAddr && !IsBadReadPtr((void*)(connStructAddr + 0x138), 8))
                            lc8 = *(UINT64*)(connStructAddr + 0x138);
                        *(UINT64*)(crcStruct + 0x00) = lc8;
                        crcStruct[0x08] = pkt[0]; // peerID low from header
                        crcStruct[0x09] = pkt[1]; // peerID high from header
                        *(UINT64*)(crcStruct + 0x18) = 0xFFFFFFFFFFFFFFFF;
                        int payloadLen = (encLen > 5) ? (encLen - 5) : 0;
                        *(UINT64*)(crcStruct + 0x48) = (UINT64)(encPart + 5);
                        *(UINT16*)(crcStruct + 0x52) = (UINT16)payloadLen;

                        typedef int (__fastcall *crc_fn_t)(BYTE*);
                        crc_fn_t CrcFn = (crc_fn_t)((BYTE*)gameBase + 0x577F10);
                        int nonce = CrcFn(crcStruct);
                        *(int*)(encPart + 0) = nonce; // patch nonce in plaintext

                        fixupCount++;
                        if (fixupCount <= 20)
                            Log("CRC_FIXUP #%d: total=%dB enc=%dB nonce=0x%08X flags=0x%02X",
                                fixupCount, totalLen, encLen, (UINT32)nonce, encPart[4]);

                        // Encrypt with GAME's BF
                        typedef void (*bf_cfb_t)(void*, BYTE*, UINT64, int);
                        bf_cfb_t BfEnc = (bf_cfb_t)((BYTE*)gameBase + 0x10F41E0);
                        BfEnc(bfCtx, encPart, (UINT64)encLen, 2); // pass 1
                        ReverseBytes(encPart, encLen);
                        BfEnc(bfCtx, encPart, (UINT64)encLen, 2); // pass 2

                        // VERIFY after encrypt: decrypt and check CRC matches
                        if (fixupCount <= 5) {
                            BYTE *verify = (BYTE*)_alloca(encLen);
                            memcpy(verify, encPart, encLen); // copy CIPHERTEXT
                            typedef void (*bf_cfb_dec_t)(void*, BYTE*, UINT64, int);
                            bf_cfb_dec_t BfDec2 = (bf_cfb_dec_t)((BYTE*)gameBase + 0x10F2A10);
                            BfDec2(bfCtx, verify, (UINT64)encLen, 2);
                            ReverseBytes(verify, encLen);
                            BfDec2(bfCtx, verify, (UINT64)encLen, 2);
                            int storedNonce = *(int*)(verify + 0);
                            int match = (storedNonce == nonce);
                            Log("  VERIFY: dec_nonce=0x%08X orig_nonce=0x%08X flags=0x%02X %s",
                                (UINT32)storedNonce, (UINT32)nonce, verify[4],
                                match ? "CRC PASS!" : "CRC MISMATCH!");
                        }

                        // Return: [4B header][re-encrypted]
                        memcpy(buf, pkt, totalLen);
                        r = totalLen;
                    }
                    cafe_done:
                    (void)0;
                } else {
                    // Normal server response = echo back for keep-alive
                    int echoLen = lastSendLen - 8;
                    if (echoLen > 0 && echoLen <= len) {
                        memcpy(buf, lastSendBuf + 8, echoLen);
                        r = echoLen;
                        echoCount++;
                    }
                }
            }
        }

        if (isLocalhost) {
            // Dump CRC struct fields on first few packets
            if (connStructAddr && crcDumpCount < 20 && !IsBadReadPtr((void*)connStructAddr, 0x170)) {
                crcDumpCount++;
                BYTE *cs = (BYTE*)connStructAddr;
                // Offsets from FUN_140577f10 Ghidra analysis:
                // +0x8: peerID (2 bytes)
                // +0x18: local_res10 (8 bytes)
                // +0x48: pointer to payload
                // +0x52: payload length (2 bytes)
                BYTE peerID_lo = cs[0x8];
                BYTE peerID_hi = cs[0x9];
                UINT64 local_res10 = *(UINT64*)(cs + 0x18);
                UINT64 payloadPtr = *(UINT64*)(cs + 0x48);
                USHORT payloadLen = *(USHORT*)(cs + 0x52);
                Log("  CRC_STRUCT #%d: peerID=%02X%02X local_res10=%016llX payloadPtr=%p payloadLen=%u",
                    crcDumpCount, peerID_hi, peerID_lo,
                    (unsigned long long)local_res10, (void*)payloadPtr, payloadLen);

                // Dump first 16 bytes of payload if available
                if (payloadPtr && payloadLen > 0 && !IsBadReadPtr((void*)payloadPtr, payloadLen < 16 ? payloadLen : 16)) {
                    BYTE *pl = (BYTE*)payloadPtr;
                    int dumpLen = payloadLen < 16 ? payloadLen : 16;
                    char hexBuf[128];
                    int off = 0;
                    for (int i = 0; i < dumpLen; i++)
                        off += snprintf(hexBuf + off, sizeof(hexBuf) - off, "%02X ", pl[i]);
                    Log("  CRC_PAYLOAD[0:%d]: %s", dumpLen, hexBuf);
                }

                // Key offsets from FUN_140588f70 Ghidra analysis:
                // param_1 + 0x138 → lVar10 → local_c8 (offset 0x00 of CRC struct)
                // param_1 + 0x144 → used for local_e8[0]
                // param_1 + 0x146 → uVar1
                UINT64 offset_138 = *(UINT64*)(cs + 0x138);
                USHORT offset_144 = *(USHORT*)(cs + 0x144);
                USHORT offset_146 = *(USHORT*)(cs + 0x146);
                Log("  CONN[0x138]=%016llX CONN[0x144]=%04X CONN[0x146]=%04X",
                    (unsigned long long)offset_138, offset_144, offset_146);
            }

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

            // Find host struct by scanning stack for object with *(ptr+0x38)==socket
            if (!recvHostStruct) {
                BYTE *stk;
                __asm__ volatile("movq %%rsp, %0" : "=r"(stk));
                for (int soff = 0; soff < 0x2000; soff += 8) {
                    BYTE *c = *(BYTE**)(stk + soff);
                    if (c && !IsBadReadPtr(c, 0x180) && !IsBadReadPtr(c + 0x38, 8)) {
                        if (*(UINT64*)(c + 0x38) == (UINT64)s && c[0x50] <= 2) {
                            recvHostStruct = c;
                            Log("  HOST FOUND: %p (stack+0x%X)", c, soff);
                            break;
                        }
                    }
                }
            }

            // Log consumer dispatch function (once)
            static int consumerLogged = 0;
            if (recvHostStruct && !consumerLogged) {
                consumerLogged = 1;
                BYTE *host = (BYTE*)recvHostStruct;
                void *plVar15 = *(void**)(host + 0x20);
                if (plVar15 && !IsBadReadPtr((BYTE*)plVar15 + 0x168, 8)) {
                    HMODULE gb = GetModuleHandleA(NULL);
                    // Scan offsets 0x100-0x180 for non-null pointers in image range
                    UINT64 imgBase = (UINT64)gb;
                    Log("  CONSUMER SCAN (plVar15=%p, imgBase=0x%llX):", plVar15, imgBase);
                    for (int off = 0x100; off <= 0x180; off += 8) {
                        void *val = *(void**)((BYTE*)plVar15 + off);
                        if (val != NULL) {
                            UINT64 v = (UINT64)val;
                            int inImg = (v > imgBase && v < imgBase + 0x20000000);
                            Log("    +0x%03X = %p %s", off, val, inImg ? "(IN IMAGE)" : "");
                        }
                    }
                    // Read vtable entries at +0x120 and +0x128
                    void *h120 = *(void**)((BYTE*)plVar15 + 0x120);
                    void *h128 = *(void**)((BYTE*)plVar15 + 0x128);
                    if (h120 && !IsBadReadPtr((BYTE*)h120 + 0x10, 8)) {
                        void *fn10_120 = *(void**)((BYTE*)h120 + 0x10);
                        Log("    +0x120 vtable: fn[2]+0x10=%p (RVA 0x%llX)", fn10_120, (UINT64)fn10_120 - imgBase);
                    }
                    if (h128 && !IsBadReadPtr((BYTE*)h128 + 0x10, 8)) {
                        void *fn10_128 = *(void**)((BYTE*)h128 + 0x10);
                        Log("    +0x128 vtable: fn[2]+0x10=%p (RVA 0x%llX) %s",
                            fn10_128, (UINT64)fn10_128 - imgBase,
                            ((UINT64)fn10_128 - imgBase) == 0x1D52B0 ? "← STUB!" : "← REAL?");
                    }
                }
            }

            // Periodic check: has the consumer dispatch changed from stub?
            {
                static int vtCheckCount = 0;
                vtCheckCount++;
                if (recvHostStruct && (vtCheckCount == 30 || vtCheckCount == 60 || vtCheckCount == 100)) {
                    BYTE *h2 = (BYTE*)recvHostStruct;
                    void *pv2 = *(void**)(h2 + 0x20);
                    if (pv2 && !IsBadReadPtr((BYTE*)pv2 + 0x128, 8)) {
                        void *vh = *(void**)((BYTE*)pv2 + 0x128);
                        HMODULE gb2 = GetModuleHandleA(NULL);
                        if (vh && !IsBadReadPtr((BYTE*)vh + 0x10, 8)) {
                            void *fn = *(void**)((BYTE*)vh + 0x10);
                            Log("  VT-CHECK #%d: +0x128 fn[2]=%p (RVA 0x%llX) %s",
                                vtCheckCount, fn, (UINT64)fn - (UINT64)gb2,
                                ((UINT64)fn - (UINT64)gb2) == 0x1D52B0 ? "STUB" : "CHANGED!");
                        }
                    }
                }
            }

            // Echo + KeyCheck injection
            if (lastSendLen > 8) {
                static int eCount = 0;
                static int kcSent = 0;
                eCount++;

                static int rawKcDone = 0;
                static int directDone = 0;
                if (0 && eCount == 80 && recvHostStruct && !directDone) { // DISABLED: causes crash
                    BYTE *hst = (BYTE*)recvHostStruct;
                    void *pv = *(void**)(hst + 0x20);
                    if (pv && !IsBadReadPtr((BYTE*)pv + 0x160, 8)) {
                        BYTE *vt160 = *(BYTE**)((BYTE*)pv + 0x160);
                        if (vt160 && !IsBadReadPtr(vt160 + 0x10, 8)) {
                            typedef void (*dfn_t)(void*, void*);
                            dfn_t fn = *(dfn_t*)(vt160 + 0x10);
                            HMODULE gb = GetModuleHandleA(NULL);
                            UINT64 fnRva = (UINT64)fn - (UINT64)gb;
                            Log("  DIRECT: fn RVA=0x%llX (expect 0x57DCE0)", fnRva);
                            if (fnRva == 0x57DCE0) {
                                directDone = 1;
                                BYTE kc[16] = {0}; kc[0] = 0x64;
                                // param_2 = pointer to key for std::map insert
                                // The key is likely connection_id (0 or 1), not data pointer
                                UINT64 mapKey = 0;  // try key=0
                                // Check +0x128 BEFORE call
                                BYTE *vt128_pre = *(BYTE**)((BYTE*)pv + 0x128);
                                void *fn128_pre = vt128_pre ? *(void**)(vt128_pre + 0x10) : NULL;

                                Log("  >>> CALLING (key=%llu) pre:+0x128 fn[2]=RVA 0x%llX <<<",
                                    mapKey, fn128_pre ? (UINT64)fn128_pre - (UINT64)gb : 0);
                                fn(pv, &mapKey);

                                // Check +0x128 AFTER call
                                BYTE *vt128_post = *(BYTE**)((BYTE*)pv + 0x128);
                                void *fn128_post = vt128_post ? *(void**)(vt128_post + 0x10) : NULL;
                                Log("  >>> RETURNED! post:+0x128 fn[2]=RVA 0x%llX %s <<<",
                                    fn128_post ? (UINT64)fn128_post - (UINT64)gb : 0,
                                    fn128_pre == fn128_post ? "UNCHANGED" : "*** CHANGED! ***");
                            }
                        }
                    }
                }
                if (1) { // ALWAYS echo
                    // Echo mode: return client's own data
                    int echoLen = lastSendLen - 8;
                    if (echoLen > 0 && echoLen <= len) {
                        memcpy(buf, lastSendBuf + 8, echoLen);
                        r = echoLen;
                        if (eCount <= 30)
                            Log("  ECHO #%d: %dB", eCount, r);
                    }
                } else if (kcSent < 10) {
                    // KeyCheck injection - try RAW (no CRC encryption, just game data)
                    // The client's 36B shows opcode 0x64 at byte 12 = plaintext!
                    HMODULE gameBase = GetModuleHandleA(NULL);
                    typedef void (*bf_cfb_enc_t)(void* ctx, BYTE* data, USHORT len, int mode);
                    typedef int (*crc_fn_t)(BYTE *param);
                    bf_cfb_enc_t BfCfbEnc = (bf_cfb_enc_t)((BYTE*)gameBase + 0x10F41E0);
                    bf_cfb_enc_t BfCfbDec = (bf_cfb_enc_t)((BYTE*)gameBase + 0x10F2A10);
                    crc_fn_t CrcFn = (crc_fn_t)((BYTE*)gameBase + 0x577f10);
                    // BF block functions: 0x10F25C0 = reverse P-box (decrypt), 0x10F3D90 = forward (encrypt)
                    typedef void (*bf_enc_block_t)(void* ctx, BYTE* data);
                    bf_enc_block_t BfEncFwd = (bf_enc_block_t)((BYTE*)gameBase + 0x10F3D90); // forward = encrypt
                    bf_enc_block_t BfEncRev = (bf_enc_block_t)((BYTE*)gameBase + 0x10F25C0); // reverse = decrypt

                    // Find BF context
                    void *bfCtx = NULL;
                    if (connStructAddr && !IsBadReadPtr((void*)(connStructAddr + 0x120), 16)) {
                        BYTE *cryptoBase = (BYTE*)connStructAddr + 0x120;
                        if (cryptoBase[0] != 0) {
                            void **treePtr = (void**)(cryptoBase + 8);
                            if (!IsBadReadPtr(treePtr, 8) && *treePtr) {
                                BYTE *rootNode = (BYTE*)(*(void**)(*treePtr));
                                if (!IsBadReadPtr(rootNode, 0x30) && *(UINT64*)(rootNode + 0x20) == 1)
                                    bfCtx = *(void**)(rootNode + 0x28);
                            }
                        }
                    }

                    if (bfCtx) {
                        kcSent++;

                        // Build KeyCheck game data (16 bytes):
                        // [4B opcode=0x64 LE][1B playerNo=0][3B pad][8B checkId]
                        BYTE keycheck[16];
                        memset(keycheck, 0, 16);
                        keycheck[0] = 0x64; // opcode 100 LE
                        // checkId = BF_encrypt(playerNo as 8 bytes)
                        // For playerNo=0: BF_encrypt(zeros)
                        // Try BOTH BF directions for checkId
                        BYTE checkFwd[8] = {0,0,0,0,0,0,0,0};
                        BYTE checkRev[8] = {0,0,0,0,0,0,0,0};
                        BfEncFwd(bfCtx, checkFwd);
                        BfEncRev(bfCtx, checkRev);
                        // Use forward (standard encrypt) for odd, reverse for even
                        BYTE *checkBlock = (kcSent % 2 == 1) ? checkFwd : checkRev;
                        memcpy(keycheck + 8, checkBlock, 8);

                        // Build CRC layer: [2B peerID=0][4B nonce][1B flags=6][16B keycheck]
                        // First compute CRC nonce including payload
                        BYTE crcBuf[0x60];
                        memset(crcBuf, 0, sizeof(crcBuf));
                        *(UINT64*)(crcBuf + 0x00) = 1; // conn seq
                        *(UINT64*)(crcBuf + 0x18) = 0xFFFFFFFFFFFFFFFF;
                        // payload = keycheck data
                        static BYTE payBuf[32];
                        memcpy(payBuf, keycheck, 16);
                        *(UINT64*)(crcBuf + 0x48) = (UINT64)payBuf;
                        *(UINT16*)(crcBuf + 0x52) = 16;

                        int crcNonce = CrcFn(crcBuf);

                        // Plaintext: [2B peerID][4B nonce][1B flags][16B keycheck] = 23B
                        BYTE pt[23];
                        memset(pt, 0, 23);
                        *(UINT32*)(pt + 2) = (UINT32)crcNonce;
                        pt[6] = 0x06; // SEND_RELIABLE (cmd=6)
                        memcpy(pt + 7, keycheck, 16);

                        // Double CFB encrypt using client's function
                        BYTE enc[23];
                        memcpy(enc, pt, 23);
                        BfCfbEnc(bfCtx, enc, 23, 2);
                        for (int i = 0; i < 11; i++) {
                            BYTE t = enc[i]; enc[i] = enc[22-i]; enc[22-i] = t;
                        }
                        BfCfbEnc(bfCtx, enc, 23, 2);

                        // Inject: 4B preamble + 23B encrypted = 27B
                        memset(buf, 0, 27);
                        memcpy(buf + 4, enc, 23);
                        r = 27;
                        Log("  KC #%d: %s 27B nonce=0x%08X fwd=%02X%02X%02X%02X%02X%02X%02X%02X rev=%02X%02X%02X%02X%02X%02X%02X%02X",
                            kcSent, (kcSent%2==1)?"FWD":"REV", (UINT32)crcNonce,
                            checkFwd[0],checkFwd[1],checkFwd[2],checkFwd[3],checkFwd[4],checkFwd[5],checkFwd[6],checkFwd[7],
                            checkRev[0],checkRev[1],checkRev[2],checkRev[3],checkRev[4],checkRev[5],checkRev[6],checkRev[7]);
                    } else {
                        // Fallback to echo
                        int echoLen = lastSendLen - 8;
                        if (echoLen > 0 && echoLen <= len) {
                            memcpy(buf, lastSendBuf + 8, echoLen);
                            r = echoLen;
                        }
                    }
                } else if (rawKcDone < 10) {
                    // Phase 3: Call consumer dispatch DIRECTLY (bypass CRC/encryption)
                    // The consumer calls: (**(code**)(*plVar3 + 0x10))(plVar3, &data, &flag1, &flag2, &flag3, &flag4)
                    // plVar3 = *(plVar15 + 0x128)
                    rawKcDone++;
                    if (recvHostStruct) {
                        BYTE *host = (BYTE*)recvHostStruct;
                        void *plVar15 = *(void**)(host + 0x20);
                        if (plVar15 && !IsBadReadPtr((BYTE*)plVar15 + 0x128, 8)) {
                            void *plVar3 = *(void**)((BYTE*)plVar15 + 0x128);
                            if (plVar3 && !IsBadReadPtr(plVar3, 8)) {
                                void *vt = *(void**)plVar3;
                                if (vt && !IsBadReadPtr((BYTE*)vt + 0x10, 8)) {
                                    typedef void (*dispatch_fn_t)(void*, void*, void*, void*, void*, void*);
                                    dispatch_fn_t dispatchFn = *(dispatch_fn_t*)((BYTE*)vt + 0x10);

                                    // Build KeyCheck as game data
                                    BYTE kcData[16] = {0};
                                    kcData[0] = 0x64; // opcode 100 LE
                                    // checkId at offset 8
                                    HMODULE gb3 = GetModuleHandleA(NULL);
                                    typedef void (*bfe_t)(void*, BYTE*);
                                    bfe_t BfE = (bfe_t)((BYTE*)gb3 + 0x10F3D90);
                                    void *bfc = NULL;
                                    BYTE *cb = (BYTE*)((BYTE*)recvHostStruct + 0x120 + 8);
                                    if (!IsBadReadPtr(cb, 8) && *(void**)cb) {
                                        BYTE *rn = (BYTE*)(*(void**)(*(void**)cb));
                                        if (!IsBadReadPtr(rn, 0x30) && *(UINT64*)(rn+0x20)==1)
                                            bfc = *(void**)(rn+0x28);
                                    }
                                    if (bfc) {
                                        BYTE ck[8] = {0};
                                        BfE(bfc, ck);
                                        memcpy(kcData + 8, ck, 8);
                                    }

                                    // Call dispatch directly
                                    UINT64 packetData = (UINT64)kcData;
                                    BYTE flag1 = 0; // local_res20 = (local_60 == 0) = false (our slot[0]=1)
                                    BYTE flag2 = 0; // local_res18 = local_50
                                    BYTE flag3 = 0; // local_res10 = uStack_4f
                                    BYTE flag4 = 0; // local_res8 = local_4e

                                    Log("  DIRECT-KC #%d: calling dispatch at %p with KC data", rawKcDone, dispatchFn);
                                    dispatchFn(plVar3, &packetData, &flag1, &flag2, &flag3, &flag4);
                                    Log("  DIRECT-KC #%d: returned OK", rawKcDone);
                                }
                            }
                        }
                    }
                    // Also echo for this iteration
                    int echoLen = lastSendLen - 8;
                    if (echoLen > 0 && echoLen <= len) {
                        memcpy(buf, lastSendBuf + 8, echoLen);
                        r = echoLen;
                    }
                } else {
                    // Phase 4: back to echo after direct KC
                    rawKcDone++;
                    if (rawKcDone <= 10) {
                        BYTE rawKc[28]; // 4B preamble + 24B KeyCheck
                        memset(rawKc, 0, 28);
                        // Preamble (4B zeros or token)
                        // KeyCheck: opcode=0x64 LE, playerNo=0, pad, checkId
                        rawKc[4] = 0x64; rawKc[5] = 0x00; rawKc[6] = 0x00; rawKc[7] = 0x00;
                        rawKc[8] = 0x00; // playerNo
                        // checkId at offset 12 (8 bytes) - use fwd BF encrypt
                        HMODULE gb = GetModuleHandleA(NULL);
                        typedef void (*bfe_t)(void*, BYTE*);
                        bfe_t BfE = (bfe_t)((BYTE*)gb + 0x10F3D90);
                        void *bfc = NULL;
                        if (connStructAddr) {
                            BYTE *cb = (BYTE*)connStructAddr + 0x120;
                            if (cb[0] && !IsBadReadPtr(*(void**)(cb+8), 8)) {
                                BYTE *rn = (BYTE*)(*(void**)(*(void**)(cb+8)));
                                if (!IsBadReadPtr(rn, 0x30) && *(UINT64*)(rn+0x20)==1)
                                    bfc = *(void**)(rn+0x28);
                            }
                        }
                        if (bfc) {
                            BYTE ck[8] = {0};
                            BfE(bfc, ck);
                            memcpy(rawKc + 12, ck, 8);
                        }
                        memcpy(buf, rawKc, 28);
                        r = 28;
                        Log("  RAW-KC #%d: 28B", rawKcDone);
                    } else {
                        // Back to echo
                        int echoLen = lastSendLen - 8;
                        if (echoLen > 0 && echoLen <= len) {
                            memcpy(buf, lastSendBuf + 8, echoLen);
                            r = echoLen;
                        }
                    }
                }
            }
            if (0) {  // DISABLED: complex VC injection code below  // skip first few to let game init
                HMODULE gameBase = GetModuleHandleA(NULL);
                // FUN_1410f2a10 at RVA 0x10F2A10
                typedef void (*bf_cfb_t)(void* ctx, BYTE* data, USHORT len, int mode);
                bf_cfb_t BfCfb = (bf_cfb_t)((BYTE*)gameBase + 0x10F2A10);

                // Find BF context: stored in tree at (connStruct + 0x120 + 8)
                // From hook log: connStruct+0x128 points to tree root
                // Tree node with key=1 has value at node+0x28 → bf context ptr
                // We need to traverse: *(*(connStruct + 0x128) + some_offset)
                // Simpler: we already found the BF_KEY address in P-box scan
                // Let's scan for it again from the known tree location
                void *bfCtx = NULL;
                if (connStructAddr && !IsBadReadPtr((void*)(connStructAddr + 0x120), 16)) {
                    BYTE *cryptoBase = (BYTE*)connStructAddr + 0x120;
                    BYTE cryptoFlag = cryptoBase[0];  // *param_3 check
                    Log("  DECRYPT_TEST: cryptoFlag=%d", cryptoFlag);

                    if (cryptoFlag != 0) {
                        // The tree is at cryptoBase + 8
                        // Tree lookup for key=1: navigate the std::map
                        // Root is at *(cryptoBase + 8)
                        void **treePtr = (void**)(cryptoBase + 8);
                        if (!IsBadReadPtr(treePtr, 8) && *treePtr) {
                            // std::map node layout: [left][parent][right][color][key(8B)][value]
                            // We need the node where key=1
                            // Root node → child(1) → value at +0x28
                            BYTE *rootNode = (BYTE*)(*(void**)(*treePtr));  // root->left (first child)
                            if (!IsBadReadPtr(rootNode, 0x30)) {
                                UINT64 nodeKey = *(UINT64*)(rootNode + 0x20);
                                void *nodeVal = *(void**)(rootNode + 0x28);
                                Log("  DECRYPT_TEST: tree node key=%llu val=%p", nodeKey, nodeVal);
                                if (nodeKey == 1 && nodeVal && !IsBadReadPtr(nodeVal, 8)) {
                                    bfCtx = nodeVal;
                                    Log("  DECRYPT_TEST: BF context at %p", bfCtx);
                                }
                            }
                        }
                    }
                }

                if (bfCtx) {
                    // CONN[0x146]=0 → no header! Decrypt ALL bytes
                    int encLen = r;
                    if (encLen > 0 && encLen < 512) {
                        BYTE decBuf[512];
                        memcpy(decBuf, buf, encLen);

                        // Double CFB decrypt: decrypt → reverse → decrypt
                        BfCfb(bfCtx, decBuf, (USHORT)encLen, 2);  // pass 1

                        // Reverse
                        for (int i = 0; i < encLen / 2; i++) {
                            BYTE tmp = decBuf[i];
                            decBuf[i] = decBuf[encLen - 1 - i];
                            decBuf[encLen - 1 - i] = tmp;
                        }

                        BfCfb(bfCtx, decBuf, (USHORT)encLen, 2);  // pass 2

                        // Log decrypted first 16 bytes
                        Log("  DECRYPTED[0:16]: %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X",
                            decBuf[0], decBuf[1], decBuf[2], decBuf[3],
                            decBuf[4], decBuf[5], decBuf[6], decBuf[7],
                            decBuf[8], decBuf[9], decBuf[10], decBuf[11],
                            decBuf[12], decBuf[13], decBuf[14], decBuf[15]);
                        UINT16 parsedPeerID = decBuf[0] | (decBuf[1] << 8);
                        UINT32 parsedNonce = *(UINT32*)(decBuf + 2);
                        BYTE parsedFlags = decBuf[6];
                        Log("  PARSED: peerID=0x%04X nonce=0x%08X flags=0x%02X",
                            parsedPeerID, parsedNonce, parsedFlags);

                        // Try injecting via client's own encrypt function (FUN_1410f41e0)
                        // to see if the packet format is correct
                        if (pktCount <= 4) {
                            typedef void (*bf_cfb_enc_t)(void* ctx, BYTE* data, USHORT len, int mode);
                            bf_cfb_enc_t BfCfbEnc = (bf_cfb_enc_t)((BYTE*)gameBase + 0x10F41E0);

                            // First: decrypt the client's CONNECT to extract connectID and fields
                            // Client sends: [4B magic][4B sessID][4B token][encrypted payload 507B]
                            // After stripping 12B header, 507B remain. The client's code skips
                            // CONN[0x144]=4 bytes, then decrypts remaining 503B.
                            // But for OUR decrypt: the client's send path encrypts starting from
                            // the token (offset 8). Let me just decrypt bytes 12..518 (507B)
                            // using Double CFB decrypt.
                            static BYTE clientConnect[512];
                            static int connectDecrypted = 0;
                            static UINT32 clientConnectID = 0;
                            if (!connectDecrypted && lastSendLen == 519) {
                                // Try decrypting from offset 8 (after LNPBlob 8B header)
                                // The encrypted data = bytes 8..518 = 511 bytes
                                // Token at bytes 8-11 might be part of encrypted or preamble
                                // Client's CONN[0x144]=4 means 4B preamble before encrypted
                                // So: bytes 8-11 = preamble (not encrypted), bytes 12-518 = encrypted (507B)
                                // But the SEND path encrypts everything after the preamble
                                // Let's try BOTH: decrypt 511B (with token) and 507B (without token)

                                // Use SEND encrypt function (FUN_1410f41e0) to "decrypt"
                                // Since CFB is auto-inverse: E(E(x)) reverses the encryption
                                // Double: E41e0 → reverse → E41e0. To undo: E41e0 → reverse → E41e0 again!
                                // Actually, to undo FUN_1410f41e0 we need FUN_1410f2a10 (the recv decrypt).
                                // But the roundtrip test proved this works! Let me just try it on the right bytes.

                                // The client's send data after LNPBlob header:
                                // Bytes 8-518 = 511B. Client skips 4B (CONN+0x144), encrypts 507B.
                                // So encrypted region is bytes 12-518 = 507B.
                                // Use FUN_1410f2a10 mode 2 (recv decrypt) - this IS the inverse of send encrypt.

                                // But ALSO try using BfCfbEnc (FUN_1410f41e0) to self-decrypt
                                // Method C: use send function to self-decrypt 507B
                                BYTE decC[512];
                                memcpy(decC, lastSendBuf + 12, 507);
                                BfCfbEnc(bfCtx, decC, 507, 2);  // "encrypt" pass = decrypt pass 2
                                for (int i = 0; i < 507/2; i++) { BYTE t = decC[i]; decC[i] = decC[506-i]; decC[506-i] = t; }
                                BfCfbEnc(bfCtx, decC, 507, 2);  // decrypt pass 1

                                // Method A: standard recv decrypt of 507B
                                BYTE decA[512];
                                memcpy(decA, lastSendBuf + 12, 507);
                                BfCfb(bfCtx, decA, 507, 2);
                                for (int i = 0; i < 507/2; i++) { BYTE t = decA[i]; decA[i] = decA[506-i]; decA[506-i] = t; }
                                BfCfb(bfCtx, decA, 507, 2);

                                // Method B: recv decrypt 511B (including 4B token)
                                BYTE decB[512];
                                memcpy(decB, lastSendBuf + 8, 511);
                                BfCfb(bfCtx, decB, 511, 2);
                                for (int i = 0; i < 511/2; i++) { BYTE t = decB[i]; decB[i] = decB[510-i]; decB[510-i] = t; }
                                BfCfb(bfCtx, decB, 511, 2);

                                Log("  CONNECT decrypt A (recv 507B):");
                                Log("    [0:16]: %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X",
                                    decA[0], decA[1], decA[2], decA[3], decA[4], decA[5], decA[6], decA[7],
                                    decA[8], decA[9], decA[10], decA[11], decA[12], decA[13], decA[14], decA[15]);
                                Log("  CONNECT decrypt B (recv 511B):");
                                Log("    [0:16]: %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X",
                                    decB[0], decB[1], decB[2], decB[3], decB[4], decB[5], decB[6], decB[7],
                                    decB[8], decB[9], decB[10], decB[11], decB[12], decB[13], decB[14], decB[15]);
                                // B with 4B skip (token preamble):
                                Log("  CONNECT decrypt B+4 (skip token):");
                                Log("    [0:16]: %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X",
                                    decB[4], decB[5], decB[6], decB[7], decB[8], decB[9], decB[10], decB[11],
                                    decB[12], decB[13], decB[14], decB[15], decB[16], decB[17], decB[18], decB[19]);
                                Log("  CONNECT decrypt C (send func 507B):");
                                Log("    [0:16]: %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X",
                                    decC[0], decC[1], decC[2], decC[3], decC[4], decC[5], decC[6], decC[7],
                                    decC[8], decC[9], decC[10], decC[11], decC[12], decC[13], decC[14], decC[15]);

                                // Choose: look for flags=0x01 (CONNECT) at offset 6
                                BYTE *dec = decA;
                                if (decC[6] == 0x01) { dec = decC; Log("  Using C (send func)"); }
                                else if (decA[6] == 0x01) { dec = decA; Log("  Using A (recv 507B)"); }
                                else if (decB[10] == 0x01) { dec = decB + 4; Log("  Using B+4 (recv 511B skip token)"); }
                                else { Log("  No method gave flags=0x01! Trying C anyway"); dec = decC; }

                                memcpy(clientConnect, dec, 507);
                                connectDecrypted = 1;
                                Log("  CLIENT CONNECT decrypted:");
                                Log("    [0:16]: %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X",
                                    clientConnect[0], clientConnect[1], clientConnect[2], clientConnect[3],
                                    clientConnect[4], clientConnect[5], clientConnect[6], clientConnect[7],
                                    clientConnect[8], clientConnect[9], clientConnect[10], clientConnect[11],
                                    clientConnect[12], clientConnect[13], clientConnect[14], clientConnect[15]);
                                Log("    [16:32]: %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X",
                                    clientConnect[16], clientConnect[17], clientConnect[18], clientConnect[19],
                                    clientConnect[20], clientConnect[21], clientConnect[22], clientConnect[23],
                                    clientConnect[24], clientConnect[25], clientConnect[26], clientConnect[27],
                                    clientConnect[28], clientConnect[29], clientConnect[30], clientConnect[31]);
                                // The CONNECT body in decrypted plaintext:
                                // After [2B peerID][4B nonce][1B flags] = 7 bytes header
                                // CONNECT body: [2B outPeerID][1B inSessID][1B outSessID]
                                //   [4B mtu][4B windowSize][4B channelCount]
                                //   [4B inBW][4B outBW][4B throttleInt][4B throttleAcc][4B throttleDec]
                                //   [4B connectID][4B data]
                                // connectID is at body offset 2+1+1+4*8 = 36
                                // = decrypt offset 7 + 36 = 43
                                clientConnectID = (UINT32)clientConnect[43] << 24 |
                                                  (UINT32)clientConnect[44] << 16 |
                                                  (UINT32)clientConnect[45] << 8 |
                                                  (UINT32)clientConnect[46];
                                Log("    connectID (BE at offset 43): 0x%08X", clientConnectID);
                                // Also try reading as LE
                                UINT32 cidLE = *(UINT32*)(clientConnect + 43);
                                Log("    connectID (LE at offset 43): 0x%08X", cidLE);
                            }

                            // Build VERIFY_CONNECT with connectID
                            typedef int (*crc_fn_t)(BYTE *param);
                            crc_fn_t CrcFn = (crc_fn_t)((BYTE*)gameBase + 0x577f10);

                            // 40-byte body: standard 36 + 4 connectID
                            BYTE body[40];
                            memset(body, 0, 40);
                            int o = 0;
                            body[o+0] = 0x00; body[o+1] = 0x00;  // outPeerID BE = 0
                            body[o+2] = 0x00;  // incomingSessionID = 0
                            body[o+3] = 0x00;  // outgoingSessionID = 0
                            body[o+4] = 0x00; body[o+5] = 0x00; body[o+6] = 0x04; body[o+7] = 0x00;  // MTU=1024
                            body[o+8] = 0x00; body[o+9] = 0x00; body[o+10] = 0x80; body[o+11] = 0x00; // windowSize=32768
                            body[o+12] = 0x00; body[o+13] = 0x00; body[o+14] = 0x00; body[o+15] = 0x08; // channelCount=8
                            body[o+16] = 0x00; body[o+17] = 0x00; body[o+18] = 0x00; body[o+19] = 0x00; // inBW
                            body[o+20] = 0x00; body[o+21] = 0x00; body[o+22] = 0x00; body[o+23] = 0x00; // outBW
                            body[o+24] = 0x00; body[o+25] = 0x00; body[o+26] = 0x13; body[o+27] = 0x88; // throttleInt=5000
                            body[o+28] = 0x00; body[o+29] = 0x00; body[o+30] = 0x00; body[o+31] = 0x02; // throttleAcc
                            body[o+32] = 0x00; body[o+33] = 0x00; body[o+34] = 0x00; body[o+35] = 0x02; // throttleDec
                            // connectID = just use 1 (we can't decrypt client's CONNECT reliably)
                            body[o+36] = 0x00;
                            body[o+37] = 0x00;
                            body[o+38] = 0x00;
                            body[o+39] = 0x01;  // connectID = 1 (BE)

                            // Build CRC struct as FUN_1405725f0 would
                            BYTE crcBuf[0x60];
                            memset(crcBuf, 0, sizeof(crcBuf));
                            *(UINT64*)(crcBuf + 0x00) = 1;  // local_c8 = connection seq
                            *(UINT64*)(crcBuf + 0x18) = 0xFFFFFFFFFFFFFFFF;  // local_b0
                            *(UINT16*)(crcBuf + 0x08) = 0;  // peerID
                            // Set payload (40 bytes = 36 + connectID)
                            static BYTE payBuf[64];
                            memcpy(payBuf, body, 40);
                            *(UINT64*)(crcBuf + 0x48) = (UINT64)payBuf;
                            *(UINT16*)(crcBuf + 0x52) = 40;

                            int crcNonce = CrcFn(crcBuf);
                            Log("  INJECT CRC nonce from client = 0x%08X", (UINT32)crcNonce);

                            // Build plaintext: [2B peerID][4B nonce][1B flags][40B body]
                            // Total = 2+4+1+40 = 47 bytes
                            BYTE testPt[47];
                            memset(testPt, 0, 47);
                            testPt[0] = 0x00; testPt[1] = 0x00;  // peerID
                            *(UINT32*)(testPt + 2) = (UINT32)crcNonce;  // nonce as returned
                            testPt[6] = 0x03;  // flags = VERIFY_CONNECT
                            memcpy(testPt + 7, body, 40);

                            // Encrypt using client's OWN function (FUN_1410f41e0, mode 2)
                            BYTE testEnc[47];
                            memcpy(testEnc, testPt, 47);
                            BfCfbEnc(bfCtx, testEnc, 47, 2);  // pass 1
                            for (int i = 0; i < 47/2; i++) {
                                BYTE tmp = testEnc[i]; testEnc[i] = testEnc[46-i]; testEnc[46-i] = tmp;
                            }
                            BfCfbEnc(bfCtx, testEnc, 47, 2);  // pass 2

                            // Verify roundtrip
                            BYTE testDec[47];
                            memcpy(testDec, testEnc, 47);
                            BfCfb(bfCtx, testDec, 47, 2);
                            for (int i = 0; i < 47/2; i++) {
                                BYTE tmp = testDec[i]; testDec[i] = testDec[46-i]; testDec[46-i] = tmp;
                            }
                            BfCfb(bfCtx, testDec, 47, 2);

                            Log("  ROUNDTRIP: pt=%02X%02X%02X%02X%02X%02X%02X enc=%02X%02X%02X%02X%02X%02X%02X dec=%02X%02X%02X%02X%02X%02X%02X",
                                testPt[0], testPt[1], testPt[2], testPt[3], testPt[4], testPt[5], testPt[6],
                                testEnc[0], testEnc[1], testEnc[2], testEnc[3], testEnc[4], testEnc[5], testEnc[6],
                                testDec[0], testDec[1], testDec[2], testDec[3], testDec[4], testDec[5], testDec[6]);

                            if (memcmp(testPt, testDec, 47) == 0) {
                                // Inject our VERIFY_CONNECT (47B encrypted)
                                // With 4B preamble (CONN+0x144=4)
                                memset(buf, 0, 51);
                                memcpy(buf + 4, testEnc, 47);  // 4B preamble + 47B enc
                                r = 51;
                                static int vcCount = 0;
                                vcCount++;
                                Log("  INJECTED VC #%d: 51B (4B pre + 47B enc, connectID=0x%08X)", vcCount, clientConnectID);
                            } else {
                                Log("  ROUNDTRIP FAILED! Encryption/decryption mismatch");
                            }
                        }
                    }
                }
            }

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
    if (hwBpInstalled && !crcPatched) EnsureHwBpOnThisThread();
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

    // Hook Schannel InitializeSecurityContextW to bypass TLS cert validation
    {
        HMODULE hSecur = GetModuleHandleA("secur32.dll");
        if (!hSecur) hSecur = GetModuleHandleA("sspicli.dll");
        if (hSecur) {
            void *pISCW = (void*)GetProcAddress(hSecur, "InitializeSecurityContextW");
            if (pISCW) {
                MakeTrampoline(pISCW, tramp_InitSecCtx);
                real_InitSecCtxW = (InitSecCtxW_fn)tramp_InitSecCtx;
                PatchJmp(pISCW, Hook_InitSecCtxW);
                Log("Hooked InitializeSecurityContextW at %p → TLS bypass active!", pISCW);
            } else {
                Log("InitializeSecurityContextW not found in secur32/sspicli");
            }
        } else {
            Log("secur32.dll / sspicli.dll not loaded");
        }
    }

    // DISABLED: trust store injection in DllMain crashes (TLS engine not init yet)
    // Moved to first sendto hook instead
    if (0) { // DISABLED
    // FUN_14168a4f0(0, &cert_ptr, cert_size) adds a CA cert to the trust store
    // FUN_1410fae90 calls this with the Riot CA. We call it with our cert too.
    {
        HMODULE hExe = GetModuleHandleA(NULL);
        typedef void (*AddCACert_t)(int, void**, int);
        AddCACert_t AddCACert = (AddCACert_t)((BYTE*)hExe + 0x168A4F0);

        // Read our FakeLCU cert DER
        FILE *cf = fopen("cert.pem", "r");
        if (!cf) cf = fopen("D:\\LeagueOfLegendsV2\\fakeLcu.crt", "r");
        if (cf) {
            char pem[4096] = {0};
            fread(pem, 1, sizeof(pem)-1, cf);
            fclose(cf);

            // Decode PEM to DER (simple base64)
            static BYTE ourDer[2048];
            int derLen = 0;
            {
                static const BYTE b64[256] = {
                    ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
                    ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
                    ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
                    ['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
                    ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
                    ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
                    ['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
                    ['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63
                };
                char *p = pem;
                while (*p && strncmp(p, "-----BEGIN", 10) != 0) p++;
                while (*p && *p != '\n') p++;
                if (*p) p++;
                int bits = 0, nbits = 0;
                while (*p && strncmp(p, "-----END", 8) != 0) {
                    if (*p=='\n'||*p=='\r'||*p==' '||*p=='=') { p++; continue; }
                    bits = (bits << 6) | b64[(unsigned char)*p];
                    nbits += 6;
                    if (nbits >= 8) { nbits -= 8; ourDer[derLen++] = (BYTE)(bits >> nbits); bits &= (1<<nbits)-1; }
                    p++;
                }
            }

            if (derLen > 0) {
                void *certPtr = ourDer;
                Log("Adding our cert (%dB DER) to TLS trust store via FUN_14168a4f0...", derLen);
                AddCACert(0, &certPtr, derLen);
                Log("*** OUR CERT ADDED TO TRUST STORE! ***");
            }
        } else {
            Log("Can't open cert.pem for TLS trust injection");
        }
    }
    } // end of if(0) DISABLED block

    // Start background thread to hook Schannel when secur32.dll loads
    Log("Starting TLS bypass thread...");
    CreateThread(NULL, 0, TlsBypassThread, NULL, 0, NULL);

    Log("Hooks: sendto, recvfrom, WSASendTo, WSARecvFrom + TLS bypass thread");

    // Check for SSL libraries to find where to hook cert verification
    HMODULE hSSL = GetModuleHandleA("ssleay32.dll");
    HMODULE hSSL2 = GetModuleHandleA("libssl-1_1-x64.dll");
    HMODULE hSSL3 = GetModuleHandleA("libssl-3-x64.dll");
    HMODULE hCrypt = GetModuleHandleA("crypt32.dll");
    HMODULE hSch = GetModuleHandleA("schannel.dll");
    HMODULE hBCrypt = GetModuleHandleA("bcrypt.dll");
    HMODULE hRiotApi = GetModuleHandleA("RiotGamesApi.dll");
    Log("SSL libs: ssleay32=%p libssl1.1=%p libssl3=%p crypt32=%p schannel=%p bcrypt=%p RiotGamesApi=%p",
        hSSL, hSSL2, hSSL3, hCrypt, hSch, hBCrypt, hRiotApi);

    // Try to find SSL_CTX_set_verify in any loaded SSL library
    void *pSetVerify = NULL;
    if (hRiotApi) {
        pSetVerify = (void*)GetProcAddress(hRiotApi, "SSL_CTX_set_verify");
        if (!pSetVerify) pSetVerify = (void*)GetProcAddress(hRiotApi, "SSL_set_verify");
        Log("RiotGamesApi SSL_CTX_set_verify=%p SSL_set_verify=%p",
            GetProcAddress(hRiotApi, "SSL_CTX_set_verify"),
            GetProcAddress(hRiotApi, "SSL_set_verify"));
    }
    // Hook Schannel to bypass TLS cert verification
    // The client uses Schannel (Windows TLS), not OpenSSL
    // We need to patch the credential flags to disable server cert validation
    {
        HMODULE hSecur = GetModuleHandleA("secur32.dll");
        if (!hSecur) hSecur = GetModuleHandleA("sspicli.dll");
        if (hSecur) {
            // AcquireCredentialsHandleW is called to set up TLS credentials
            // The SCHANNEL_CRED struct has a dwFlags field
            // If we set SCH_CRED_MANUAL_CRED_VALIDATION (0x8) and
            // SCH_CRED_NO_SERVERNAME_CHECK (0x4), cert validation is disabled

            // Better approach: hook InitializeSecurityContextW
            // After it returns, check if it returns SEC_E_UNTRUSTED_ROOT (0x80090325)
            // and change it to SEC_E_OK (0)

            // Simplest approach: find and patch the Schannel credential flags
            // The client calls AcquireCredentialsHandleW with SCHANNEL_CRED
            // We can hook this to modify the flags

            // Hook InitializeSecurityContextW to intercept TLS handshake results
            typedef LONG (WINAPI *InitSecCtxW_t)(void*, void*, void*, ULONG, ULONG, ULONG, void*, ULONG, void*, void*, ULONG*, void*);
            InitSecCtxW_t pInitSecCtx = (InitSecCtxW_t)GetProcAddress(hSecur, "InitializeSecurityContextW");
            Log("Schannel: secur32=%p InitializeSecurityContextW=%p", hSecur, pInitSecCtx);

            // Patch InitializeSecurityContextW to never return cert errors
            // SEC_E_UNTRUSTED_ROOT = 0x80090325
            // SEC_I_CONTINUE_NEEDED = 0x00090312
            // SEC_E_OK = 0
            // We'll inline hook it: save first bytes, JMP to our wrapper
            if (pInitSecCtx) {
                // Instead of complex inline hook, patch AcquireCredentialsHandleW
                // to set SCH_CRED_MANUAL_CRED_VALIDATION in the credential flags
                // Actually, simplest: just hook the IAT of the main EXE for these functions

                // For now: directly patch the SCHANNEL_CRED flags when they're on the stack
                // This requires knowing when AcquireCredentialsHandle is called...

                // EASIEST approach: hook `connect()` for TCP connections to the LCU port
                // and wrap the socket in our own TLS that accepts any cert.
                // But that's complex too.

                // Let's try: Hook WSASend/WSARecv for the TCP socket to the LCU
                // and implement our own TLS layer? No, too complex.

                // SIMPLEST: patch the ISC_REQ flags in InitializeSecurityContext calls
                // Add ISC_REQ_MANUAL_CRED_VALIDATION (0x00080000) to disable cert check
                // This requires hooking InitializeSecurityContextW

                // Use same inline hook technique as for sendto/recvfrom
                Log("Attempting to hook InitializeSecurityContextW for TLS bypass...");
            }
        }
    }

    // Also hook CertVerifyCertificateChainPolicy (might help with some paths)
    if (hCrypt) {
        typedef BOOL (WINAPI *CertVerify_t)(LPCSTR, void*, void*, void*);
        CertVerify_t pVerify = (CertVerify_t)GetProcAddress(hCrypt, "CertVerifyCertificateChainPolicy");
        Log("CertVerifyCertificateChainPolicy=%p", pVerify);
        if (pVerify) {
            // Inline hook: overwrite first bytes with JMP to our stub that returns TRUE
            // Our stub: set pPolicyStatus->dwError = 0, return TRUE
            // But simpler: just NOP the function to return TRUE immediately
            // MOV EAX, 1; RET = B8 01 00 00 00 C3 (6 bytes)
            DWORD oldProt;
            if (VirtualProtect((void*)pVerify, 16, PAGE_EXECUTE_READWRITE, &oldProt)) {
                BYTE *p = (BYTE*)pVerify;
                // CERT_CHAIN_POLICY_STATUS is the 4th param (pPolicyStatus)
                // We need to zero pPolicyStatus->dwError before returning TRUE
                // pPolicyStatus is in R9 (4th param in x64)
                // MOV dword ptr [R9+4], 0  (set dwError=0): 41 C7 41 04 00 00 00 00 (8 bytes)
                // MOV EAX, 1: B8 01 00 00 00 (5 bytes)
                // RET: C3 (1 byte)
                // Total: 14 bytes
                p[0] = 0x41; p[1] = 0xC7; p[2] = 0x41; p[3] = 0x04;
                p[4] = 0x00; p[5] = 0x00; p[6] = 0x00; p[7] = 0x00; // [R9+4] = 0
                p[8] = 0xB8; p[9] = 0x01; p[10] = 0x00; p[11] = 0x00; p[12] = 0x00; // EAX = 1
                p[13] = 0xC3; // RET
                VirtualProtect((void*)pVerify, 16, oldProt, &oldProt);
                Log("*** PATCHED CertVerifyCertificateChainPolicy → always TRUE ***");
            } else {
                Log("VirtualProtect on CertVerify failed: err=%lu", GetLastError());
            }
        }
    }
}

// Background thread to hook Schannel when secur32.dll loads
static DWORD WINAPI TlsBypassThread(LPVOID param) {
    for (int i = 0; i < 100; i++) {
        Sleep(100);
        if (real_InitSecCtxW) break;
        HMODULE hSec = GetModuleHandleA("secur32.dll");
        if (!hSec) hSec = GetModuleHandleA("sspicli.dll");
        if (hSec) {
            void *p = (void*)GetProcAddress(hSec, "InitializeSecurityContextW");
            if (p) {
                MakeTrampoline(p, tramp_InitSecCtx);
                real_InitSecCtxW = (InitSecCtxW_fn)tramp_InitSecCtx;
                PatchJmp(p, Hook_InitSecCtxW);
                Log("*** [TLS Thread] Hooked InitializeSecurityContextW! ***");
                break;
            }
        }
    }
    if (!real_InitSecCtxW) Log("[TLS Thread] secur32.dll never loaded (10s timeout)");

    // Add cert to TLS trust store ASAP (no delay - race with TLS handshake)
    {
        HMODULE hExe = GetModuleHandleA(NULL);
        typedef void (*AddCA_t)(int, void**, int);
        AddCA_t AddCA = (AddCA_t)((BYTE*)hExe + 0x168A4F0);
        FILE *cf = fopen("cert.pem", "r");
        if (cf) {
            char pm[4096]={0}; fread(pm,1,4095,cf); fclose(cf);
            static BYTE der2[2048]; int dl2=0;
            static const BYTE b2[256]={['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63};
            char *p2=pm; while(*p2&&strncmp(p2,"-----BEGIN",10)!=0)p2++; while(*p2&&*p2!='\n')p2++; if(*p2)p2++;
            int bits2=0,nb2=0;
            while(*p2&&strncmp(p2,"-----END",8)!=0){if(*p2=='\n'||*p2=='\r'||*p2==' '||*p2=='='){p2++;continue;}bits2=(bits2<<6)|b2[(unsigned char)*p2];nb2+=6;if(nb2>=8){nb2-=8;der2[dl2++]=(BYTE)(bits2>>nb2);bits2&=(1<<nb2)-1;}p2++;}
            if (dl2 > 0) {
                void *cp = der2;
                Log("[TLS Thread] Adding cert (%dB) to trust store...", dl2);
                AddCA(0, &cp, dl2);
                Log("[TLS Thread] *** CERT ADDED! ***");
            }
        }
    }
    return 0;
}

// Thread that adds our cert to BoringSSL trust store ASAP
// Safe memory read: returns 0 if page is not readable
static int SafeRead8(void *addr, UINT64 *out) {
    MEMORY_BASIC_INFORMATION mi;
    if (!VirtualQuery(addr, &mi, sizeof(mi))) return 0;
    if (mi.State != MEM_COMMIT) return 0;
    if (!(mi.Protect & (PAGE_READWRITE|PAGE_READONLY|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE))) return 0;
    if (mi.Protect & (PAGE_GUARD|PAGE_NOACCESS)) return 0;
    *out = *(UINT64*)addr;
    return 1;
}

static DWORD WINAPI CertInjectionThread(LPVOID param) {
    if (logfile) { fprintf(logfile, "[CertThread] STARTED\n"); fflush(logfile); }
    HMODULE hExe = GetModuleHandleA(NULL);
    if (!hExe) return 0;

    // === PHASE 0: Patch SSL_CTX verify_mode BEFORE first TLS attempt ===
    // The parent SSL object has vtable at hExe + 0x19658D0
    // Scan heap for this vtable to find the SSL parent, then patch verify_mode
    Sleep(200); // tiny delay for heap init
    {
        UINT64 sslVtable = (UINT64)hExe + 0x19658D0;
        if (logfile) { fprintf(logfile, "[CertThread] Scanning for SSL vtable 0x%llX...\n",
            (unsigned long long)sslVtable); fflush(logfile); }

        MEMORY_BASIC_INFORMATION mbi;
        BYTE *scan = NULL;
        int sslFound = 0;

        // Retry up to 10 times (SSL_CTX may not be created yet)
        for (int attempt = 0; attempt < 10 && !sslFound; attempt++) {
            if (attempt > 0) Sleep(1000);
            scan = NULL;
            while (VirtualQuery(scan, &mbi, sizeof(mbi))) {
                if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE) &&
                    !(mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS)) && mbi.RegionSize >= 8) {
                    BYTE *base = (BYTE*)mbi.BaseAddress;
                    SIZE_T size = mbi.RegionSize;
                    if (!(base >= (BYTE*)hExe && base < (BYTE*)hExe + 0x20000000)) {
                        for (SIZE_T j = 0; j + 8 <= size && !sslFound; j += 8) {
                            UINT64 qval = *(UINT64*)(base + j);
                            if (qval == sslVtable) {
                                BYTE *sslObj = base + j;
                                // Verify: the object should have heap pointers after the vtable
                                UINT64 field1 = (j+16 <= size) ? *(UINT64*)(sslObj + 8) : 0;
                                if (field1 < 0x10000 || field1 > 0x7FFFFFFFFFFF) continue; // not a valid ptr
                                if (logfile) { fprintf(logfile,
                                    "[CertThread] SSL parent at %p field1=%p (attempt %d)\n",
                                    sslObj, (void*)field1, attempt+1);
                                    // Dump first 64 bytes for analysis
                                    fprintf(logfile, "  [0..63]: ");
                                    for (int d = 0; d < 64 && j+d < size; d++)
                                        fprintf(logfile, "%02X ", sslObj[d]);
                                    fprintf(logfile, "\n");
                                    fflush(logfile);
                                }

                                // The SSL parent stores pointers to sub-objects
                                // One of them is the SSL_CTX (0x2E0 bytes)
                                // Try to find and patch verify_mode in sub-objects
                                // In BoringSSL, verify_mode is typically an int with value 1 (VERIFY_PEER)
                                // Scan the object and its referenced objects for verify_mode

                                // Strategy: look at pointer fields in the SSL parent
                                // Each pointer might lead to SSL_CTX or SSL_config
                                for (int poff = 8; poff < 256 && poff + 8 <= (int)size - (int)j; poff += 8) {
                                    UINT64 ptr = *(UINT64*)(sslObj + poff);
                                    if (ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF) continue;
                                    // Check if this pointer leads to a large heap object
                                    MEMORY_BASIC_INFORMATION mbi2;
                                    if (!VirtualQuery((void*)ptr, &mbi2, sizeof(mbi2))) continue;
                                    if (mbi2.State != MEM_COMMIT || !(mbi2.Protect & PAGE_READWRITE)) continue;

                                    // Scan this sub-object for verify_mode (int == 1)
                                    // Try offsets 0x80-0x120 (common for BoringSSL verify_mode)
                                    for (int voff = 0x80; voff <= 0x180; voff += 4) {
                                        UINT32 val = 0;
                                        if (SafeRead8((void*)(ptr + voff), (UINT64*)&val)) {
                                            // Don't use SafeRead8 for 4 bytes, just read directly
                                        }
                                        if (!IsBadReadPtr((void*)(ptr + voff), 4)) {
                                            val = *(UINT32*)(ptr + voff);
                                            if (val == 1) { // SSL_VERIFY_PEER
                                                // Check if nearby bytes look right (not just random 1)
                                                UINT32 prev = *(UINT32*)(ptr + voff - 4);
                                                UINT32 next = *(UINT32*)(ptr + voff + 4);
                                                // verify_mode=1 is often near other small ints or zeros
                                                if (prev < 100 && next < 100) {
                                                    if (logfile) { fprintf(logfile,
                                                        "[CertThread] Candidate verify_mode at obj+0x%X (parent+0x%X ptr=%p): "
                                                        "prev=%u val=%u next=%u\n",
                                                        voff, poff, (void*)ptr, prev, val, next);
                                                        fflush(logfile); }
                                                    // PATCH IT to SSL_VERIFY_NONE (0)
                                                    *(UINT32*)(ptr + voff) = 0;
                                                    if (logfile) { fprintf(logfile,
                                                        "[CertThread] *** PATCHED verify_mode to 0 at %p+0x%X ***\n",
                                                        (void*)ptr, voff); fflush(logfile); }
                                                    sslFound = 1;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                    if (sslFound) break;
                                }
                                if (!sslFound) {
                                    // Didn't find verify_mode in sub-objects, try in the parent itself
                                    for (int voff = 0x20; voff <= 0x200 && j + voff + 4 <= size; voff += 4) {
                                        UINT32 val = *(UINT32*)(sslObj + voff);
                                        if (val == 1) {
                                            UINT32 prev = (voff >= 4) ? *(UINT32*)(sslObj + voff - 4) : 999;
                                            UINT32 next = *(UINT32*)(sslObj + voff + 4);
                                            if (prev < 100 && next < 100) {
                                                *(UINT32*)(sslObj + voff) = 0;
                                                if (logfile) { fprintf(logfile,
                                                    "[CertThread] *** PATCHED parent+0x%X to 0 (was 1) ***\n", voff);
                                                    fflush(logfile); }
                                                sslFound = 1;
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                scan = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
            }
            if (logfile && !sslFound) {
                fprintf(logfile, "[CertThread] SSL attempt %d: not found\n", attempt+1);
                fflush(logfile);
            }
        }
    }

    // === PHASE 1: Parse certs and scan trust store (existing code) ===
    Sleep(500); // delay for DLL init

    // If vtable not yet captured, try to compute it by parsing a cert ourselves
    if (g_x509Vtable == 0) {
        // Parse the Riot CA cert from the binary to get the vtable
        typedef void* (*ParseCert_t)(void*, void**, int);
        ParseCert_t ParseCert = (ParseCert_t)((BYTE*)hExe + 0x168A4F0);
        BYTE *riotCA = (BYTE*)hExe + 0x19EEBD0;
        static UINT64 tmpCtx[4] = {0};
        void *tmpPtr = riotCA;
        void *handle = ParseCert(tmpCtx, &tmpPtr, 1060);
        if (tmpCtx[0]) {
            UINT64 *cb = (UINT64*)tmpCtx[0];
            g_x509Vtable = cb[4]; // vtable at +0x20
            if (logfile) { fprintf(logfile, "[CertThread] Computed vtable=0x%llX from Riot CA (hExe=%p)\n",
                g_x509Vtable, hExe); fflush(logfile); }
        }
    }

    // Also wait for sendto to capture it (backup)
    if (g_x509Vtable == 0) {
        for (int w = 0; w < 100 && g_x509Vtable == 0; w++) Sleep(100);
    }
    if (g_x509Vtable == 0) {
        if (logfile) { fprintf(logfile, "[CertThread] No vtable after 10s, aborting\n"); fflush(logfile); }
        return 0;
    }

    // Also parse our own cert if not yet done
    if (g_ourCertHandle == 0) {
        // Read cert.pem from Game directory
        char certPath[MAX_PATH];
        GetModuleFileNameA(NULL, certPath, MAX_PATH);
        char *lastSlash = strrchr(certPath, '\\');
        if (lastSlash) { strcpy(lastSlash + 1, "cert.pem"); }
        FILE *cf = fopen(certPath, "rb");
        if (cf) {
            BYTE certBuf[4096];
            // Decode PEM to DER
            fseek(cf, 0, SEEK_END); long sz = ftell(cf); fseek(cf, 0, SEEK_SET);
            char pemBuf[4096]; fread(pemBuf, 1, sz, cf); fclose(cf);
            pemBuf[sz] = 0;
            // Simple base64 decode
            static const BYTE b64[] = {
                ['A']=0,['B']=1,['C']=2,['D']=3,['E']=4,['F']=5,['G']=6,['H']=7,
                ['I']=8,['J']=9,['K']=10,['L']=11,['M']=12,['N']=13,['O']=14,['P']=15,
                ['Q']=16,['R']=17,['S']=18,['T']=19,['U']=20,['V']=21,['W']=22,['X']=23,
                ['Y']=24,['Z']=25,['a']=26,['b']=27,['c']=28,['d']=29,['e']=30,['f']=31,
                ['g']=32,['h']=33,['i']=34,['j']=35,['k']=36,['l']=37,['m']=38,['n']=39,
                ['o']=40,['p']=41,['q']=42,['r']=43,['s']=44,['t']=45,['u']=46,['v']=47,
                ['w']=48,['x']=49,['y']=50,['z']=51,['0']=52,['1']=53,['2']=54,['3']=55,
                ['4']=56,['5']=57,['6']=58,['7']=59,['8']=60,['9']=61,['+']=62,['/']=63
            };
            char *p = strstr(pemBuf, "-----BEGIN");
            if (p) p = strchr(p, '\n'); if (p) p++;
            int dl = 0;
            BYTE dr[4096];
            unsigned bits = 0; int nb = 0;
            while(p && *p && strncmp(p,"-----END",8)!=0) {
                if(*p=='\n'||*p=='\r'||*p==' '||*p=='='){p++;continue;}
                bits=(bits<<6)|b64[(unsigned char)*p];nb+=6;
                if(nb>=8){nb-=8;dr[dl++]=(BYTE)(bits>>nb);bits&=(1<<nb)-1;}
                p++;
            }
            if (dl > 0) {
                typedef void* (*ParseCert_t2)(void*, void**, int);
                ParseCert_t2 PC = (ParseCert_t2)((BYTE*)hExe + 0x168A4F0);
                static UINT64 ourCtx2[4] = {0};
                void *certPtr = dr;
                PC(ourCtx2, &certPtr, dl);
                if (ourCtx2[0]) {
                    g_ourCertHandle = ourCtx2[0];
                    if (logfile) { fprintf(logfile, "[CertThread] Parsed our cert: handle=%p\n",
                        (void*)g_ourCertHandle); fflush(logfile); }
                }
            }
        }
    }
    if (logfile) { fprintf(logfile, "[CertThread] vtable=0x%llX handle=%p, scanning heap...\n",
        g_x509Vtable, (void*)g_ourCertHandle); fflush(logfile); }

    // Search heap for arrays of pointers where entry+0x20 == g_x509Vtable
    MEMORY_BASIC_INFORMATION mbi;
    BYTE *scan = NULL;
    int found = 0;
    int regionsScanned = 0, vtableHits = 0;

    while (VirtualQuery(scan, &mbi, sizeof(mbi)) && !found) {
        if (mbi.State != MEM_COMMIT || !(mbi.Protect & PAGE_READWRITE) ||
            (mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS)) || mbi.RegionSize < 256) {
            scan = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
            continue;
        }
        BYTE *base = (BYTE*)mbi.BaseAddress;
        SIZE_T size = mbi.RegionSize;
        if (base >= (BYTE*)hExe && base < (BYTE*)hExe + 0x20000000) {
            scan = base + size; continue;
        }
        regionsScanned++;

        // Scan for ANY pointer whose target has vtable at +0x20
        for (SIZE_T j = 0; j + 8 <= size && !found; j += 8) {
            UINT64 val = *(UINT64*)(base + j);
            if (val < 0x10000 || val > 0x7FFFFFFFFFFF) continue;
            if (val >= (UINT64)hExe && val < (UINT64)hExe + 0x20000000) continue;

            UINT64 vtCheck = 0;
            if (SafeRead8((void*)(val + 0x20), &vtCheck) && vtCheck == g_x509Vtable) {
                vtableHits++;
                // Found a cert handle! Count consecutive ones
                int count = 0;
                for (int k = 0; k < 60; k++) {
                    UINT64 next = 0;
                    if (j + (k+1)*8 > size) break;
                    next = *(UINT64*)(base + j + k*8);
                    UINT64 vt2 = 0;
                    if (!SafeRead8((void*)(next + 0x20), &vt2) || vt2 != g_x509Vtable) break;
                    count++;
                }
                if (vtableHits <= 10 && logfile) {
                    fprintf(logfile, "[CertThread] vtable hit #%d at %p: val=%p count=%d\n",
                        vtableHits, base+j, (void*)val, count);
                    fflush(logfile);
                }
                // Replace Riot cert with ours IMMEDIATELY on first non-self hit
                if (val != g_ourCertHandle && g_ourCertHandle && !found) {
                    *(UINT64*)(base + j) = g_ourCertHandle;
                    found = 1;
                    if (logfile) { fprintf(logfile,
                        "[CertThread] *** EARLY REPLACE at %p: old=%p → new=%p ***\n",
                        base+j, (void*)val, (void*)g_ourCertHandle); fflush(logfile); }
                    goto scan_done;
                }
                if (count >= 3) { // lowered from 5 to 3
                    found = 1;
                    if (logfile) {
                        fprintf(logfile, "[CertThread] *** TRUST VECTOR ARRAY at %p, %d entries! ***\n",
                                base + j, count);
                        fflush(logfile);
                    }
                    // Search backward for the vector struct: {begin, end, capacity}
                    // begin should equal base+j, end = begin + count*8
                    UINT64 arrAddr = (UINT64)(base + j);
                    UINT64 endAddr = arrAddr + count * 8;
                    // Search nearby for the vector header
                    BYTE *searchBase = base;
                    for (SIZE_T s = 0; s + 24 <= size; s += 8) {
                        UINT64 *vec = (UINT64*)(searchBase + s);
                        if (vec[0] == arrAddr && vec[1] >= arrAddr && vec[1] <= endAddr + 64) {
                            if (logfile) {
                                fprintf(logfile, "[CertThread] VECTOR STRUCT at %p: begin=%p end=%p cap=%p\n",
                                        vec, (void*)vec[0], (void*)vec[1], (void*)vec[2]);
                                fflush(logfile);
                            }
                            // PUSH OUR CERT!
                            if (g_ourCertHandle) {
                                typedef void (*VecPush_t)(void*, void*, void*);
                                VecPush_t VecPush = (VecPush_t)((BYTE*)hExe + 0x1E2190);
                                void *h = (void*)g_ourCertHandle;
                                if (logfile) { fprintf(logfile, "[CertThread] push_back(vec=%p, end=%p, &handle=%p)\n",
                                    vec, (void*)vec[1], &h); fflush(logfile); }
                                VecPush(vec, (void*)vec[1], &h);
                                if (logfile) { fprintf(logfile, "[CertThread] *** CERT INJECTED! New count=%llu ***\n",
                                    (vec[1] - vec[0]) / 8); fflush(logfile); }
                            }
                            goto scan_done;
                        }
                    }
                }
            }
        }
        scan = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    scan_done:
    if (logfile) {
        fprintf(logfile, "[CertThread] Scan #1: %d regions, %d vtable hits, found=%d\n",
            regionsScanned, vtableHits, found);
        fflush(logfile);
    }
    // Retry scan every 5s for up to 60s (TLS may init later)
    if (!found) {
        for (int retry = 0; retry < 12 && !found; retry++) {
            Sleep(5000);
            scan = NULL;
            vtableHits = 0; regionsScanned = 0;
            while (VirtualQuery(scan, &mbi, sizeof(mbi)) && !found) {
                if (mbi.State != MEM_COMMIT || !(mbi.Protect & PAGE_READWRITE) ||
                    (mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS)) || mbi.RegionSize < 256) {
                    scan = (BYTE*)mbi.BaseAddress + mbi.RegionSize; continue;
                }
                BYTE *base2 = (BYTE*)mbi.BaseAddress;
                SIZE_T size2 = mbi.RegionSize;
                if (base2 >= (BYTE*)hExe && base2 < (BYTE*)hExe + 0x20000000) {
                    scan = base2 + size2; continue;
                }
                regionsScanned++;
                for (SIZE_T j = 0; j + 8 <= size2 && !found; j += 8) {
                    UINT64 val = *(UINT64*)(base2 + j);
                    if (val < 0x10000 || val > 0x7FFFFFFFFFFF) continue;
                    UINT64 vtc = 0;
                    if (SafeRead8((void*)(val + 0x20), &vtc) && vtc == g_x509Vtable) {
                        vtableHits++;
                        int count = 0;
                        for (int k = 0; k < 60; k++) {
                            if (j + (k+1)*8 > size2) break;
                            UINT64 next = *(UINT64*)(base2 + j + k*8);
                            UINT64 vt2 = 0;
                            if (!SafeRead8((void*)(next + 0x20), &vt2) || vt2 != g_x509Vtable) break;
                            count++;
                        }
                        if (count >= 3) {
                            found = 1;
                            if (logfile) { fprintf(logfile, "[CertThread] RETRY #%d: TRUST ARRAY at %p, %d entries!\n",
                                retry+1, base2+j, count); fflush(logfile); }
                            UINT64 arrAddr = (UINT64)(base2 + j);
                            UINT64 endAddr = arrAddr + count * 8;
                            for (SIZE_T s = 0; s + 24 <= size2; s += 8) {
                                UINT64 *vec = (UINT64*)(base2 + s);
                                if (vec[0] == arrAddr && vec[1] >= arrAddr && vec[1] <= endAddr + 64) {
                                    if (g_ourCertHandle) {
                                        typedef void (*VecPush_t)(void*, void*, void*);
                                        VecPush_t VP = (VecPush_t)((BYTE*)hExe + 0x1E2190);
                                        void *h = (void*)g_ourCertHandle;
                                        VP(vec, (void*)vec[1], &h);
                                        if (logfile) { fprintf(logfile, "[CertThread] *** CERT INJECTED! count=%llu ***\n",
                                            (vec[1]-vec[0])/8); fflush(logfile); }
                                    }
                                    goto retry_done;
                                }
                            }
                            // Array found but no vector struct — try direct write
                            if (logfile) { fprintf(logfile, "[CertThread] Array found but no vector struct. Trying direct write.\n"); fflush(logfile); }
                            // Write our handle at the end of the array
                            *(UINT64*)(base2 + j + count*8) = g_ourCertHandle;
                            if (logfile) { fprintf(logfile, "[CertThread] *** DIRECT WRITE at arr[%d]=%p ***\n",
                                count, (void*)g_ourCertHandle); fflush(logfile); }
                            goto retry_done;
                        }
                    }
                }
                scan = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
            }
            if (logfile) { fprintf(logfile, "[CertThread] Retry #%d: %d regions, %d hits, found=%d\n",
                retry+1, regionsScanned, vtableHits, found); fflush(logfile); }

            // If we found exactly 1 cert handle (Riot CA), replace it with ours
            if (!found && vtableHits >= 1 && g_ourCertHandle) {
                // Rescan to find the single Riot cert handle and replace it
                BYTE *rescan = NULL;
                MEMORY_BASIC_INFORMATION mbi2;
                while (VirtualQuery(rescan, &mbi2, sizeof(mbi2))) {
                    if (mbi2.State == MEM_COMMIT && (mbi2.Protect & PAGE_READWRITE) &&
                        !(mbi2.Protect & (PAGE_GUARD|PAGE_NOACCESS)) && mbi2.RegionSize >= 8) {
                        BYTE *rb = (BYTE*)mbi2.BaseAddress;
                        SIZE_T rs = mbi2.RegionSize;
                        if (!(rb >= (BYTE*)hExe && rb < (BYTE*)hExe + 0x20000000)) {
                            for (SIZE_T rj = 0; rj + 8 <= rs; rj += 8) {
                                UINT64 rv = *(UINT64*)(rb + rj);
                                if (rv < 0x10000 || rv > 0x7FFFFFFFFFFF) continue;
                                if (rv == g_ourCertHandle) continue; // skip our own handle
                                UINT64 rvt = 0;
                                if (SafeRead8((void*)(rv + 0x20), &rvt) && rvt == g_x509Vtable) {
                                    // Found a Riot cert handle - REPLACE it with ours
                                    UINT64 oldHandle = rv;
                                    *(UINT64*)(rb + rj) = g_ourCertHandle;
                                    found = 1;
                                    if (logfile) { fprintf(logfile,
                                        "[CertThread] *** REPLACED cert at %p: old=%p → new=%p ***\n",
                                        rb+rj, (void*)oldHandle, (void*)g_ourCertHandle); fflush(logfile); }
                                    goto retry_done;
                                }
                            }
                        }
                    }
                    rescan = (BYTE*)mbi2.BaseAddress + mbi2.RegionSize;
                }
            }
        }
    }
    retry_done:
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);

        // Init Blowfish key schedule and CRC table for CRC nonce fixup
        {
            // Key: 17BLOhi6KZsTtldTsizvHg== (base64) = 16 bytes
            static const BYTE bfKey[] = {0xD7,0xB0,0x4B,0x3A,0x18,0xBA,0x29,0x9B,0x13,0xB6,0x57,0x53,0xB2,0x2C,0xEF,0x1E};
            HookBF_Init(bfKey, 16);
            InitCrcTable();
        }

        // CRC bypass will be installed on first sendto (not in DllMain - too early)

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
        {
            // Verify BF: encrypt 8 zeros and check against known bf_enc_zeros
            UINT32 tl = 0, tr = 0;
            HookBF_Encrypt(&tl, &tr);
            Log("BF P[0]=0x%08X (expect 0xBBCD2876) enc(0)=%02X%02X%02X%02X%02X%02X%02X%02X (expect F9ED26C0F22A52B4)",
                hook_P[0],
                (tl>>24)&0xFF,(tl>>16)&0xFF,(tl>>8)&0xFF,tl&0xFF,
                (tr>>24)&0xFF,(tr>>16)&0xFF,(tr>>8)&0xFF,tr&0xFF);
            Log("CRC[1]=0x%08X (expect 0x04C11DB7)", crc_table[1]);
            // Test Double-CFB roundtrip with known data
            {
                BYTE testPt[24] = {0x00,0x00,0xDE,0xAD,0xBE,0xEF,0x06,0x00,
                                   0x00,0x01,0x00,0x14,0x00,0x00,0x00,0x00,
                                   0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00};
                BYTE testEnc[24];
                memcpy(testEnc, testPt, 24);
                HookDoubleCFB_Encrypt(testEnc, 24);
                // Expected: 192D3AFE7205F4DB9DBC86FD1D541512A3279BA724455868
                Log("DBLCFB enc: %02X%02X%02X%02X%02X%02X%02X%02X (expect 192D3AFE7205F4DB)",
                    testEnc[0],testEnc[1],testEnc[2],testEnc[3],
                    testEnc[4],testEnc[5],testEnc[6],testEnc[7]);
                HookDoubleCFB_Decrypt(testEnc, 24);
                int match = (memcmp(testEnc, testPt, 24) == 0);
                Log("DBLCFB roundtrip: %s", match ? "OK" : "FAIL!");
                if (!match) {
                    Log("  Got: %02X%02X%02X%02X%02X%02X%02X%02X",
                        testEnc[0],testEnc[1],testEnc[2],testEnc[3],
                        testEnc[4],testEnc[5],testEnc[6],testEnc[7]);
                }
            }
        }

        // Install network hooks
        InstallNetHooks();

        // Start cert injection thread (adds our cert to BoringSSL trust store)
        CreateThread(NULL, 0, CertInjectionThread, NULL, 0, NULL);
    }
    else if (reason == DLL_PROCESS_DETACH) {
        Log("Unloading");
        if (logfile) fclose(logfile);
        if (realVersionDll) FreeLibrary(realVersionDll);
    }
    return TRUE;
}
