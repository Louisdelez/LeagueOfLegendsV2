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
static volatile BYTE *connStructAddr = NULL;  // RBX = connection struct address
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
        // Patch CRC check on first sendto (game is already initialized by now)
        // Try to patch CRC (may already be done in DllMain)
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

static volatile void *recvHostStruct = NULL;

int WINAPI Hook_recvfrom(SOCKET s, char *buf, int len, int flags,
                         struct sockaddr *from, int *fromlen) {
    // Find host struct: the object whose *(ptr+0x38) == our socket handle
    // Host struct layout: +0x38 = socket, +0x50 = some byte, +0x28 = ushort
    if (!recvHostStruct) {
        // Scan near connStructAddr (the host might be nearby in memory)
        // Actually, the host is passed as param_1 (RCX) to the outer function
        // Since we can't capture RCX, scan the stack for a pointer to an object with +0x38 = socket
        BYTE *stack;
        __asm__ volatile("movq %%rsp, %0" : "=r"(stack));
        for (int off = 0; off < 0x2000; off += 8) {
            BYTE *candidate = *(BYTE**)(stack + off);
            if (candidate && !IsBadReadPtr(candidate, 0x180) && !IsBadReadPtr(candidate + 0x38, 8)) {
                UINT64 sock = *(UINT64*)(candidate + 0x38);
                if (sock == (UINT64)s) {
                    // Found! Verify: +0x50 should be a small byte
                    BYTE b50 = candidate[0x50];
                    if (b50 <= 2) {
                        recvHostStruct = candidate;
                        Log("  FOUND HOST at %p (stack offset +0x%X, socket=%llu, +0x50=%d)",
                            candidate, off, sock, b50);
                        break;
                    }
                }
            }
        }
    }
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
            // Find and dump vtable for the handler using REAL host struct
            static int vtableDumped = 0;
            if (recvHostStruct && !vtableDumped) {
                vtableDumped = 1;
                HMODULE gameBase = GetModuleHandleA(NULL);
                UINT64 base = (UINT64)gameBase;
                BYTE *host = (BYTE*)recvHostStruct;

                Log("  REAL HOST struct at %p:", host);
                Log("    +0x08 qword: 0x%llX", *(UINT64*)(host + 8));
                Log("    +0x20 qword: 0x%llX", *(UINT64*)(host + 0x20));
                Log("    +0x38 socket: %llu", *(UINT64*)(host + 0x38));

                // plVar15 = *(host+0x20) — NOW CONFIRMED NON-NULL!
                void *plVar15 = *(void**)(host + 0x20);
                Log("    plVar15 = %p (from host+0x20)", plVar15);
                if (!plVar15 || IsBadReadPtr(plVar15, 0x98)) {
                    plVar15 = (void*)(host + 8);
                    Log("    fallback to host+8");
                }

                void *vtable = *(void**)plVar15;
                if (vtable && !IsBadReadPtr(vtable, 0x48)) {
                    void *fn28 = *(void**)((BYTE*)vtable + 0x28);
                    void *fn18 = *(void**)((BYTE*)vtable + 0x18);
                    Log("  REAL VTABLE at %p:", vtable);
                    Log("    [0x18] = %p (RVA 0x%llX)", fn18, (UINT64)fn18 - base);
                    Log("    [0x28] = %p (RVA 0x%llX) ← HANDLER", fn28, (UINT64)fn28 - base);
                }

                // Also dump critical offsets
                Log("    +0x120 byte: %d", host[0x120]);
                Log("    +0x138 qword: %llu", *(UINT64*)(host + 0x138));
                Log("    +0x144 ushort: %u", *(USHORT*)(host + 0x144));
                Log("    +0x146 ushort: %u", *(USHORT*)(host + 0x146));
                Log("    +0x178 uint: %u", *(UINT32*)(host + 0x178));

                // Queue object at plVar15 (the REAL handler object)
                BYTE *queue = (BYTE*)plVar15;
                Log("    QUEUE: paused=*(+0x18)=%d capacity=*(+0x80)=%llu writeIdx=*(+0x88)=%llu count=*(+0x90)=%llu",
                    queue[0x18],
                    *(UINT64*)(queue + 0x80),
                    *(UINT64*)(queue + 0x88),
                    *(UINT64*)(queue + 0x90));
            }
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

            // === USE CLIENT'S OWN DECRYPT FUNCTION ===
            // FUN_1410f2a10(bf_ctx, data, len, mode=2) is BF_cfb64_decrypt
            // We call it on a COPY to see what the client would see after decryption
            // Log queue state periodically
            {
                static int queueLogCount = 0;
                if (recvHostStruct && queueLogCount < 30) {
                    queueLogCount++;
                    BYTE *host2 = (BYTE*)recvHostStruct;
                    void *pv = *(void**)(host2 + 0x20);
                    BYTE *qp = pv ? (BYTE*)pv : host2 + 8;
                    if (!IsBadReadPtr(qp, 0x98)) {
                        UINT64 cap = *(UINT64*)(qp + 0x80);
                        UINT64 cnt = *(UINT64*)(qp + 0x90);
                        Log("  QUEUE #%d: paused=%d cap=%llu count=%llu",
                            queueLogCount, qp[0x18], cap, cnt);

                        // Dump slot 0 always
                        if (cap > 0) {
                            BYTE **slotArray = *(BYTE***)(qp + 0x78);
                            UINT64 slot = 0;
                            BYTE *slotData = NULL;
                            if (slotArray && !IsBadReadPtr(slotArray, cap * 8))
                                slotData = slotArray[0];
                            if (slotData && !IsBadReadPtr(slotData, 0x60)) {
                                    // Slot layout: [0x00] connID [0x0C] const=4 [0x10] CRC struct copy
                                    // CRC struct: +0x00 local_c8, +0x08 peerID(2B), +0x0A flags>>7, +0x0B cmd
                                    BYTE *crc = slotData + 0x10; // CRC struct starts at slot+0x10
                                    USHORT peerID = *(USHORT*)(crc + 8);
                                    BYTE sentTime = crc[0x0A];
                                    BYTE cmd = crc[0x0B];
                                    USHORT payLen = *(USHORT*)(crc + 0x52);
                                    Log("  SLOT[%llu]: connID=%llu peerID=0x%04X cmd=%d sentTime=%d payLen=%d",
                                        slot, *(UINT64*)slotData, peerID, cmd, sentTime, payLen);
                                    // Dump first 32 bytes of slot
                                    Log("    [0x00-0x1F]: %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X",
                                        slotData[0], slotData[1], slotData[2], slotData[3],
                                        slotData[4], slotData[5], slotData[6], slotData[7],
                                        slotData[8], slotData[9], slotData[10], slotData[11],
                                        slotData[12], slotData[13], slotData[14], slotData[15],
                                        slotData[16], slotData[17], slotData[18], slotData[19],
                                        slotData[20], slotData[21], slotData[22], slotData[23],
                                        slotData[24], slotData[25], slotData[26], slotData[27],
                                        slotData[28], slotData[29], slotData[30], slotData[31]);
                                    // Dump payload from CRC struct
                                    BYTE *payPtr = *(BYTE**)(crc + 0x48);
                                    if (payLen > 0 && payPtr && !IsBadReadPtr(payPtr, payLen < 32 ? payLen : 32)) {
                                        int dumpLen = payLen < 16 ? payLen : 16;
                                        char hex[128]; int hoff = 0;
                                        for (int b = 0; b < dumpLen; b++)
                                            hoff += snprintf(hex+hoff, sizeof(hex)-hoff, "%02X ", payPtr[b]);
                                        Log("    PAYLOAD[%d]: %s", payLen, hex);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if (lastSendLen > 8) {  // Echo mode active
                static int eCount = 0;
                static int keycheckSent = 0;
                eCount++;

                // Phase 1: Echo for first 20 packets (establish connection)
                // Phase 2: After echo, inject KeyCheck
                if (eCount <= 20 || keycheckSent >= 5) {
                    // Echo mode
                    int echoLen = lastSendLen - 8;
                    if (echoLen > 0 && echoLen <= len) {
                        memcpy(buf, lastSendBuf + 8, echoLen);
                        r = echoLen;
                        if (eCount <= 30)
                            Log("  ECHO #%d: %dB", eCount, r);
                    }
                } else if (keycheckSent < 5) {
                    // Inject KeyCheck using client's own encrypt functions
                    HMODULE gameBase = GetModuleHandleA(NULL);
                    typedef void (*bf_cfb_enc_t)(void* ctx, BYTE* data, USHORT len, int mode);
                    typedef int (*crc_fn_t)(BYTE *param);
                    bf_cfb_enc_t BfCfbEnc = (bf_cfb_enc_t)((BYTE*)gameBase + 0x10F41E0);
                    crc_fn_t CrcFn = (crc_fn_t)((BYTE*)gameBase + 0x577f10);

                    // Find BF context
                    void *bfCtx = NULL;
                    if (connStructAddr && !IsBadReadPtr((void*)(connStructAddr + 0x120), 16)) {
                        BYTE *cryptoBase = (BYTE*)connStructAddr + 0x120;
                        if (cryptoBase[0] != 0) {
                            void **treePtr = (void**)(cryptoBase + 8);
                            if (!IsBadReadPtr(treePtr, 8) && *treePtr) {
                                BYTE *rootNode = (BYTE*)(*(void**)(*treePtr));
                                if (!IsBadReadPtr(rootNode, 0x30)) {
                                    UINT64 nodeKey = *(UINT64*)(rootNode + 0x20);
                                    if (nodeKey == 1)
                                        bfCtx = *(void**)(rootNode + 0x28);
                                }
                            }
                        }
                    }

                    if (bfCtx) {
                        keycheckSent++;
                        // Build KeyCheck payload:
                        // ENet SEND_RELIABLE body after CRC header
                        BYTE kcPayload[22]; // channel(1)+seqNo(2)+dataLen(2)+keycheck(16)+pad(1)
                        memset(kcPayload, 0, sizeof(kcPayload));
                        kcPayload[0] = 0x00;  // channelID = 0
                        kcPayload[1] = 0x00; kcPayload[2] = 0x01;  // reliableSeqNo = 1 (BE)
                        kcPayload[3] = 0x00; kcPayload[4] = 0x10;  // dataLen = 16 (BE)
                        // KeyCheck: [4B opcode LE][1B playerNo][3B pad][8B checksum]
                        kcPayload[5] = 0x64; kcPayload[6] = 0x00; kcPayload[7] = 0x00; kcPayload[8] = 0x00; // opcode=100 LE
                        kcPayload[9] = 0x00;   // playerNo = 0
                        // rest is zeros (checksum)

                        // Build CRC struct for nonce
                        BYTE crcBuf[0x60];
                        memset(crcBuf, 0, sizeof(crcBuf));
                        *(UINT64*)(crcBuf + 0x00) = 1;
                        *(UINT64*)(crcBuf + 0x18) = 0xFFFFFFFFFFFFFFFF;
                        *(UINT16*)(crcBuf + 0x08) = 0;  // peerID

                        // Include payload in CRC
                        static BYTE payBuf[64];
                        int payLen = 21; // 1+2+2+16 = channel+seq+len+data
                        memcpy(payBuf, kcPayload, payLen);
                        *(UINT64*)(crcBuf + 0x48) = (UINT64)payBuf;
                        *(UINT16*)(crcBuf + 0x52) = (UINT16)payLen;

                        int crcNonce = CrcFn(crcBuf);
                        Log("  KEYCHECK CRC nonce = 0x%08X", (UINT32)crcNonce);

                        // Build plaintext: [2B peerID][4B nonce][1B flags][payload]
                        int ptLen = 2 + 4 + 1 + payLen; // 28 bytes
                        BYTE pt[32];
                        memset(pt, 0, 32);
                        pt[0] = 0x00; pt[1] = 0x00;  // peerID = 0
                        *(UINT32*)(pt + 2) = (UINT32)crcNonce;
                        pt[6] = 0x06;  // flags = SEND_RELIABLE (cmd=6)
                        memcpy(pt + 7, kcPayload, payLen);

                        // Double CFB encrypt with client's function
                        BYTE enc[32];
                        memcpy(enc, pt, ptLen);
                        BfCfbEnc(bfCtx, enc, (USHORT)ptLen, 2);
                        for (int i = 0; i < ptLen/2; i++) {
                            BYTE tmp = enc[i]; enc[i] = enc[ptLen-1-i]; enc[ptLen-1-i] = tmp;
                        }
                        BfCfbEnc(bfCtx, enc, (USHORT)ptLen, 2);

                        // Inject: 4B preamble + encrypted
                        memset(buf, 0, 4);
                        memcpy(buf + 4, enc, ptLen);
                        r = 4 + ptLen;
                        Log("  INJECTED KeyCheck #%d: %dB (nonce=0x%08X)", keycheckSent, r, (UINT32)crcNonce);
                    } else {
                        // Fallback: echo
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

    // DON'T hook send/WSASend/connect — they break SSL/TLS
    // Only log connect calls for debugging (without hooking)
    Log("Not hooking send/WSASend/connect (TCP) to avoid breaking SSL");
    Log("Only UDP hooks active: sendto, recvfrom, WSASendTo, WSARecvFrom");
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);

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
