# LoL Private Server - Protocol Analysis Documentation

## Project Overview

Private server for League of Legends patch 16.6, using the real modern LoL client.
Stack: C# .NET 8, Blowfish Double CFB, CRC-32/MPEG-2, Ghidra, Cheat Engine

---

## Architecture

```
League of Legends.exe (game client)
    |
    +-- stub.dll (anti-cheat: guard pages on .text, blocks debug regs, Frida, etc.)
    +-- RiotGamesApi.dll (REST/WebSocket APIs, TCP networking only)
    +-- version.dll (OUR hook - packet capture, CRC struct dump, HW BP attempts)
    |
    v
ws2_32.dll (Windows Sockets)
    |
    v
UDP to game server (port 5119)
```

---

## Encryption — FULLY REVERSE-ENGINEERED

### Algorithm: Blowfish Double CFB

| Property | Value |
|----------|-------|
| Algorithm | Blowfish CFB (OpenSSL-style) |
| Mode | **Double CFB**: encrypt → reverse ALL bytes → encrypt |
| Key | From `gameconfig.json`: `17BLOhi6KZsTtldTsizvHg==` (16 bytes, base64) |
| IV | 0 (zeroed, fresh for each packet) |
| Block processing | Only full 8-byte blocks (`len >> 3`), trailing bytes unprocessed |
| Byte order | **Big-endian** (confirmed by assembly analysis) |

### Double CFB Process

```
Encrypt (server → client):
  1. CFB_encrypt(plaintext, IV=0)  → intermediate
  2. Reverse ALL bytes of intermediate
  3. CFB_encrypt(reversed, IV=0)   → ciphertext

Decrypt (client → server):
  1. CFB_decrypt(ciphertext, IV=0) → reversed
  2. Reverse ALL bytes
  3. CFB_decrypt(unreversed, IV=0) → plaintext
```

### Key Ghidra Functions

| Function | RVA | Role |
|----------|-----|------|
| FUN_1410f2a10 | 0x10F2A10 | Double CFB decrypt (recv path) |
| FUN_1410f41e0 | 0x10F41E0 | Double CFB encrypt (send path) |
| FUN_1410f25c0 | 0x10F25C0 | BF_encrypt (single block, 8 bytes) |
| FUN_1410f2ce0 | 0x10F2CE0 | BF_cfb64_encrypt (CFB mode) |
| FUN_14058ef90 | 0x58EF90 | Send wrapper (double CFB + byte reversal) |
| FUN_14058af50 | 0x58AF50 | Recv loop (recvfrom at +0x58B093) |

### Verification

- P-box and S-box extracted from runtime memory match our Blowfish implementation **byte-for-byte**
- Double CFB encrypt/decrypt roundtrip on captured client data: **PERFECT**
- BF_encrypt(zeros) = `F9 ED 26 C0 F2 2A 52 B4` (used for XOR decryption logging)

---

## CRC-32/MPEG-2 Integrity Check

### Overview

Every server → client packet contains a 4-byte CRC nonce. The client computes an expected nonce from its internal state and compares. Mismatch = packet rejected silently.

### CRC Parameters

| Parameter | Value |
|-----------|-------|
| Polynomial | `0x04C11DB7` (MPEG-2, MSB-first, non-reflected) |
| Formula | `(crc << 8 \| byte) ^ TABLE[crc >> 24]` |
| Init | `(byte[8] \| 0xFFFFFF00) ^ 0xB1F740B4` |
| Final | `~crc` (bitwise NOT) |

### CRC Nonce Computation (FUN_140577f10)

The CRC is computed over a **stack struct** built in FUN_140588f70, NOT the packet payload.

**Stack struct layout** (param_1 of FUN_140577f10):

| Offset | Stack var | Size | Value | Source |
|--------|-----------|------|-------|--------|
| 0x00 | local_c8 | 8B | `*(conn + 0x138)` = 1 | Connection sequence counter |
| 0x08 | local_c0 | 8B | 0 | Stays 0 when local_c8 ≠ 0 |
| 0x18 | local_b0 | 8B | `0xFFFFFFFFFFFFFFFF` | Hardcoded init value |
| 0x48 | local_80 | 8B | NULL | Payload pointer (no payload) |
| 0x52 | — | 2B | 0 | Payload length |

**Processing order:**
1. Init: `(byte[8] | 0xFFFFFF00) ^ 0xB1F740B4` where byte[8] = 0
2. Feed byte[9] = 0
3. Feed bytes[0..7] = 1 as int64 LE = `01 00 00 00 00 00 00 00`
4. Feed 8 bytes from offset 0x18 = `FF FF FF FF FF FF FF FF`
5. No payload (payloadLen = 0)
6. Final: `~crc = 0x8DFE1964`

### CRC Validation (FUN_1405725f0)

```c
iVar20 = *(int *)(packet_data + offset);  // Read nonce from decrypted packet
iVar7 = FUN_140577f10(param_1);           // Compute expected nonce
return iVar20 == iVar7 & bVar17;          // Must match
```

**Patch target:** RVA `0x572827`
- Original: `44 3B E0 0F 94 C0` (CMP R12D,EAX; SETE AL)
- Patched:  `90 90 90 B0 01 90` (NOP*3; MOV AL,1; NOP) → always passes

---

## Packet Format

### Client → Server (519 bytes)

```
[0-3]   LNPBlob magic: 0x37AA0014
[4-7]   SessionID (little-endian): 0xDEADBEEF
[8-11]  Connection token: 0xEDE36B43 (constant per session)
[12-516] Encrypted payload (Double CFB)
[517-518] Footer: 0xEDF9
```

### Server → Client

```
Wire format:
  [4B connectToken BE] [encrypted data...]

Plaintext (before Double CFB):
  [2B peerID LE]        = 0x0000
  [4B CRC_NONCE BE]     = 0x8DFE1964
  [1B flags]            = command type (0x03=VERIFY_CONNECT, 0x05=PING, etc.)
  [NB ENet command body]
```

### Handshake Sequence

```
C→S  519B   CONNECT (ENet connection request, repeated every 500ms)
S→C   43B   VERIFY_CONNECT (Double CFB encrypted)
C→S  519B   (continues sending until VERIFY accepted)
C→S   65B   KeyCheck / Session Init
C→S   34B   Handshake continuation
S→C  125B   Session Info
C→S   27B   ACK
S→C   19B   ACK
S→C   41B   Config
S→C  701B   Game Info (champions, map, skins)
S→C  500B+  Spawn Data (multiple packets)
```

### Echo Mechanism

When the server echoes the client's own data back (bytes 8-518 of the 519B packet), the client accepts it via a **memcmp ring buffer bypass** that skips the CRC check entirely. This is how the current handshake works (echo mode).

---

## Anti-Cheat (stub.dll)

### Protections

| Protection | Description |
|-----------|-------------|
| Guard pages | Sets PAGE_GUARD on all `.text` sections → VirtualProtect fails with err=5 |
| Debug registers | Hooks GetThreadContext/SetThreadContext → returns FALSE for CONTEXT_DEBUG_REGISTERS |
| VEH intercept | Catches EXCEPTION_SINGLE_STEP before our handler |
| Frida block | Refuses to load frida-agent in both attach and spawn modes |
| WriteProcessMemory | VirtualProtectEx fails from external process |
| Binary integrity | Hash check on stub.dll → "Crash Dump" if modified on disk |
| Fake DLL detect | Game crashes immediately if stub.dll is replaced with a dummy |

### What Works Despite stub.dll

| Technique | Status |
|-----------|--------|
| version.dll proxy (IAT hook on ws2_32) | ✅ Works |
| Reading .text pages | ✅ Works (can verify bytes, just can't write) |
| Reading process memory (any offset) | ✅ Works |
| Cheat Engine kernel driver (dbk64.sys) | ✅ Bypasses all ring-3 protections |

---

## Key Files

### Source Code

| File | Description |
|------|-------------|
| `nethook/version_proxy.c` | Hook DLL: sendto/recvfrom hooks, CRC struct dump, register capture |
| `server/src/LoLServer.Core/Network/RawGameServer.cs` | Game server: encryption, CRC, packet handling |
| `server/src/LoLServer.Core/Network/BlowFish.cs` | Blowfish implementation (BE byte order) |
| `ce_kernel_patch.lua` | Cheat Engine Lua script for CRC bypass |
| `ghidra_scripts/*.java` | Ghidra analysis scripts |

### Ghidra Analysis Outputs

| File | Description |
|------|-------------|
| `ghidra_nonce_full.txt` | FUN_140577f10 (CRC nonce) decompilation + assembly |
| `ghidra_5725f0.txt` | FUN_1405725f0 (recv handler) decompilation |
| `ghidra_588f70.txt` | FUN_140588f70 (packet dispatcher) decompilation |
| `ghidra_crypt_func.txt` | Double CFB encrypt function |
| `ghidra_sendto.txt` | sendto caller analysis |

---

## Game Keys

| Context | Key (base64) | Server | Port |
|---------|-------------|--------|------|
| Private server | `17BLOhi6KZsTtldTsizvHg==` | 127.0.0.1 | 5119 |
| Real game #1 | `K4gyS9t7q4RaFM0VLUJFJg==` | 162.249.72.5 | 7350 |
| Real game #2 | `jNdWPAc3Vb5AyjoYdkar/g==` | 162.249.72.5 | 7342 |

---

## Connection Struct (Runtime)

Captured via RBX register in sendto hook. Address changes each session.

| Offset | Size | Description |
|--------|------|-------------|
| 0x120 | 8B+ | Crypto context map (std::map with BF keys, TREE_KEY=1) |
| 0x138 | 8B | Connection sequence counter (= 1 after first connect) |
| 0x144 | 2B | Value 0x0004 |
| 0x146 | 2B | Value 0x0000 |

---

## LNPBlob

Passed to client via `-LNPBlob=<base64>` argument.

```
Format: [4B magic: 37-AA-00-14] [4B SessionID LE]
Example: N6oAFO++rd4= → 37-AA-00-14-EF-BE-AD-DE (SessionID = 0xDEADBEEF)
```

The client uses the LNPBlob to fill the first 8 bytes of each outgoing packet.

---

## Next Steps

1. **Reboot PC** (registry change for CE kernel driver takes effect)
2. **Patch CRC check** via Cheat Engine kernel driver at RVA 0x572827
3. **Verify server packets accepted** (client progresses past "Hard Connect")
4. **Send game init packets**: KeyCheck, StartGame, champion spawn data
5. **Reach loading screen** and beyond
