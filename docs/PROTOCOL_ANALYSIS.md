# LoL Private Server - Protocol Analysis Documentation

## Project Overview

Private server for League of Legends patch 16.6, using the real modern LoL client.
Stack: C# .NET 8, LENet, Blowfish, Wireshark, Ghidra, NetHook DLL

---

## Architecture

```
LoLPrivate.exe (game client)
    |
    +-- stub.dll (anti-debug, protection)
    +-- RiotGamesApi.dll (REST/WebSocket APIs, TCP networking)
    +-- version.dll (OUR hook - packet capture & analysis)
    |
    v
ws2_32.dll (Windows Sockets)
    |
    v
UDP to game server (port 5119)
```

---

## Protocol Format

### Packet Structure (519 bytes, client -> server)

```
[0-7]   Header/Checksum (8 bytes)
        - Private client: 00-00-00-00-00-00-00-00 (zeros)
        - Real client: LNPBlob (37-AA-00-14 + SessionID)

[8-14]  Constant per session (derived from Blowfish key)

[15]    Nonce/counter (varies per packet)

[16-516] Encrypted payload (ENet commands)

[517-518] Footer (sequence counter, reversed checksum bytes)
```

### Server Response (111 bytes)

```
[0-7]   LENet header (SessionID + PeerID + TimeSent, big-endian)
[8-108] Encrypted ENet commands
[109-110] Footer
```

### Handshake Sequence (from Wireshark capture)

```
C->S  519B   CONNECT (ENet connection request)
S->C  111B   VERIFY_CONNECT
C->S  519B   CONNECT (retry, normal)
S->C  111B   VERIFY_CONNECT
C->S   65B   KeyCheck / Session Init
C->S   34B   Handshake continuation
S->C  125B   Session Info
C->S   27B   ACK
S->C   19B   ACK
S->C   41B   Config
S->C  701B   Game Info (champions, map, skins)
S->C  500B+  Spawn Data (multiple packets)
```

---

## Encryption

### What We Know

| Finding | Source |
|---------|--------|
| Blowfish P-box in LoLPrivate.exe | Ghidra (offsets 0x19ECDC0, 0x1ADEE20) |
| BF_set_key at FUN_1410ec460 | Ghidra P-box xref |
| BF_encrypt at FUN_1410f25c0 | Ghidra call analysis |
| BF_cfb64_encrypt at FUN_1410f2ce0 | Ghidra decompile |
| OpenSSL EVP strings (BF-CBC, BF-CFB, BF-ECB, BF-OFB) | String search |
| BF functions are for SPECTATOR/REPLAY only | Call chain analysis |
| Game UDP sendto at LoLPrivate.exe +0x58ECBB | Runtime hook |
| Thread stack: LoLPrivate.exe -> ntdll (direct) | Stack trace |
| RiotGamesApi.dll handles TCP/WebSocket, NOT game UDP | Ghidra + objdump |

### What's Unknown

- The encryption algorithm for the game UDP handshake
- The key derivation for the encryption
- How the IV/nonce is computed per packet
- Whether the encryption is in LoLPrivate.exe or loaded dynamically

### Encryption is NOT:
- Blowfish ECB (tested, doesn't decode)
- Blowfish CBC/CFB/OFB with any standard IV (tested ~40 IVs)
- AES-GCM with the Blowfish key (tested)
- AES-CTR (tested)
- Plaintext ENet (no valid ENet commands found at any offset)

---

## Key Files

### Captures
| File | Description |
|------|-------------|
| `riot_game_capture.pcapng` | 67MB Wireshark capture of real Riot server |
| `riot_protocol/handshake_packets.txt` | First 50 packets in hex |
| `riot_protocol/blowfish_key.txt` | Game key + connection info |
| `client-private/Game/nethook_logs/` | Captured packets from private client |

### Ghidra Analysis
| File | Description |
|------|-------------|
| `ghidra_bf_output.txt` | P-box xrefs, BF_set_key decompiled |
| `ghidra_bf_callers.txt` | Full call chain of BF_set_key |
| `ghidra_bf_encrypt.txt` | BF_cfb64_encrypt + callers |
| `ghidra_network.txt` | Network functions with constant 519 |
| `ghidra_sendto.txt` | sendto callers in RiotGamesApi.dll |
| `ghidra_encrypt_layer.txt` | Callers of send functions |
| `ghidra_disasm_before.txt` | Assembly around sendto call |

### Source Code
| File | Description |
|------|-------------|
| `nethook/version_proxy.c` | Main hook DLL (packet capture + call stack) |
| `nethook/evp_hook.c` | P-box scanner |
| `nethook/no_encrypt.c` | Encryption bypass attempt |
| `server/src/LoLServer.Core/Network/RawGameServer.cs` | Game server |
| `server/src/LoLServer.Console/CryptoModeTest.cs` | Crypto mode tests |
| `server/src/LoLServer.Console/RiotProtocolDecoder.cs` | Packet decoder |
| `ghidra_scripts/*.java` | Ghidra analysis scripts |

### LENet (decompiled)
| File | Description |
|------|-------------|
| `lenet_decompiled/LENet/Version.cs` | Season 1-12 protocol versions |
| `lenet_decompiled/LENet/ProtocolHeader.cs` | Header format (big-endian) |
| `lenet_decompiled/LENet/Protocol.cs` | ENet commands (CONNECT, VERIFY, etc.) |
| `lenet_decompiled/LENet/Buffer.cs` | Big-endian read/write |

---

## Tools

| Tool | Location | Purpose |
|------|----------|---------|
| MinGW-w64 14.2 | `mingw64/` | C compiler for hook DLLs |
| Ghidra 11.3.2 | `ghidra/` | Binary analysis |
| Wireshark 4.6.4 | `C:\Program Files\Wireshark\` | Network capture |
| x64dbg + ScyllaHide | `x64dbg/` | Debugger (blocked by anti-debug) |
| Frida | pip package | Dynamic instrumentation (blocked) |
| JDK 21 | `jdk21/` | For Ghidra |
| Npcap | System | Packet capture driver |

---

## Game Keys (captured)

| Game | Key (base64) | Server | Port |
|------|-------------|--------|------|
| Private | `17BLOhi6KZsTtldTsizvHg==` | 127.0.0.1 | 5119 |
| Real #1 | `K4gyS9t7q4RaFM0VLUJFJg==` | 162.249.72.5 | 7350 |
| Real #2 | `jNdWPAc3Vb5AyjoYdkar/g==` | 162.249.72.5 | 7342 |

---

## LNPBlob

The LNPBlob is passed to the client via `-LNPBlob=<base64>` argument.

```
Decoded: [4 bytes magic: 37-AA-00-14] [4 bytes SessionID]
Example: N6oAFLLMbKo= -> 37-AA-00-14-B2-CC-6C-AA
```

The client uses the LNPBlob to fill the first 8 bytes of each packet.

---

## LENet Protocol Versions

| Version | MaxPeerID | ChecksumSend | ChecksumRecv | HeaderBase | Era |
|---------|-----------|-------------|-------------|-----------|-----|
| Season12 | 32767 | 0 | 0 | 8 | Current |
| Season8_Client | 127 | 8 | 0 | 4 | S8+ |
| Season8_Server | 127 | 0 | 8 | 4 | S8+ |
| Patch420 | 127 | 4 | 4 | 4 | S4 |
| Season34 | 127 | 0 | 0 | 4 | S3-4 |
| Season12 | 32767 | 0 | 0 | 8 | S1-2 |

All values are big-endian. Header structure:
- MaxPeerID > 127: `[4B SessionID][2B PeerID|Flag][2B TimeSent]`
- MaxPeerID <= 127: `[1B SessionID][1B PeerID|Flag][2B TimeSent]`

---

## Next Steps

1. **Complete Ghidra full analysis** of LoLPrivate.exe (in progress)
2. **Find the enqueue function** that writes encrypted packets to the send buffer
3. **Hook the enqueue function** to capture plaintext before encryption
4. **Implement the encryption** in our server once understood
5. **Complete the handshake** and proceed to game data exchange
