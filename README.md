# League of Legends Private Server

A private server emulator for League of Legends (patch 16.6), compatible with the real modern LoL client.

> **Status:** Game alive 2+ min, 3800+ packets exchanged, opcode table extracted. Two blockers remain: TLS cert verify (Vanguard blocks all bypass) and packet framing (game data doesn't reach dispatcher).

## What Works

- Client launches, connects, and **stays alive indefinitely** (2+ minutes confirmed)
- Full Blowfish Double CFB encryption/decryption (game's own BF context)
- CRC-32 nonce computed by game's own function — **CRC PASS on every packet**
- Echo handshake + CAFE delivery (server→client game data)
- FLOW state machine bypassed (`flowPtr+8 = 1`)
- Game state progression: `Bootstrap → Patching → LoLCommon → GameSession → Hard Connect`
- **Full opcode table extracted at runtime** — 22 primary + 40 secondary opcodes
- Proper CA + server cert chain (CA:TRUE, SAN=localhost, verified OK)
- 15 TLS bypass approaches tested and documented
- Hardware breakpoint CRC bypass via VEH (Vanguard-compatible)

## What's Left

| Blocker | Status | Details |
|---------|--------|---------|
| TLS cert verify | **Exhausted** | 15 approaches tried. Vanguard blocks .text + .rdata patches, HW breakpoints, debug registers. BoringSSL ignores SSL_CERT_FILE. Game runs without LCU but loading screen may need it. |
| Packet framing | **Active blocker** | Game data sent via cmd=2 doesn't reach the game's opcode dispatcher (RVA 0x955C20). Consumer expects 56-byte records with opcode at byte 50. Need real packet capture to reverse the exact framing. |
| Loading screen | Blocked by framing | Client sends 64+ opcodes but never SynchVersion (0x56). Server responds but client ignores — wrong framing. |

## Protocol (Fully Reverse-Engineered)

| Layer | Description |
|-------|-------------|
| Transport | UDP via `sendto` in `ws2_32.dll` |
| Framing | Modified ENet, 519-byte client packets with LNPBlob header |
| Encryption | **Blowfish Double CFB** (encrypt → reverse ALL bytes → encrypt), IV=0, block-based (full 8B blocks only) |
| Key | `17BLOhi6KZsTtldTsizvHg==` (base64, 16 bytes) |
| Integrity | CRC-32 nonce, polynomial `0x04C11DB7`, non-standard byte mixing: `(crc << 8 \| byte) ^ table[crc >> 24]` |
| Game data | cmd=2 → handler +0x168 (real), cmd=6 → handler +0x128 (stub) |
| Dispatcher | 22 primary opcodes (0x0A–0x103) + 40 secondary (0x10A–0x479), jump tables at 0x140957120 + 0x1409570C4 |
| Anti-cheat | Vanguard: guard pages on `.text`, blocks VirtualProtect + debug registers |

### Packet Format

**Client → Server (519B):**
```
[4B magic 0x37AA0014][4B sessionID LE][4B connToken (unencrypted)][Double-CFB encrypted: [4B CRC nonce][1B flags/cmd][body...]]
```

**Server → Client (via CAFE hook):**
```
Hook receives: [2B 0xCAFE][4B header][plaintext: [4B nonce placeholder][1B cmd][body...]]
Hook strips CAFE, computes CRC with game's function, encrypts with game's BF
Client sees:   [4B connToken][Double-CFB encrypted: [4B CRC nonce][1B cmd][body...]]
```

### CRC Nonce Computation

Computed by game function at RVA 0x577F10 over a stack struct:
```
crcStruct+0x00: local_c8 (from connStruct+0x138)
crcStruct+0x08: peerID_lo (from header byte 0)
crcStruct+0x09: peerID_hi (from header byte 1)
crcStruct+0x18: timestamp (0xFFFFFFFFFFFFFFFF)
crcStruct+0x48: pointer to payload (after flags byte)
crcStruct+0x52: payload length
```

### Game Init Sequence (Season 4 reference)

```
1. KeyCheck (channel 0, 32B)
2. QueryStatusReq (0x14) → QueryStatusAns (0x88)
3. SynchVersionC2S (0xBD) → SynchVersionS2C (0x54)
4. CharSelected (0xBE) → TeamRosterUpdate (0x67, channel 7)
5. ClientReady (0x52) → StartSpawn (0x62) + CreateHero (0x4C) + EndSpawn (0x11)
6. StartGame (0x5C) + SynchSimTime (0xC1)
```

## Architecture

```
D:\LeagueOfLegendsV2\
|-- server/src/
|   |-- LoLServer.Console/     Game server + analysis tools
|   |-- LoLServer.Core/        Network (RawGameServer), protocol, game logic
|
|-- nethook/                   C hook DLL (version.dll proxy)
|   |-- version_proxy.c        sendto/recvfrom hooks, CAFE CRC fixup, VEH HW breakpoint,
|   |                          FLOW patch, cert thread, client packet decryption
|
|-- docs/
|   |-- JOURNEY.md             Full reverse engineering journal (Phases 1-25)
|   |-- PROTOCOL_ANALYSIS.md   Protocol documentation
|
|-- launch-game.bat            Client launcher (without LCU)
|-- launch-game-lcu.bat        Client launcher (with FakeLCU port)
|-- start-server.bat           Server launcher
|
|-- client-private/Game/       Private copy of LoL client (not in repo)
```

## Tech Stack

- **Server:** C# .NET 8, Blowfish, CRC-32, Raw UDP + CAFE protocol
- **Hooks:** C (MinGW-w64), VEH handler, HW breakpoints, CAFE CRC fixup
- **Analysis:** Ghidra 11.3.2, ~100 scripts, binary pattern scanning
- **Client:** LoL 16.6 (private copy, separate from official install)

## Quick Start

### Prerequisites
- Windows 10/11
- .NET 8 SDK
- MinGW-w64 (MSYS2 mingw64)
- A copy of LoL client (patch 16.6) in `client-private/`

### 1. Compile the hook DLL
```bash
cd nethook
PATH="/c/msys64/mingw64/bin:$PATH" gcc -shared -o version.dll version_proxy.c -lws2_32 -ldbghelp
cp version.dll ../client-private/Game/version.dll
```

### 2. Start the server
```bash
cd server
dotnet run --project src/LoLServer.Console --configuration Release -- --rawudp
```

### 3. Launch the client
```batch
launch-game-lcu.bat
```

Or manually:
```powershell
cd client-private\Game
Start-Process "League of Legends.exe" '"127.0.0.1 5119 17BLOhi6KZsTtldTsizvHg== 1" "-Product=LoL" "-PlayerID=1" "-GameID=1" "-LNPBlob=N6oAFO++rd4=" "-GameBaseDir=D:\LeagueOfLegendsV2\client-private" "-Region=EUW" "-Locale=fr_FR" "-SkipBuild" "-EnableCrashpad=false"'
```

## Key Ghidra Functions

| Function | RVA | Role |
|----------|-----|------|
| CRC nonce | 0x577F10 | CRC-32 computation over stack struct |
| CRC check | 0x5725F0 | Recv decrypt + CRC validate |
| Packet handler | 0x588F70 | Dequeue + dispatch |
| Consumer | 0x5883D0 | Batch record → 56B internal struct |
| Enqueue | 0x573160 | Enqueue game data to consumer queue |
| Packet processor | 0x57AF90 | Parse raw packet → queue records |
| **Dispatcher** | **0x955C20** | **22+40 game opcodes, opcode at struct+0x08** |
| Opcode byte table | 0x957120 | 250 entries, maps opcode-0x0A → case index |
| Opcode offset table | 0x9570C4 | Case index → handler code offset |
| CFB decrypt | 0x10F2A10 | Double CFB decrypt (recv path) |
| ParseCert | 0x168A4F0 | d2i_X509 — parse DER cert, works from hooks |
| SSL_METHOD | 0x199D218 | TLS method struct (function ptrs to .text) |
| Riot CA DER | 0x19EEBD0 | Embedded root CA cert (1060B, PAGE_READONLY) |
| flowPtr | 0x1DA5228 | Global connection state pointer |
| CFB encrypt | 0x10F41E0 | Double CFB encrypt (send path) |
| ParseCert | 0x168A4F0 | BoringSSL d2i_X509 |
| flowPtr | 0x1DA5228 | FLOW state machine global |

## Important Notes

- **DO NOT** modify the official LoL installation or Vanguard
- The private client (`client-private/`) must be completely separate
- Vanguard runs alongside — we coexist, never interfere
- This project is for educational/research purposes only

## License

MIT
