# League of Legends Private Server

A private server emulator for League of Legends (patch 16.6), compatible with the real modern LoL client.

> **Status:** Encryption cracked, CRC nonce computed, pending runtime patch for full connection

## What Works

- Client launches and connects to our server (reaches "Hard Connect" state)
- Full Blowfish Double CFB encryption/decryption (verified byte-for-byte)
- Echo handshake completes (519 -> 119 -> 64 -> 34 -> 27 -> 19B sequence)
- CRC-32/MPEG-2 nonce computation reverse-engineered from Ghidra
- Network packet capture via custom DLL hook (`version.dll` proxy)
- Game logic ready: 165 champions, 138 items, spells, jungle, vision, buffs

## What's In Progress

- Runtime CRC bypass via Cheat Engine kernel driver (pending reboot)
- Once CRC bypassed: game initialization packets (KeyCheck, StartGame, etc.)

## Protocol (Fully Reverse-Engineered)

| Layer | Description |
|-------|-------------|
| Transport | UDP via `sendto` in `ws2_32.dll` |
| Framing | LENet (ENet fork), big-endian, 519-byte client packets |
| Encryption | **Blowfish Double CFB** (encrypt -> reverse ALL bytes -> encrypt), IV=0 |
| Key | From `gameconfig.json`: `17BLOhi6KZsTtldTsizvHg==` (base64, 16 bytes) |
| Integrity | CRC-32/MPEG-2 nonce in packet header, polynomial `0x04C11DB7` |
| Anti-cheat | `stub.dll` sets guard pages on `.text`, blocks all ring-3 memory writes |

### Packet Format

**Client -> Server:**
```
[4B magic 0x37AA0014][4B sessionID LE][encrypted payload][2B footer EDF9]
```

**Server -> Client:**
```
Plaintext: [2B peerID LE][4B CRC_NONCE BE][1B flags][ENet commands...]
Encrypted: DoubleCfbEncrypt(plaintext)
Sent:      [4B connectToken BE (skipped by client)][encrypted bytes]
```

### CRC Nonce Computation

The CRC is computed over a **stack struct** (NOT the packet payload):

```
Init:  (byte[8] | 0xFFFFFF00) ^ 0xB1F740B4   (byte[8] = 0)
Feed:  byte[9]=0, bytes[0..7]=1 as int64 LE, 8x 0xFF
Nonce: ~crc = 0x8DFE1964
```

## Architecture

```
D:\LeagueOfLegendsV2\
|-- server/src/
|   |-- LoLServer.Console/     Game server + analysis tools
|   |-- LoLServer.Core/        Network, protocol, game logic
|   |-- LoLServer.Launcher/    Client launcher
|
|-- nethook/                   C hook DLLs (version.dll proxy)
|   |-- version_proxy.c        sendto/recvfrom hooks, CRC struct dump, HW BP attempts
|   |-- fake_stub.c            Dummy anti-cheat (blocked by integrity check)
|
|-- ghidra_scripts/            Ghidra analysis scripts (Java)
|-- ce_kernel_patch.lua        Cheat Engine CRC bypass script
|-- start-client.bat           Client launcher with full arguments
|-- launch-game.bat            Simple client launcher
|
|-- client-private/Game/       Private copy of LoL client (not in repo)
```

## Tech Stack

- **Server:** C# .NET 8, Blowfish, CRC-32/MPEG-2
- **Hooks:** C (MinGW-w64), inline hooking on ws2_32.dll, VEH handler
- **Analysis:** Ghidra 11.3.2, Cheat Engine (kernel driver)
- **Client:** LoL 16.6 (private copy, separate from official install)

## Quick Start

### Prerequisites
- Windows 10/11
- .NET 8 SDK
- A copy of LoL client (patch 16.6) in `client-private/`
- MinGW-w64 (for compiling hook DLLs)
- Cheat Engine (for runtime CRC bypass)

### 1. Compile the hook DLL
```bash
cd nethook
gcc -shared -o version.dll version_proxy.c -lws2_32 -O2
cp version.dll ../client-private/Game/version.dll
```

### 2. Start the server
```bash
cd server/src/LoLServer.Console
dotnet run -- --rawudp
```

### 3. Launch the client
```powershell
cd client-private\Game
Start-Process -FilePath '.\League of Legends.exe' -ArgumentList '"127.0.0.1 5119 17BLOhi6KZsTtldTsizvHg== 1" "-Product=LoL" "-PlayerID=1" "-GameID=1" "-LNPBlob=N6oAFO++rd4=" "-GameBaseDir=D:\LeagueOfLegendsV2\client-private" "-Region=EUW" "-Locale=fr_FR" "-SkipBuild" "-EnableCrashpad=false"'
```

### 4. Patch CRC (Cheat Engine)
1. Open CE as admin, attach to `League of Legends.exe`
2. Settings -> Extra -> check "Read/Write Process Memory"
3. Table -> Show Cheat Table Lua Script
4. Paste `ce_kernel_patch.lua` content, click Execute

## Key Ghidra Functions

| Function | RVA | Role |
|----------|-----|------|
| `FUN_1405725f0` | 0x5725F0 | Recv decrypt + CRC validate |
| `FUN_140577f10` | 0x577F10 | CRC nonce computation |
| `FUN_140588f70` | 0x588F70 | Packet dispatcher (builds CRC stack struct) |
| `FUN_1410f2a10` | 0x10F2A10 | Double CFB decrypt (recv) |
| `FUN_1410f41e0` | 0x10F41E0 | Double CFB encrypt (send) |
| `FUN_14058ef90` | 0x58EF90 | Send wrapper (double CFB + byte reversal) |

## Important Notes

- **DO NOT** modify the official LoL installation or Vanguard
- The private client (`client-private/`) must be completely separate from the official install
- Cheat Engine's kernel driver requires disabling the Windows vulnerable driver blocklist
- This project is for educational/research purposes only

## License

MIT
