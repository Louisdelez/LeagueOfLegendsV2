# League of Legends Private Server

A private server emulator for League of Legends (patch 16.6), compatible with the real modern LoL client.

> **Status:** Work in progress - Protocol reverse engineering phase

## What Works

- Client launches and connects to our server
- Network packet capture via custom DLL hook (`version.dll` proxy)
- Full Wireshark capture of real Riot server traffic (67MB)
- Ghidra analysis of game binary (Blowfish functions, network code)
- LENet protocol library decompiled (Season 1-12 formats)
- Game logic ready: 165 champions, 138 items, spells, jungle, vision, buffs

## What's In Progress

- Reverse engineering the packet encryption used by the modern client
- The handshake encryption algorithm is located but not yet decoded
- Full Ghidra analysis of LoLPrivate.exe running

## Architecture

```
D:\LeagueOfLegendsV2\
|-- server/src/
|   |-- LoLServer.Console/     Game server + analysis tools
|   |-- LoLServer.Core/        Network, protocol, game logic
|   |-- LoLServer.Launcher/    Client launcher (patches exe, sets up env)
|
|-- nethook/                   C hook DLLs (version.dll proxy)
|   |-- version_proxy.c        Main hook: packet capture + call stack tracing
|   |-- evp_hook.c             P-box memory scanner
|   |-- no_encrypt.c           Encryption bypass attempt
|
|-- ghidra_scripts/            Ghidra analysis scripts (Java)
|-- tools/PacketCapture/       Network capture tool (C# raw sockets)
|-- lenet_decompiled/          Decompiled LENet library
|-- docs/                      Documentation
|   |-- PROTOCOL_ANALYSIS.md   Technical protocol reference
|   |-- JOURNEY.md             Full reverse engineering journal
|
|-- client-private/Game/       Private copy of LoL client (not in repo)
|-- riot_protocol/             Captured packet data
```

## Tech Stack

- **Server:** C# .NET 8, LENet, BouncyCastle, Blowfish
- **Hooks:** C (MinGW-w64), inline hooking on ws2_32.dll
- **Analysis:** Ghidra 11.3.2, Wireshark 4.6.4, x64dbg + ScyllaHide
- **Client:** LoL 16.6 (patched, separate from official install)

## How It Works

1. **Launcher** patches the LoL client and launches it with our server's address
2. **version.dll** hook captures all network traffic between client and server
3. **Game server** handles the ENet protocol and game logic
4. The client expects encrypted communication - we're reverse engineering this

## Protocol Findings

The modern LoL client (Season 8+) uses a custom encryption layer:

| Layer | Description |
|-------|-------------|
| Transport | UDP via `sendto` in `ws2_32.dll` |
| Framing | LENet (ENet fork) Season 12, big-endian, 519-byte packets |
| Encryption | Unknown custom algorithm (NOT Blowfish ECB/CBC/CFB/OFB) |
| Blowfish | Used only for spectator/replay data, NOT for game UDP |

See [docs/PROTOCOL_ANALYSIS.md](docs/PROTOCOL_ANALYSIS.md) for full technical details.

See [docs/JOURNEY.md](docs/JOURNEY.md) for the complete reverse engineering journal.

## Quick Start

### Prerequisites
- Windows 10/11
- .NET 8 SDK
- A copy of LoL client (patch 16.6) in `client-private/`
- MinGW-w64 (for compiling hook DLLs)

### Run the server
```bash
cd server/src/LoLServer.Console
dotnet run -- --modern
```

### Launch the client
```bash
cd server/src/LoLServer.Launcher
dotnet run
```

### Compile the hook DLL
```bash
cd nethook
gcc -shared -o version.dll version_proxy.c -lws2_32 -O2
cp version.dll ../client-private/Game/version.dll
```

## Important Notes

- **DO NOT** modify the official LoL installation or Vanguard
- **DO NOT** use network capture tools (pktmon, etc.) while the official game is running (causes VAN 193)
- The private client (`client-private/`) must be completely separate from the official install
- This project is for educational/research purposes only

## License

MIT
