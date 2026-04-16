# LENet patched for LoL 7.13

Fork of `moonshadow565/LENet` with a new `Version.Patch713` variant.

## Why

`Version.Patch420` (checksum 4/4) and `Version.Seasson8_Server` (0/8) both
let the 7.13 client partially handshake:

- **Patch420** rejects incoming CONNECT silently — header parse fails
  because client prepends 8 bytes, not 4.
- **Seasson8_Server** accepts the CONNECT (header skip of 8 bytes matches),
  but its replies use `ChecksumSizeSend=0` → no leading 8-byte prefix in
  the outgoing VerifyConnect → 7.13 client rejects as malformed.

`Version.Patch713 = new Version(0x7F, 8, 8, 4, 0xFFFFFFFF, 0xFFFFFFFF)`
is symmetric: 8 bytes reserved on both send and receive, matching what
the 7.13 client does on its side.

## Verified

With `Version.Patch713`, the 7.13 client completes the ENet handshake:
1. Client CONNECT (52B) → server HandleConnect returns 0
2. Server sends VerifyConnect
3. **Client sends Acknowledge** ← first time past the retransmit loop
4. Steady-state Ping/Acknowledge exchange (~15 Hz) for the rest of the
   session, no retransmit spam.

Captured over ~12 s: 184 Ping, 186 Acknowledge, 2 Connect.

Game-layer content still doesn't flow (LeagueSandbox emits 4.20-era
KeyCheck/StartGame payloads that 7.13 doesn't parse), but the transport
is solved.

## How to rebuild

```bash
cd 4.20/LENet-patched
dotnet build -c Release
cp bin/Release/netstandard2.0/LENet.dll ~/.nuget/packages/lenet/1.0.1/lib/netstandard2.0/LENet.dll
# then rebuild the solution that depends on the NuGet package
cd ../GameServer
dotnet build GameServer.sln -c Debug
```

After each `dotnet build GameServer.sln`, the NuGet-provided DLL gets
copied into `GameServerConsole/bin/.../LENet.dll`. Since we replaced the
NuGet cache, that copy carries our patch.
