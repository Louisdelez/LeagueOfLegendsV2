# LoL 7.13 — pre-Vanguard reverse engineering track

Downloaded archive: `Client/client_full.7z` (5.5 GB, from Archive.org).
Confirmed version **patch 7.13 (July 5, 2017)** via `system.yaml` containing
`build.branch: '7.13'`.

## Why this track exists

The archive turned out to be 7.13 instead of the expected 4.20. Rather
than discard it, we use it as a **third track** with its own rationale:

- **Pre-Vanguard** (Vanguard didn't ship for LoL until Jan 2024 / patch 14.2)
  → `.text` patching works, runtime hooks work, unlike on 16.6
- **More modern content** than 4.20 (new champions, items, runes from 2014→2017)
- **Community protocol knowledge** from LeagueSandbox 4.20 era still
  partially applies (same crypto family, similar ENet framing)

## Game content in 7.13 that didn't exist in 4.20

Champions added 2014-2017 that will be present:
Bard, Ekko, Kalista, Tahm Kench, Kindred, Illaoi, Jhin, Aurelion Sol,
Taliyah, Kled, Ivern, Camille, Rakan, Xayah, Kayn, Ornn + reworks of
Fiddlesticks, Sion, Skarner, Warwick, Galio, Urgot.

Also: Runes Reforged (2017), modernized item shop (2016-2017 meta),
updated Summoner's Rift visuals (2014 → full 2017).

## Plan

1. **Extract** the archive (in progress / done)
2. **Identify key binaries** — `League of Legends.exe`, `LeagueClient.exe`,
   `lol_launcher.exe`, etc.
3. **Launch attempt** with 4.20-style args (`IP PORT BF_KEY PLAYER_ID`):
   - If the command line works → LeagueSandbox 4.20 server might partially
     function (handshake at least)
   - If the client expects different args → need to reverse the launcher
4. **Observe** connection behaviour:
   - Crypto key exchange (Blowfish variant?)
   - CRC layer (same bytewise CRC32?)
   - ENet frame format
5. **Port `16.6/nethook`** to 7.13 target:
   - Strip Vanguard workarounds (not needed)
   - Adjust RVAs (binary is different)
   - Test `.text` patches directly — they will succeed
6. **Adapt LeagueSandbox** (`../4.20/GameServer/`) to emit 7.13-compatible
   packets if differences are small, OR write a new server layer

## Directory structure (target)

```
7.13/
├── Client/
│   ├── client_full.7z          (5.5 GB, kept as backup)
│   └── League Of Legends/       (extracted, 15-20 GB)
│       ├── LeagueClient.exe     (LCU, for login/matchmaking)
│       ├── RADS/
│       │   └── projects/lol_game_client/releases/.../deploy/
│       │       └── League of Legends.exe  (the in-game engine)
│       └── Config/
├── nethook/                     (hook DLL, clone of 16.6 adjusted for 7.13)
├── server/                      (server layer, if we write a custom one)
└── README.md
```
