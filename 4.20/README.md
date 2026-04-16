# LoL 4.20 Private Server (LeagueSandbox-based)

Goal: a playable private server for LoL **patch 4.20 (October 2014)** using
the modern community stack (LeagueSandbox / Fishbones C# server + patch-4.20
client).

## Plan

1. **Server:** clone an active LeagueSandbox fork (Fishbones was updated
   2026-04-15). Install .NET 6+, restore NuGet, build.
2. **Client:** obtain a patch-4.20 `League of Legends.exe` + its `RADS/`
   game data from a community archive. ~3-5 GB total.
3. **Config:** edit `GameInfo.json` — players, champion picks, blowfish key,
   server IP/port, map ID (1=old SR, 8=Dominion, 10=Twisted Treeline,
   11=modern SR).
4. **Launch:** start server → launch client with
   `"League of Legends.exe" "8394" "LoLLauncher.exe" "" "IP PORT BLOWFISH_KEY PLAYER_ID"`.

## Supported maps

| Map | ID | Status |
|-----|:---:|---|
| Summoner's Rift (2014) | 11 | ★★★★★ — most tested |
| Twisted Treeline 3v3 | 10 | ★★★☆☆ — some bugs on Vilemaw/altars |
| Crystal Scar (Dominion) | 8 | ★★★☆☆ — capture points work, speed shrine buggy |
| Summoner's Rift (pre-2014) | 1 | mostly abandoned |
| Howling Abyss (ARAM) | 12 | limited support |

## What is and is not in 4.20

- ~120 champions (of the ~170 today). No post-2014 champions.
- Pre-Runes-Reforged rune system (you buy stat pages).
- Items are the 2014 set (no Mythics, no modern Trinity Force, etc.).
- Dominion and 3v3 Twisted Treeline are both available here and no longer
  exist on official servers.

## Next steps

Work lives here. The `16.6/` track is frozen research and does not move.
