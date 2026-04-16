# League of Legends V2 — dual-track repo

This repo contains **two parallel projects** for running League of Legends
outside Riot's official services.

## `16.6/` — Modern client reverse engineering

Reverse-engineering the current LoL client (version 16.6, post-Vanguard).

**Status:** research only. The modern client is protected by Vanguard at the
kernel level, and its gameplay packet format is completely undocumented in
public. We have:

- Working Blowfish double-CFB crypto layer
- CRC bypass on the specific instruction
- ENet handshake / VERIFY_CONNECT
- Game reaches `GameSession` state (stays alive 2+ min)
- Full opcode dispatcher table extracted (22 primary + 40 secondary)
- 7 FLOW states + Push function located
- 10 parser error codes mapped

We do **not** have a working game-data packet path — this is the wall that
has stopped every public project for 12 years. See the commits tagged
"Day 6…" for the latest reverse engineering progress.

## `4.20/` — LeagueSandbox-based private server

The realistic path to a **playable private LoL server**. Uses the
community-maintained LeagueSandbox / Fishbones C# server plus a patch-4.20
(2014) LoL client.

**Status:** setup in progress. See `4.20/README.md` for the install plan
(clone server, obtain client, configure `GameInfo.json`, launch).

Playable result: LoL as it was in 2014, including Summoner's Rift (5v5),
Twisted Treeline (3v3), and Dominion — the last two being game modes that
are no longer available on Riot's official servers.

## Why the two tracks coexist

- `16.6/` is frozen work we don't want to throw away: it's the current
  public frontier of modern-client reverse engineering, useful as
  research regardless of whether a playable server ever ships.
- `4.20/` is the pragmatic track: a working private server, today, with
  most of the champions/items of the 2014 patch.

Modern champions, items, and maps (post-2014) exist only on Riot's
servers and are not reproducible in any private server project in 2026.
