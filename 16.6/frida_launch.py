#!/usr/bin/env python3
"""Launch LoLPrivate.exe with Frida instrumentation to capture crypto operations."""

import frida
import sys
import subprocess
import time
import os

GAME_EXE = r"D:\LeagueOfLegendsV2\client-private\Game\LoLPrivate.exe"
GAME_DIR = r"D:\LeagueOfLegendsV2\client-private\Game"
SCRIPT_PATH = r"D:\LeagueOfLegendsV2\frida_evp_hook.js"
LOG_PATH = r"D:\LeagueOfLegendsV2\frida_output.log"

GAME_ARGS = [
    "127.0.0.1 5119 17BLOhi6KZsTtldTsizvHg== 1",
    "-Product=LoL",
    "-PlayerID=1",
    "-GameID=1",
    "-PlayerNameMode=ALIAS",
    "-LNPBlob=N6oAFO++rd4=",
    "-GameBaseDir=D:\\LeagueOfLegendsV2\\client-private",
    "-Region=EUW",
    "-PlatformID=EUW1",
    "-Locale=fr_FR",
    "-SkipBuild",
    "-EnableCrashpad=false",
    "-RiotClientPort=51843",
    "-RiotClientAuthToken=test",
]

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[FRIDA] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[ERROR] {message['stack']}")
    else:
        print(f"[MSG] {message}")

    # Also log to file
    with open(LOG_PATH, "a") as f:
        f.write(f"{message}\n")

def main():
    print("=== Frida LoL Crypto Tracer ===")
    print(f"Game: {GAME_EXE}")
    print(f"Script: {SCRIPT_PATH}")
    print()

    # Read the Frida script
    with open(SCRIPT_PATH, "r") as f:
        script_code = f.read()

    # Clear log
    with open(LOG_PATH, "w") as f:
        f.write("=== Frida Log ===\n")

    # Spawn the process with Frida
    print("[*] Spawning LoLPrivate.exe with Frida...")
    try:
        pid = frida.spawn(GAME_EXE, argv=[GAME_EXE] + GAME_ARGS, cwd=GAME_DIR)
        print(f"[+] Spawned PID: {pid}")
    except Exception as e:
        print(f"[!] Spawn failed: {e}")
        print("[*] Trying to attach to existing process...")
        # Try attaching to an already-running process
        try:
            session = frida.attach("LoLPrivate.exe")
        except Exception as e2:
            print(f"[!] Attach failed too: {e2}")
            return
        pid = None

    if pid:
        session = frida.attach(pid)

    print("[*] Attaching script...")
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()

    if pid:
        print("[*] Resuming process...")
        frida.resume(pid)

    print("[*] Frida active. Press Ctrl+C to stop.")
    print()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping...")

    session.detach()
    print("[*] Done. Log saved to", LOG_PATH)

if __name__ == "__main__":
    main()
