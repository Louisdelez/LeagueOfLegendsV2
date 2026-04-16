#!/bin/bash
# Starts the LeagueSandbox GameServer (patch 4.20) on port 5119.
# Config is in GameServerConsole/bin/Debug/net8.0/Settings/GameInfo.json

set -e
cd "$(dirname "$0")/GameServer/GameServerConsole/bin/Debug/net8.0"
exec dotnet GameServerConsole.dll "$@"
