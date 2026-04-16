@echo off
REM Read FakeLCU port
set /p LCUPORT=<"D:\LeagueOfLegendsV2\fakeLcu.port"
echo FakeLCU port: %LCUPORT%

cd /d "D:\LeagueOfLegendsV2\client-private\Game"

start "" "League of Legends.exe" "127.0.0.1 5119 17BLOhi6KZsTtldTsizvHg== 1" "-Product=LoL" "-PlayerID=1" "-GameID=1" "-PlayerNameMode=ALIAS" "-LNPBlob=N6oAFO++rd4=" "-GameBaseDir=D:\LeagueOfLegendsV2\client-private" "-Region=EUW" "-PlatformID=EUW1" "-Locale=fr_FR" "-SkipBuild" "-EnableCrashpad=false" "-RiotClientPort=%LCUPORT%" "-RiotClientAuthToken=PrivateServerToken123"

echo Client launched with RiotClientPort=%LCUPORT%
