@echo off
echo === Starting Server ===
start "LoL Server" cmd /c "cd /d D:\LeagueOfLegendsV2\server\src\LoLServer.Console && dotnet run -- --modern"
timeout /t 5

echo === Starting x64dbg with client ===
start "" "D:\LeagueOfLegendsV2\x64dbg\release\x64\x64dbg.exe" "D:\LeagueOfLegendsV2\client-private\Game\LoLPrivate.exe"

echo.
echo x64dbg is open. In the command bar at the bottom:
echo   1. Type: bp ws2_32.recvfrom
echo   2. Press F9 to run
echo   3. When it breaks on recvfrom after receiving our VERIFY:
echo      - Check the buffer (arg2) for our response bytes
echo      - Step out (Ctrl+F9) to see which function processes it
echo      - Look at the call stack for Blowfish/decrypt references
echo.
pause
