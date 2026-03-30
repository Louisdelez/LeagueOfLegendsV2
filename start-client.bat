@echo off
REM LoL Private Server - Windows Client Launcher
REM Copy the client/Game/ folder to Windows and run this script

SET SERVER_IP=127.0.0.1
SET SERVER_PORT=5119
SET BLOWFISH_KEY=17BLOhi6KZsTtldTsizvHg==
SET PLAYER_ID=1

echo =========================================
echo   LoL Private Server - Client Launcher
echo =========================================
echo.
echo Server: %SERVER_IP%:%SERVER_PORT%
echo Player ID: %PLAYER_ID%
echo.

REM If running on the same machine as the server
cd /d "%~dp0client\Game"

echo Launching League of Legends.exe...
start "" "League of Legends.exe" "8394" "LoLLauncher.exe" "" "%SERVER_IP% %SERVER_PORT% %BLOWFISH_KEY% %PLAYER_ID%"

echo.
echo Client launched! Check the server console for connection logs.
pause
