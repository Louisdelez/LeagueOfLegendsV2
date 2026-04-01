@echo off
REM LoL Private Server - Windows Client Launcher
REM Usage: start-client.bat [player_id]
REM
REM This script searches for the League of Legends client in common locations.
REM Set GAME_DIR below if your client is in a custom location.

SET SERVER_IP=127.0.0.1
SET SERVER_PORT=5119
SET BLOWFISH_KEY=17BLOhi6KZsTtldTsizvHg==

REM Player ID (1st argument or default 1)
IF "%~1"=="" (SET PLAYER_ID=1) ELSE (SET PLAYER_ID=%~1)

echo =========================================
echo   LoL Private Server - Client Launcher
echo =========================================
echo.
echo Server: %SERVER_IP%:%SERVER_PORT%
echo Player ID: %PLAYER_ID%
echo Blowfish Key: %BLOWFISH_KEY%
echo.

REM Search for PRIVATE client first (separate from official install)
SET GAME_DIR=
IF EXIST "%~dp0client-private\Game\League of Legends.exe" SET GAME_DIR=%~dp0client-private\Game
IF EXIST "%~dp0client\Game\League of Legends.exe" SET GAME_DIR=%~dp0client\Game
IF EXIST "C:\Riot Games\League of Legends\Game\League of Legends.exe" SET GAME_DIR=C:\Riot Games\League of Legends\Game
IF EXIST "D:\Riot Games\League of Legends\Game\League of Legends.exe" SET GAME_DIR=D:\Riot Games\League of Legends\Game
IF EXIST "D:\Programm\Riot Games\League of Legends\Game\League of Legends.exe" SET GAME_DIR=D:\Programm\Riot Games\League of Legends\Game

IF "%GAME_DIR%"=="" (
    echo [ERROR] Could not find League of Legends.exe!
    echo.
    echo Searched in:
    echo   - %~dp0client\Game\
    echo   - C:\Riot Games\League of Legends\Game\
    echo   - D:\Riot Games\League of Legends\Game\
    echo   - D:\Programm\Riot Games\League of Legends\Game\
    echo.
    echo Edit this script and set GAME_DIR to your client's Game folder.
    pause
    exit /b 1
)

echo Found client: %GAME_DIR%
echo.

cd /d "%GAME_DIR%"

echo Launching League of Legends.exe...
echo Command: "League of Legends.exe" "8394" "LoLLauncher.exe" "" "%SERVER_IP% %SERVER_PORT% %BLOWFISH_KEY% %PLAYER_ID%"
echo.

start "" "League of Legends.exe" "8394" "LoLLauncher.exe" "" "%SERVER_IP% %SERVER_PORT% %BLOWFISH_KEY% %PLAYER_ID%"

echo Client launched! Check the server console for connection logs.
echo.
echo If the client doesn't connect, try:
echo   1. Make sure the server is running first (start-server.bat)
echo   2. Check Windows Firewall - allow UDP port %SERVER_PORT%
echo   3. Run with --raw flag on server for protocol analysis
echo.
pause
