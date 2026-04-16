@echo off
REM LoL Private Server - Windows Client Launcher
REM Usage: start-client.bat [player_id]

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

REM Search for PRIVATE client first
SET GAME_DIR=
IF EXIST "%~dp0client-private\Game\League of Legends.exe" SET GAME_DIR=%~dp0client-private\Game
IF EXIST "%~dp0client\Game\League of Legends.exe" SET GAME_DIR=%~dp0client\Game

SET BASE_DIR=%~dp0client-private

IF "%GAME_DIR%"=="" (
    echo [ERROR] Could not find League of Legends.exe!
    pause
    exit /b 1
)

echo Found client: %GAME_DIR%
echo.

cd /d "%GAME_DIR%"

REM LNPBlob = base64([37AA0014][EFBEADDE]) = N6oAFO++rd4=
SET LNPBLOB=N6oAFO++rd4=

REM Build full argument list matching real client launch
SET ARGS="%SERVER_IP% %SERVER_PORT% %BLOWFISH_KEY% %PLAYER_ID%"
SET ARGS=%ARGS% "-Product=LoL"
SET ARGS=%ARGS% "-PlayerID=%PLAYER_ID%"
SET ARGS=%ARGS% "-GameID=1"
SET ARGS=%ARGS% "-PlayerNameMode=ALIAS"
SET ARGS=%ARGS% "-LNPBlob=%LNPBLOB%"
SET ARGS=%ARGS% "-GameBaseDir=%BASE_DIR%"
SET ARGS=%ARGS% "-Region=EUW"
SET ARGS=%ARGS% "-PlatformID=EUW1"
SET ARGS=%ARGS% "-Locale=fr_FR"
SET ARGS=%ARGS% "-SkipBuild"
SET ARGS=%ARGS% "-EnableCrashpad=false"

echo Launching League of Legends.exe...
echo Command: "League of Legends.exe" %ARGS%
echo.

start "" "League of Legends.exe" %ARGS%

echo Client launched! Check the server console for connection logs.
echo.
pause
