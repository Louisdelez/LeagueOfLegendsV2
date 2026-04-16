@echo off
echo ============================================
echo   LoL Crypto Debugger (ScyllaHide + x64dbg)
echo ============================================
echo.

echo [1/3] Starting game server...
start "LoL Server" cmd /c "cd /d D:\LeagueOfLegendsV2\server\src\LoLServer.Console && dotnet run -- --modern"
timeout /t 5 /nobreak >nul

echo [2/3] Launching x64dbg with ScyllaHide...
echo.
echo === INSTRUCTIONS ===
echo.
echo 1. x64dbg va s'ouvrir. Attends que le client se charge.
echo.
echo 2. Dans le menu: Plugins ^> ScyllaHide ^> Options
echo    Coche TOUT (NtSetInformationThread, NtQueryInformationProcess, etc.)
echo    Clique "Apply" puis ferme la fenetre options.
echo.
echo 3. Dans la barre de commande en bas, tape:
echo       bp ws2_32.WSASendTo
echo    Puis appuie Entree.
echo.
echo 4. Appuie F9 (Run) pour lancer le client.
echo.
echo 5. Quand le breakpoint s'active sur WSASendTo:
echo    - RCX = socket
echo    - RDX = pointeur vers WSABUF (buffer des donnees)
echo    - Regarde le buffer: c'est le paquet AVANT envoi
echo    - Fais "Step Out" (Ctrl+F9) pour remonter au code appelant
echo    - Note l'adresse de retour dans la call stack
echo.
echo 6. Fais un screenshot de la call stack et du buffer!
echo.
echo =====================
echo.
pause

start "" "D:\LeagueOfLegendsV2\x64dbg\release\x64\x64dbg.exe"

echo.
echo x64dbg est ouvert.
echo Dans x64dbg: File ^> Open ^> D:\LeagueOfLegendsV2\client-private\Game\LoLPrivate.exe
echo.
echo Arguments (copie-colle):
echo "127.0.0.1 5119 17BLOhi6KZsTtldTsizvHg== 1" "-Product=LoL" "-PlayerID=1" "-GameID=1" "-PlayerNameMode=ALIAS" "-LNPBlob=N6oAFO++rd4=" "-GameBaseDir=D:\LeagueOfLegendsV2\client-private" "-Region=EUW" "-PlatformID=EUW1" "-Locale=fr_FR" "-SkipBuild" "-EnableCrashpad=false" "-RiotClientPort=51843" "-RiotClientAuthToken=test"
echo.
echo Working Directory: D:\LeagueOfLegendsV2\client-private\Game
echo.
pause
