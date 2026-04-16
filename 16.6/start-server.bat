@echo off
REM LoL Private Server - Windows Server Launcher
REM Usage: start-server.bat [--raw] [--modern] [--port=5119]
REM   --modern  : Raw UDP mode for modern LoL client (16.6+)
REM   --raw     : LENet mode with raw packet capture

echo =========================================
echo   LoL Private Server - Server Launcher
echo =========================================
echo.

REM Build
echo Building server...
dotnet build server\LoLServer.sln -c Debug
IF %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Build failed!
    pause
    exit /b 1
)
echo.

REM Run with all arguments passed through
echo Starting server...
echo.
dotnet run --project server\src\LoLServer.Console -- %*

pause
