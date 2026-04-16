@echo off
set JAVA_HOME=D:\LeagueOfLegendsV2\jdk21\jdk-21.0.10+7
set PATH=%JAVA_HOME%\bin;%PATH%
echo Testing java...
java -version
echo.
echo Launching Ghidra...
call "D:\LeagueOfLegendsV2\ghidra\ghidra_11.3.2_PUBLIC\ghidraRun.bat"
pause
