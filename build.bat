@echo off
REM pompom build script — Windows (MSVC or MinGW)
REM
REM Usage:
REM   build.bat                     Build native (auto-detect)
REM   build.bat --target x86_64     Build for x64
REM   build.bat --target x86_32     Build for x86
REM   build.bat --test              Build + run tests
REM   build.bat --clean             Clean build output
REM   build.bat --mingw             Force MinGW instead of MSVC
REM
REM Requires: Visual Studio Build Tools (cl.exe) or MinGW (gcc)
REM           NASM for x86 assembly (https://www.nasm.us)

setlocal enabledelayedexpansion
cd /d "%~dp0"

set "ACTION=build"
set "ARCH="
set "COMPILER=auto"
set "BUILDDIR=build\win"

REM ── Parse args ─────────────────────────────────────────────────────

:parse_args
if "%~1"=="" goto detect
if /i "%~1"=="--target"   ( set "ARCH=%~2" & shift & shift & goto parse_args )
if /i "%~1"=="--test"     ( set "ACTION=test" & shift & goto parse_args )
if /i "%~1"=="--clean"    ( if exist build rmdir /s /q build & echo cleaned. & exit /b 0 )
if /i "%~1"=="--mingw"    ( set "COMPILER=mingw" & shift & goto parse_args )
if /i "%~1"=="--help"     ( goto usage )
echo unknown option: %~1
exit /b 1

:usage
echo Usage: build.bat [--target x86_64^|x86_32] [--test] [--clean] [--mingw]
exit /b 0

REM ── Detect architecture ────────────────────────────────────────────

:detect
if "%ARCH%"=="" (
    if "%PROCESSOR_ARCHITECTURE%"=="AMD64" ( set "ARCH=x86_64" )
    if "%PROCESSOR_ARCHITECTURE%"=="x86"   ( set "ARCH=x86_32" )
    if "%PROCESSOR_ARCHITECTURE%"=="ARM64" ( set "ARCH=arm" )
)
if "%ARCH%"=="" set "ARCH=x86_64"

set "BUILDDIR=build\%ARCH%-win"
if not exist "%BUILDDIR%" mkdir "%BUILDDIR%"
echo arch: %ARCH%
echo compiler: %COMPILER%

REM ── Detect compiler ────────────────────────────────────────────────

if "%COMPILER%"=="mingw" goto use_mingw

where cl >nul 2>&1
if %ERRORLEVEL%==0 goto use_msvc

where gcc >nul 2>&1
if %ERRORLEVEL%==0 goto use_mingw

echo error: no compiler found. Install Visual Studio Build Tools or MinGW.
exit /b 1

REM ── MSVC build ─────────────────────────────────────────────────────

:use_msvc
echo using: MSVC (cl.exe)

set "CC=cl"
set "CFLAGS=/nologo /W4 /WX /Iinclude /O2 /c"
set "AR=lib"
set "ARFLAGS=/nologo /OUT:"

REM Compile all C sources
for %%f in (src\*.c) do (
    echo   compile %%~nf.c
    cl %CFLAGS% /Fo"%BUILDDIR%\%%~nf.obj" "%%f"
    if errorlevel 1 exit /b 1
)

REM Assemble x86 with NASM (if available and target is x86)
if "%ARCH%"=="x86_64" (
    where nasm >nul 2>&1
    if !ERRORLEVEL!==0 (
        for %%f in (asm\x86_64\*.asm) do (
            echo   assemble %%~nf.asm
            nasm -f win64 -DWIN64 -o "%BUILDDIR%\%%~nf.obj" "%%f"
            if errorlevel 1 exit /b 1
        )
    ) else (
        echo   warning: nasm not found, skipping ASM (scalar fallback)
    )
)
if "%ARCH%"=="x86_32" (
    where nasm >nul 2>&1
    if !ERRORLEVEL!==0 (
        for %%f in (asm\x86_32\*.asm) do (
            echo   assemble %%~nf.asm
            nasm -f win32 -DWIN32 -o "%BUILDDIR%\%%~nf.obj" "%%f"
            if errorlevel 1 exit /b 1
        )
    )
)

REM Link static library
echo   archive libpompom.lib
lib /nologo /OUT:"%BUILDDIR%\libpompom.lib" "%BUILDDIR%\*.obj"
if errorlevel 1 exit /b 1

REM Build test if requested
if "%ACTION%"=="test" (
    echo   compile bench
    cl /nologo /W4 /O2 /Iinclude /Fe"%BUILDDIR%\pompom_bench.exe" test\bench.c "%BUILDDIR%\libpompom.lib"
    if errorlevel 1 exit /b 1
    echo   running tests...
    "%BUILDDIR%\pompom_bench.exe"
)

echo done: %BUILDDIR%\libpompom.lib
goto end

REM ── MinGW build ────────────────────────────────────────────────────

:use_mingw
echo using: MinGW (gcc)

set "CC=gcc"
set "CFLAGS=-Wall -Wextra -Werror -Iinclude -O2"
set "AR=ar"

REM Compile C sources
for %%f in (src\*.c) do (
    echo   compile %%~nf.c
    gcc %CFLAGS% -c -o "%BUILDDIR%\%%~nf.o" "%%f"
    if errorlevel 1 exit /b 1
)

REM Assemble
if "%ARCH%"=="x86_64" (
    where nasm >nul 2>&1
    if !ERRORLEVEL!==0 (
        for %%f in (asm\x86_64\*.asm) do (
            echo   assemble %%~nf.asm
            nasm -f win64 -DWIN64 -o "%BUILDDIR%\%%~nf.o" "%%f"
            if errorlevel 1 exit /b 1
        )
    )
)
if "%ARCH%"=="x86_32" (
    where nasm >nul 2>&1
    if !ERRORLEVEL!==0 (
        for %%f in (asm\x86_32\*.asm) do (
            echo   assemble %%~nf.asm
            nasm -f win32 -DWIN32 -o "%BUILDDIR%\%%~nf.o" "%%f"
            if errorlevel 1 exit /b 1
        )
    )
)

REM Archive
echo   archive libpompom.a
ar rcs "%BUILDDIR%\libpompom.a" "%BUILDDIR%\*.o"
if errorlevel 1 exit /b 1

REM Test
if "%ACTION%"=="test" (
    gcc %CFLAGS% -o "%BUILDDIR%\pompom_bench.exe" test\bench.c "%BUILDDIR%\libpompom.a"
    if errorlevel 1 exit /b 1
    "%BUILDDIR%\pompom_bench.exe"
)

echo done: %BUILDDIR%\libpompom.a

:end
endlocal
