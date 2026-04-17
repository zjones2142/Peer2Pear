@echo off
REM Peer2Pear setup -- Windows.
REM
REM Installs Ninja (via winget), clones and bootstraps vcpkg, and installs
REM SQLCipher + pkgconf through vcpkg. Leaves the repo ready for Qt Creator
REM or a manual "cmake --build" invocation.
REM
REM Idempotent: re-running after a successful setup is a no-op.
REM
REM KEEP THIS IN SYNC WITH vcpkg.json, CMakeLists.txt, and setup.sh.
REM If new dependencies are added to the build, add the install step here too.

setlocal EnableDelayedExpansion

echo Peer2Pear setup (Windows)
echo(

REM ---- Required tools -------------------------------------------------

where git >nul 2>&1
if errorlevel 1 (
    echo Error: git not found in PATH.
    echo        Install from https://git-scm.com/download/win and re-run.
    exit /b 1
)

where cmake >nul 2>&1
if errorlevel 1 (
    echo Error: cmake not found in PATH.
    echo        Install CMake from https://cmake.org, or add Qt's bundled
    echo        CMake to your PATH (C:\Qt\Tools\CMake_64\bin).
    exit /b 1
)

REM ---- Ninja ----------------------------------------------------------

where ninja >nul 2>&1
if errorlevel 1 (
    echo Ninja not found. Attempting install via winget...
    where winget >nul 2>&1
    if errorlevel 1 (
        echo Error: winget not found either. Install Ninja manually:
        echo        - https://github.com/ninja-build/ninja/releases
        echo        - Or: choco install ninja
        echo        - Or: scoop install ninja
        exit /b 1
    )
    winget install --id Ninja-build.Ninja -e --silent --accept-source-agreements --accept-package-agreements
    if errorlevel 1 (
        echo Error: winget failed to install Ninja.
        exit /b 1
    )
    echo   [ok] Ninja installed. Restart your terminal if "ninja" is still not in PATH.
) else (
    echo   [ok] ninja
)

REM ---- vcpkg ----------------------------------------------------------
REM
REM vcpkg.json declares libsodium, liboqs, msquic, libnice, glib, which
REM get auto-installed on first CMake configure via the toolchain file.
REM SQLCipher + pkgconf are installed classic-mode below because the
REM top-level build uses pkg-config to discover them.

if not exist "vcpkg\" (
    echo Cloning vcpkg...
    git clone https://github.com/microsoft/vcpkg.git
    if errorlevel 1 exit /b 1
) else (
    echo   [ok] vcpkg directory already exists
)

if not exist "vcpkg\vcpkg.exe" (
    echo Bootstrapping vcpkg...
    call .\vcpkg\bootstrap-vcpkg.bat -disableMetrics
    if errorlevel 1 exit /b 1
) else (
    echo   [ok] vcpkg already bootstrapped
)

REM ---- SQLCipher + pkgconf via vcpkg ----------------------------------
REM
REM CMakeLists.txt uses pkg_check_modules(SQLCIPHER ... sqlcipher). On
REM Windows this needs both the sqlcipher library and a pkg-config shim,
REM neither of which ship with the OS.

echo Installing sqlcipher and pkgconf via vcpkg (may take several minutes on first run)...
.\vcpkg\vcpkg.exe install sqlcipher:x64-windows pkgconf:x64-windows
if errorlevel 1 (
    echo Error: vcpkg install failed.
    exit /b 1
)

echo(
echo Setup complete.
echo(
echo Next steps:
echo   - Open CMakeLists.txt in Qt Creator, OR
echo   - Build from the command line:
echo         cmake -B build -S . -G Ninja -DCMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake
echo         cmake --build build
echo(
echo The first CMake configure will take several minutes -- vcpkg builds
echo libsodium, liboqs, msquic, libnice, and glib from source.
echo(
pause
