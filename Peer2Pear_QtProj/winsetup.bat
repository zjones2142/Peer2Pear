@echo off
setlocal

echo ============================================================
echo  Peer2Pear - Windows Build Setup
echo ============================================================
echo.

REM --- Enable vcpkg binary caching (greatly speeds up rebuilds) ---
REM Caches pre-built packages in %LOCALAPPDATA%\vcpkg\archives so
REM subsequent builds and CI runs skip recompilation of dependencies.
if not defined VCPKG_DEFAULT_BINARY_CACHE (
    set "VCPKG_DEFAULT_BINARY_CACHE=%LOCALAPPDATA%\vcpkg\archives"
)
if not exist "%VCPKG_DEFAULT_BINARY_CACHE%" (
    mkdir "%VCPKG_DEFAULT_BINARY_CACHE%"
)
echo [OK] Binary caching enabled: %VCPKG_DEFAULT_BINARY_CACHE%

REM --- Clone or update vcpkg ---
if not exist vcpkg\ (
    echo Cloning vcpkg repository...
    git clone https://github.com/microsoft/vcpkg.git
    if errorlevel 1 (
        echo [ERROR] Failed to clone vcpkg. Check your internet connection and git installation.
        pause
        exit /b 1
    )
) else (
    echo vcpkg directory already exists. Pulling latest changes...
    git -C vcpkg pull --ff-only 2>nul || echo [WARN] Could not update vcpkg, using existing version.
)

REM --- Bootstrap vcpkg ---
echo Bootstrapping vcpkg...
call .\vcpkg\bootstrap-vcpkg.bat -disableMetrics
if errorlevel 1 (
    echo [ERROR] Failed to bootstrap vcpkg. Ensure you have a C++ compiler installed.
    echo         Install Visual Studio 2019+ or Build Tools with the "Desktop development with C++" workload.
    pause
    exit /b 1
)
echo [OK] vcpkg bootstrapped.

echo.
echo ============================================================
echo  Setup complete!
echo ============================================================
echo.
echo  Next steps:
echo    1. Open this folder in Qt Creator.
echo    2. Select the "win-msvc-debug" or "win-msvc-release" CMake preset.
echo    3. Build the project (Ctrl+B).
echo.
echo  Or build from a Developer Command Prompt:
echo    cd Peer2Pear_QtProj
echo    cmake --preset win-msvc-debug
echo    cmake --build build
echo.
echo  TIP: The first build takes longer because vcpkg compiles
echo       dependencies from source. Subsequent builds will use
echo       cached binaries from %VCPKG_DEFAULT_BINARY_CACHE%.
echo.
pause