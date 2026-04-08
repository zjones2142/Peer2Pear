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

REM --- Check for Qt installation ---
set "QT_DETECTED="
if exist "C:\Qt" (
    for /d %%Q in (C:\Qt\6.*) do (
        if exist "%%Q\msvc2022_64\bin\qmake.exe" set "QT_DETECTED=%%Q\msvc2022_64"
        if exist "%%Q\msvc2019_64\bin\qmake.exe" set "QT_DETECTED=%%Q\msvc2019_64"
    )
    if not defined QT_DETECTED (
        for /d %%Q in (C:\Qt\5.*) do (
            if exist "%%Q\msvc2019_64\bin\qmake.exe" set "QT_DETECTED=%%Q\msvc2019_64"
            if exist "%%Q\msvc2017_64\bin\qmake.exe" set "QT_DETECTED=%%Q\msvc2017_64"
        )
    )
)
if defined QT_DETECTED (
    echo [OK] Qt detected: %QT_DETECTED%
) else (
    echo [WARN] Qt not found at C:\Qt. Make sure Qt is installed.
    echo        Download from: https://www.qt.io/download-qt-installer
    echo        Install a Desktop MSVC kit ^(e.g. Qt 6.x / MSVC 2022 64-bit^).
)

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
    git -C vcpkg pull --ff-only 2>nul || echo [WARN] Could not update vcpkg ^(local changes or network issue^), using existing version.
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