@echo off
REM Peer2Pear setup -- Windows.
REM
REM Installs Ninja (via winget), clones and bootstraps vcpkg, and installs
REM SQLCipher + pkgconf through vcpkg. Leaves the repo ready for Qt Creator
REM or a manual "cmake --build" invocation. Idempotent.
REM
REM KEEP THIS IN SYNC WITH vcpkg.json, CMakeLists.txt, and setup.sh.
REM Written in goto-style (no block IFs) because nested parenthesized IFs
REM cause parser errors on some cmd.exe versions, especially when invoked
REM through PowerShell.

setlocal

echo Peer2Pear setup (Windows)
echo.

REM ---- Required tools -------------------------------------------------

where git >nul 2>&1
if errorlevel 1 goto err_git

where cmake >nul 2>&1
if errorlevel 1 goto err_cmake

REM ---- Ninja ----------------------------------------------------------

where ninja >nul 2>&1
if errorlevel 1 goto install_ninja
echo   [ok] ninja
goto ninja_done

:install_ninja
echo Ninja not found. Attempting install via winget...
where winget >nul 2>&1
if errorlevel 1 goto err_no_winget
winget install --id Ninja-build.Ninja -e --silent --accept-source-agreements --accept-package-agreements
if errorlevel 1 goto err_winget
echo   [ok] Ninja installed. If "ninja" still isn't found, restart your terminal.

:ninja_done

REM ---- vcpkg ----------------------------------------------------------

if exist "vcpkg\" goto vcpkg_clone_done
echo Cloning vcpkg...
git clone https://github.com/microsoft/vcpkg.git
if errorlevel 1 goto err_generic
goto vcpkg_bootstrap

:vcpkg_clone_done
echo   [ok] vcpkg directory already exists

:vcpkg_bootstrap
if exist "vcpkg\vcpkg.exe" goto vcpkg_ready
echo Bootstrapping vcpkg...
call .\vcpkg\bootstrap-vcpkg.bat -disableMetrics
if errorlevel 1 goto err_generic
goto vcpkg_install

:vcpkg_ready
echo   [ok] vcpkg already bootstrapped

:vcpkg_install

REM ---- SQLCipher + pkgconf via vcpkg ----------------------------------
REM CMakeLists.txt uses pkg_check_modules(SQLCIPHER ...), which on
REM Windows needs both the sqlcipher library and a pkg-config shim.

echo Installing sqlcipher and pkgconf via vcpkg (may take several minutes on first run)...
.\vcpkg\vcpkg.exe install sqlcipher:x64-windows pkgconf:x64-windows
if errorlevel 1 goto err_generic

echo.
echo Setup complete.
echo.
echo Next steps:
echo   - Open CMakeLists.txt in Qt Creator, OR
echo   - Build from the command line:
echo         cmake -B build -S . -G Ninja -DCMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake
echo         cmake --build build
echo.
echo The first CMake configure will take several minutes -- vcpkg builds
echo libsodium, liboqs, msquic, libnice, and glib from source.
echo.
pause
exit /b 0

REM ---- Error labels ---------------------------------------------------

:err_git
echo Error: git not found in PATH.
echo Install from https://git-scm.com/download/win and re-run.
exit /b 1

:err_cmake
echo Error: cmake not found in PATH.
echo Install CMake from https://cmake.org, or add Qt's bundled
echo CMake (C:\Qt\Tools\CMake_64\bin) to your PATH.
exit /b 1

:err_no_winget
echo Error: winget not found. Install Ninja manually:
echo   - https://github.com/ninja-build/ninja/releases
echo   - Or: choco install ninja
echo   - Or: scoop install ninja
exit /b 1

:err_winget
echo Error: winget failed to install Ninja.
exit /b 1

:err_generic
echo Error: setup step failed. See output above.
exit /b 1
