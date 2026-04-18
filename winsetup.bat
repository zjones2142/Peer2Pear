@echo off
REM Peer2Pear setup -- Windows.
REM
REM Comprehensive one-command setup.  Installs via winget:
REM   - git, cmake, ninja, Python
REM   - Visual Studio 2022 Build Tools (VC workload, Windows 10/11 SDK)
REM Then uses aqtinstall to download Qt (msvc2019_64 + WebSockets module)
REM to C:\Qt\, clones and bootstraps vcpkg, runs vcpkg in manifest mode to
REM install everything listed in vcpkg.json (sqlcipher, pkgconf, libsodium,
REM liboqs, and the "p2p" feature's msquic/libnice/glib), and setx's
REM CMAKE_PREFIX_PATH so CMake finds Qt.
REM
REM Idempotent -- re-running after a successful setup is a no-op.
REM
REM First-time download is ~10 GB.  Budget an hour with a good connection.
REM
REM If any tool is freshly installed, the script will finish and ask you to
REM close the terminal and run winsetup.bat again so the new PATH entries
REM take effect.  The re-run is fast -- everything already installed is
REM skipped.
REM
REM KEEP THIS IN SYNC WITH vcpkg.json, CMakeLists.txt, and setup.sh.
REM Written in goto-style (no parenthesized IF blocks) because nested
REM IFs cause cmd.exe parser errors, especially under PowerShell.

setlocal

REM Clear any stray VCPKG_ROOT so we don't fight an old env var pointing at
REM a different vcpkg clone (e.g. an "external\vcpkg" submodule from a past
REM setup).  We always use the vcpkg folder inside this repo.
set "VCPKG_ROOT="

set "INSTALLED_SOMETHING=0"

REM Qt version + aqtinstall arch.  Using Qt 6.5.3 LTS because it's the
REM most broadly aqtinstall-compatible release.  "win64_msvc2019_64" is the
REM only MSVC binary Qt ships for 6.5.x -- 6.8+ is when msvc2022_64 appears.
REM These 2019 binaries are ABI-compatible with MSVC 2022, so they link
REM fine against the compiler the VS Build Tools step installed.
set "QT_VERSION=6.5.3"
set "QT_ARCH=win64_msvc2019_64"
set "QT_ROOT=C:\Qt"

REM Derive the install subdirectory from QT_ARCH: aqtinstall writes to
REM "<QT_ROOT>\<version>\<arch-with-win64_-prefix-stripped>".
set "QT_ARCH_DIR=%QT_ARCH:win64_=%"
set "QT_DIR=%QT_ROOT%\%QT_VERSION%\%QT_ARCH_DIR%"

echo Peer2Pear setup (Windows)
echo.
echo This will install (skipping anything already present):
echo   git, cmake, ninja, Python 3, Visual Studio 2022 Build Tools,
echo   Qt %QT_VERSION%, vcpkg, sqlcipher, pkgconf
echo.
echo First-time total download: ~7-8 GB, roughly 45 minutes.
echo.

REM ---- winget -----------------------------------------------------------
REM Almost every install below uses winget, so check for it up front.

where winget >nul 2>&1
if errorlevel 1 goto err_no_winget

REM ---- git --------------------------------------------------------------

where git >nul 2>&1
if errorlevel 1 goto install_git
echo   [ok] git
goto git_done

:install_git
echo Installing git via winget...
winget install --id Git.Git -e --silent --accept-source-agreements --accept-package-agreements
if errorlevel 1 goto err_winget_fail
set "INSTALLED_SOMETHING=1"

:git_done

REM ---- cmake ------------------------------------------------------------

where cmake >nul 2>&1
if errorlevel 1 goto install_cmake
echo   [ok] cmake
goto cmake_done

:install_cmake
echo Installing cmake via winget...
winget install --id Kitware.CMake -e --silent --accept-source-agreements --accept-package-agreements
if errorlevel 1 goto err_winget_fail
set "INSTALLED_SOMETHING=1"

:cmake_done

REM ---- ninja ------------------------------------------------------------

where ninja >nul 2>&1
if errorlevel 1 goto install_ninja
echo   [ok] ninja
goto ninja_done

:install_ninja
echo Installing ninja via winget...
winget install --id Ninja-build.Ninja -e --silent --accept-source-agreements --accept-package-agreements
if errorlevel 1 goto err_winget_fail
set "INSTALLED_SOMETHING=1"

:ninja_done

REM ---- Python (for aqtinstall) -----------------------------------------
REM We prefer the "py" launcher because it's installed into %WINDIR% and
REM is findable from any fresh shell.  If neither py nor python is found,
REM install Python via winget.

where py >nul 2>&1
if not errorlevel 1 goto python_done
where python >nul 2>&1
if not errorlevel 1 goto python_done
echo Installing Python 3 via winget...
winget install --id Python.Python.3.12 -e --silent --accept-source-agreements --accept-package-agreements
if errorlevel 1 goto err_winget_fail
set "INSTALLED_SOMETHING=1"
goto python_done

:python_done
echo   [ok] Python

REM ---- Visual Studio 2022 Build Tools ----------------------------------
REM Check via vswhere for an existing install.  Without it, vcpkg cannot
REM build libsodium / liboqs / msquic on Windows because there's no MSVC
REM compiler.  winget override flag adds the VC workload so we don't end
REM up with just the installer shell.

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto install_vs
set "VS_PATH="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul`) do set "VS_PATH=%%i"
if not defined VS_PATH goto install_vs
echo   [ok] Visual Studio Build Tools at %VS_PATH%
goto vs_done

:install_vs
echo.
echo Installing Visual Studio 2022 Build Tools with the VC workload.
echo (Minimal install: VC compiler + Windows 11 SDK, no recommended extras.)
echo Expect ~3-4 GB download, 15-20 minutes.
echo.
echo This step is only needed when PEER2PEAR_P2P is ON (the default).
echo If you plan to build with -DPEER2PEAR_P2P=OFF you can skip MSVC.
echo.
winget install --id Microsoft.VisualStudio.2022.BuildTools --silent --accept-source-agreements --accept-package-agreements --override "--wait --quiet --add Microsoft.VisualStudio.Workload.VCTools --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64 --add Microsoft.VisualStudio.Component.Windows11SDK.22621"
if errorlevel 1 goto err_winget_fail
set "INSTALLED_SOMETHING=1"

:vs_done

REM ---- Bail if anything was freshly installed --------------------------
REM The newly-installed binaries aren't yet on the CURRENT terminal's
REM PATH, so downstream steps (git clone, py -m pip, etc.) would fail.
REM Ask the user to rerun in a fresh terminal.

if "%INSTALLED_SOMETHING%"=="1" goto need_rerun

REM From here down, all tool prerequisites are assumed to be on PATH.

REM ---- Qt 6 via aqtinstall ---------------------------------------------

if exist "%QT_DIR%\bin\qmake.exe" goto qt_done

echo Installing latest aqtinstall (pip)...
REM --force-reinstall in case a previous run cached a version with
REM Python 3.14 parser quirks; --upgrade alone may skip.
py -m pip install --upgrade --force-reinstall --user aqtinstall
if errorlevel 1 goto err_aqtinstall

echo Installing Qt %QT_VERSION% (%QT_ARCH%) with WebSockets module to %QT_ROOT% ...
echo (download ~1.5 GB)
py -m aqt install-qt windows desktop %QT_VERSION% %QT_ARCH% -m qtwebsockets -O "%QT_ROOT%"
if errorlevel 1 goto err_aqtinstall

:qt_done
echo   [ok] Qt %QT_VERSION% at %QT_DIR%

REM Persist CMAKE_PREFIX_PATH so CMake picks up Qt in future shells.
REM (setx writes the USER env var; takes effect in new terminals.)
setx CMAKE_PREFIX_PATH "%QT_DIR%" >nul

REM ---- vcpkg -----------------------------------------------------------
REM vcpkg.json lists everything the build needs:
REM   - core:          libsodium, liboqs, nlohmann-json
REM   - windows-only:  sqlcipher, pkgconf
REM   - feature "p2p": msquic, libnice, glib  (default ON)
REM
REM We run vcpkg in MANIFEST mode -- positional package args are not
REM supported once a vcpkg.json exists in the repo root, so everything
REM has to come from the manifest.

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
REM Install the manifest's deps + the "p2p" feature (matches the default
REM PEER2PEAR_P2P=ON CMake option).  First run takes 15-30 minutes because
REM every dep compiles from source; subsequent runs are near-instant.
echo Installing vcpkg manifest dependencies (may take 15-30 minutes on first run)...
.\vcpkg\vcpkg.exe install --x-feature=p2p
if errorlevel 1 goto err_generic

echo.
echo =====================================================================
echo Setup complete.
echo =====================================================================
echo.
echo CMAKE_PREFIX_PATH was set to: %QT_DIR%
echo (effective in new terminals; close and reopen to pick it up)
echo.
echo Next steps:
echo   - Open CMakeLists.txt in Qt Creator, OR
echo   - In a NEW terminal, build from the command line:
echo         cmake -B build -S . -G Ninja -DCMAKE_TOOLCHAIN_FILE=vcpkg/scripts/buildsystems/vcpkg.cmake
echo         cmake --build build
echo.
echo The first CMake configure will take several more minutes -- vcpkg
echo builds libsodium, liboqs, msquic, libnice, and glib from source.
echo.
pause
exit /b 0

REM ---- "Installed something, please rerun" exit path -----------------

:need_rerun
echo.
echo =====================================================================
echo One or more tools were just installed.  Their executables are not
echo yet on the CURRENT terminal's PATH.
echo.
echo   1. Close this terminal window.
echo   2. Open a NEW terminal (PowerShell or Command Prompt).
echo   3. cd to this repo and run:  winsetup.bat
echo.
echo The script is idempotent -- it'll skip everything already installed
echo and pick up where it left off.
echo =====================================================================
echo.
pause
exit /b 0

REM ---- Error labels ----------------------------------------------------
REM Every error path pauses before exit so the window stays open when the
REM script is double-clicked from Explorer (no console persists otherwise).

:err_no_winget
echo.
echo Error: winget not found.  Requires Windows 10 21H1+ or Windows 11.
echo Install App Installer from the Microsoft Store, then re-run.
echo.
pause
exit /b 1

:err_winget_fail
echo.
echo Error: winget install failed.  See output above for details.
echo You may need to run this terminal as Administrator.
echo.
pause
exit /b 1

:err_aqtinstall
echo.
echo Error: aqtinstall or Qt installation failed.
echo   - Check that Python is on PATH (py --version).
echo   - If this persists, install Qt manually from https://www.qt.io/download
echo     and set CMAKE_PREFIX_PATH to point to the msvc install dir, e.g.:
echo         setx CMAKE_PREFIX_PATH "C:\Qt\%QT_VERSION%\msvc2022_64"
echo.
pause
exit /b 1

:err_generic
echo.
echo Error: setup step failed.  See output above.
echo.
pause
exit /b 1
