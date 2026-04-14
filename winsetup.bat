@echo off
echo Setting up vcpkg for Windows...

REM Check if the vcpkg directory already exists
IF NOT EXIST vcpkg\ (
    echo Cloning vcpkg repository...
    git clone https://github.com/microsoft/vcpkg.git
) ELSE (
    echo vcpkg directory already exists. Skipping clone.
    REM Optional: You could add 'git -C vcpkg pull' here to update an existing clone
)

echo Bootstrapping vcpkg...
call .\vcpkg\bootstrap-vcpkg.bat -disableMetrics

echo Setup complete! You can now open the project in Qt Creator.
pause