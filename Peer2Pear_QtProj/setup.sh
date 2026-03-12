#!/bin/bash
echo "Setting up vcpkg for macOS/Linux..."

# Check if the vcpkg directory already exists
if [ ! -d "vcpkg" ]; then
    echo "Cloning vcpkg repository..."
    git clone https://github.com/microsoft/vcpkg.git
else
    echo "vcpkg directory already exists. Skipping clone."
    # Optional: You could add 'git -C vcpkg pull' here if you want to ensure it's up to date
fi

echo "Bootstrapping vcpkg..."
./vcpkg/bootstrap-vcpkg.sh -disableMetrics

echo "Setup complete! You can now open the project in Qt Creator."