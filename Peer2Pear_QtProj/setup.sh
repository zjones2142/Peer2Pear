#!/bin/bash
echo "Setting up vcpkg for macOS/Linux..."

# --- Enable vcpkg binary caching (greatly speeds up rebuilds) ---
if [ -z "$VCPKG_DEFAULT_BINARY_CACHE" ]; then
    export VCPKG_DEFAULT_BINARY_CACHE="$HOME/.cache/vcpkg/archives"
fi
mkdir -p "$VCPKG_DEFAULT_BINARY_CACHE"
echo "[OK] Binary caching enabled: $VCPKG_DEFAULT_BINARY_CACHE"

# Check if the vcpkg directory already exists
if [ ! -d "vcpkg" ]; then
    echo "Cloning vcpkg repository..."
    git clone https://github.com/microsoft/vcpkg.git
else
    echo "vcpkg directory already exists. Pulling latest changes..."
    git -C vcpkg pull --ff-only 2>/dev/null || echo "[WARN] Could not update vcpkg, using existing version."
fi

echo "Bootstrapping vcpkg..."
./vcpkg/bootstrap-vcpkg.sh -disableMetrics

echo ""
echo "Setup complete! You can now open the project in Qt Creator."
echo ""
echo "  Or build from a terminal:"
echo "    cmake --preset vcpkg-default"
echo "    cmake --build build"