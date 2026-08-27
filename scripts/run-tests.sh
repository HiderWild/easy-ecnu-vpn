#!/bin/bash
# run-tests.sh - Local test runner for EXV
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PRESET="${1:-linux-release}"
LABEL=""

# Parse arguments
LIST_LABELS=false
DIAGNOSTICS=false

usage() {
    echo "Usage: $0 [preset] [options]"
    echo ""
    echo "Presets: linux-release, macos-release, windows-release"
    echo ""
    echo "Options:"
    echo "  -l, --label LABEL       Run only tests with this label"
    echo "  --list-labels           Show available test labels and exit"
    echo "  --diagnostics           Run DLL/platform diagnostics before tests"
    echo "  -h, --help              Show this help"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -l|--label)
            LABEL="$2"
            shift 2
            ;;
        --list-labels)
            LIST_LABELS=true
            shift
            ;;
        --diagnostics)
            DIAGNOSTICS=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            # First non-option arg is the preset
            if [ -z "$PRESET_SET" ]; then
                PRESET="$1"
                PRESET_SET=true
            fi
            shift
            ;;
    esac
done

echo "=== EXV Test Runner ==="
echo "Preset: $PRESET"

# List labels mode
if [ "$LIST_LABELS" = true ]; then
    echo -e "\n--- Configuring ---"
    cmake --preset "$PRESET"

    BUILD_DIR=""
    case "$PRESET" in
        linux-release)   BUILD_DIR="$REPO_ROOT/build/linux/cpp" ;;
        macos-release)   BUILD_DIR="$REPO_ROOT/build/macos/cpp" ;;
        windows-release) BUILD_DIR="$REPO_ROOT/build-windows/cpp" ;;
    esac

    if [ -d "$BUILD_DIR" ]; then
        echo -e "\n--- Available test labels ---"
        cd "$BUILD_DIR"
        ctest --print-labels
    else
        echo "Build directory not found: $BUILD_DIR"
    fi
    exit 0
fi

# Configure
echo -e "\n--- Configuring ---"
cmake --preset "$PRESET"

# Build
echo -e "\n--- Building ---"
cmake --build --preset "$PRESET"

# Diagnostic mode
if [ "$DIAGNOSTICS" = true ]; then
    echo -e "\n--- Platform Diagnostic ---"
    echo "Test executables:"
    BUILD_DIR=""
    case "$PRESET" in
        linux-release) BUILD_DIR="$REPO_ROOT/build/linux/cpp" ;;
        macos-release) BUILD_DIR="$REPO_ROOT/build/macos/cpp" ;;
    esac
    if [ -n "$BUILD_DIR" ] && [ -d "$BUILD_DIR" ]; then
        find "$BUILD_DIR" -name "*_test" -type f -exec sh -c 'echo "  $1: $(ldd "$1" 2>/dev/null | grep "not found" || echo "all deps OK")"' _ {} \;
    fi
fi

# Test
echo -e "\n--- Running Tests ---"
CTEST_ARGS="--preset $PRESET --output-on-failure"
if [ -n "$LABEL" ]; then
    CTEST_ARGS="$CTEST_ARGS -L $LABEL"
fi

ctest $CTEST_ARGS
TEST_RESULT=$?

echo -e "\n=== Results ==="
if [ $TEST_RESULT -eq 0 ]; then
    echo "All tests passed!"
else
    echo "Some tests failed. Check Testing/Temporary/LastTest.log"
fi

exit $TEST_RESULT
