#!/bin/bash

set -e

# Change to /tmp/iitd-csf directory for all operations
WORK_DIR="/tmp/iitd-csf"
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

SCRIPT_NAME="sensor-helm-install.py"
SCRIPT_URL="https://raw.githubusercontent.com/iIT-Distribution/scripts/refs/heads/master/crowdstrike/cloud/sensor-helm-install.py"
VENV_DIR="$WORK_DIR/.falcon-venv"
REQUIRED_PACKAGES=("rich" "pyyaml" "requests")
IMPORT_NAMES=("rich" "yaml" "requests")

echo "🚀 CrowdStrike Falcon Sensor Helm Preparation Tool"
echo "=================================================="
echo ""

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not found"
    echo "Please install Python 3.8+ and try again"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 8 ]); then
    echo "❌ Python 3.8+ is required (found $PYTHON_VERSION)"
    echo "Please upgrade Python and try again"
    exit 1
fi

echo "✅ Python $PYTHON_VERSION found"

# Download the script if it doesn't exist
SCRIPT_PATH="$WORK_DIR/$SCRIPT_NAME"
if [ ! -f "$SCRIPT_PATH" ]; then
    echo "📥 Downloading $SCRIPT_NAME to $SCRIPT_PATH..."
    if command -v curl &> /dev/null; then
        curl -sSL "$SCRIPT_URL" -o "$SCRIPT_PATH"
    elif command -v wget &> /dev/null; then
        wget -q "$SCRIPT_URL" -O "$SCRIPT_PATH"
    else
        echo "❌ Neither curl nor wget found"
        echo "Please install curl or wget, or download the script manually:"
        echo "  $SCRIPT_URL"
        exit 1
    fi
    echo "✅ Script downloaded to $SCRIPT_PATH"
fi

# Make script executable
chmod +x "$SCRIPT_PATH"

# Function to check if a Python package is available
check_package() {
    python3 -c "import $1" &> /dev/null
}

# Function to check all required packages
check_all_packages() {
    for package in "${IMPORT_NAMES[@]}"; do
        if ! check_package "$package"; then
            echo "❌ $package not found in system Python"
            return 1
        fi
    done
    return 0
}

# Try to run with system Python first
if check_all_packages; then
    echo "✅ All dependencies found in system Python"
    echo "🏃 Running installer..."
    python3 "$SCRIPT_PATH" "$@"
    exit 0
fi

echo "⚠️  Some dependencies missing in system Python"

# Try to install packages globally
echo "🔧 Attempting to install dependencies globally..."
if python3 -m pip install --user "${REQUIRED_PACKAGES[@]}" &> /dev/null; then
    if check_all_packages; then
        echo "✅ Dependencies installed globally"
        echo "🏃 Running installer..."
        python3 "$SCRIPT_PATH" "$@"
        exit 0
    fi
fi

echo "⚠️  Global installation failed or insufficient"

# Check if venv module is available
if ! python3 -m venv --help &> /dev/null; then
    echo "❌ Python venv module not available"
    echo ""
    echo "Please install dependencies manually:"
    echo "  pip3 install --user ${REQUIRED_PACKAGES[*]}"
    echo ""
    echo "Or install python3-venv:"
    echo "  # Ubuntu/Debian:"
    echo "  sudo apt install python3-venv"
    echo "  # RHEL/CentOS:"
    echo "  sudo yum install python3-venv"
    echo "  # macOS:"
    echo "  # venv is included with Python 3.3+"
    exit 1
fi

# Create and use virtual environment
if [ ! -d "$VENV_DIR" ]; then
    echo "🔧 Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

echo "🔧 Installing dependencies in virtual environment..."
source "$VENV_DIR/bin/activate"

if ! pip install "${REQUIRED_PACKAGES[@]}" &> /dev/null; then
    echo "❌ Failed to install dependencies in virtual environment"
    echo ""
    echo "Please try manually:"
    echo "  python3 -m venv $VENV_DIR"
    echo "  source $VENV_DIR/bin/activate"
    echo "  pip install ${REQUIRED_PACKAGES[*]}"
    echo "  python3 $SCRIPT_PATH"
    exit 1
fi

echo "✅ Dependencies installed in virtual environment"
echo "🏃 Running installer..."

# Run the script in virtual environment
python3 "$SCRIPT_PATH" "$@"