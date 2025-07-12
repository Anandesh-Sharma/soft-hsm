#!/bin/bash

echo "Setting up SoftHSM development environment..."
echo "=============================================="

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macOS"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="Linux"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

echo "Detected OS: $OS"

# Install SoftHSM
echo "Installing SoftHSM..."
if [[ "$OS" == "macOS" ]]; then
    if command -v brew &> /dev/null; then
        brew install softhsm
    else
        echo "Homebrew not found. Please install Homebrew first."
        exit 1
    fi
elif [[ "$OS" == "Linux" ]]; then
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y softhsm2
    elif command -v yum &> /dev/null; then
        sudo yum install -y softhsm
    else
        echo "Package manager not found. Please install SoftHSM manually."
        exit 1
    fi
fi

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
fi

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Find SoftHSM library path
echo "Finding SoftHSM library path..."
if [[ "$OS" == "macOS" ]]; then
    SOFTHSM_LIB=$(find /usr/local -name "libsofthsm2.so" 2>/dev/null | head -1)
    if [ -z "$SOFTHSM_LIB" ]; then
        SOFTHSM_LIB=$(find /opt/homebrew -name "libsofthsm2.so" 2>/dev/null | head -1)
    fi
elif [[ "$OS" == "Linux" ]]; then
    SOFTHSM_LIB=$(find /usr -name "libsofthsm2.so" 2>/dev/null | head -1)
fi

if [ -z "$SOFTHSM_LIB" ]; then
    echo "SoftHSM library not found. Please check your installation."
    exit 1
fi

echo "SoftHSM library found at: $SOFTHSM_LIB"

# Create SoftHSM configuration
echo "Creating SoftHSM configuration..."
mkdir -p ~/.softhsm2
SOFTHSM_CONF=~/.softhsm2/softhsm2.conf

cat > "$SOFTHSM_CONF" << EOF
# SoftHSM configuration file
directories.tokendir = ~/.softhsm2/tokens/
objectstore.backend = file
log.level = INFO
EOF

# Create tokens directory
mkdir -p ~/.softhsm2/tokens

# Initialize a token
echo "Initializing SoftHSM token..."
softhsm2-util --init-token --slot 0 --label "TestToken" --pin 1234 --so-pin 1234

# Update the Python file with the correct library path
echo "Updating library path in Python file..."
if [[ "$OS" == "macOS" ]]; then
    sed -i '' "s|/usr/lib/softhsm/libsofthsm2.so|$SOFTHSM_LIB|g" softhsm_utils.py
elif [[ "$OS" == "Linux" ]]; then
    sed -i "s|/usr/lib/softhsm/libsofthsm2.so|$SOFTHSM_LIB|g" softhsm_utils.py
fi

echo ""
echo "Setup complete! 🎉"
echo "==================="
echo "SoftHSM library: $SOFTHSM_LIB"
echo "Configuration file: $SOFTHSM_CONF"
echo "Token directory: ~/.softhsm2/tokens"
echo ""
echo "To test the setup, run:"
echo "  python softhsm_utils.py"
echo "  python example_usage.py"
echo ""
echo "Available tokens:"
softhsm2-util --show-slots %  