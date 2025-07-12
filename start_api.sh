#!/bin/bash

# Start script for HSM Edwards API with BoringSSL fix

echo "Starting HSM Edwards API with BoringSSL fix..."

# Set environment variable to prevent BoringSSL assertion failure
export CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1

# Disable Python's hash randomization which can cause issues with cryptography
export PYTHONHASHSEED=0

# Enable SoftHSM mode to bypass BoringSSL issues
export USE_SOFTHSM=true

# For macOS, additional settings
if [[ "$(uname)" == "Darwin" ]]; then
    echo "macOS detected - using SoftHSM to bypass BoringSSL issues"
    # Unset problematic library paths
    unset DYLD_LIBRARY_PATH
    unset LD_LIBRARY_PATH
fi

# Start the API
echo "Starting API server in SoftHSM mode..."
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload