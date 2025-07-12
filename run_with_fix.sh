#!/bin/bash

echo "Starting HSM Edwards API with comprehensive BoringSSL fix..."

# Kill any existing processes on port 8000
lsof -ti:8000 | xargs kill -9 2>/dev/null

# Unset problematic environment variables that might interfere
unset DYLD_LIBRARY_PATH
unset LD_LIBRARY_PATH

# Set environment variables to bypass BoringSSL
export CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1
export PYTHONHASHSEED=0

# For macOS, force the use of system libraries
if [[ "$(uname)" == "Darwin" ]]; then
    echo "Detected macOS, applying platform-specific fixes..."
    
    # Disable SIP-protected library usage
    export DYLD_FALLBACK_LIBRARY_PATH=/usr/local/lib
    
    # If on Apple Silicon, run in Rosetta mode
    if [[ "$(uname -m)" == "arm64" ]]; then
        echo "Running in x86_64 compatibility mode..."
        arch -x86_64 python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
    else
        python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
    fi
else
    python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
fi