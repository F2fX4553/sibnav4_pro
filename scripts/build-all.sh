#!/bin/bash
set -e

echo "Building Secure Protocol System..."

# Core
echo "[1/3] Building Rust Core..."
cd core
cargo build --release --features "ffi"
cd ..

# C++
echo "[2/3] Building C++ Bindings..."
mkdir -p bindings/cpp/build
cd bindings/cpp/build
cmake ..
make
cd ../../..

# Python
echo "[3/3] Setting up Python..."
cd bindings/python
# Should run inside venv ideally
# pip install -e . 
echo "Python setup skipped (run manually: cd bindings/python && pip install -e .)"
cd ../..

echo "Build Complete."
