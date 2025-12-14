# Multi-stage build for Secure Protocol System

# Stage 1: Build Rust Core
FROM rust:1.75 as rust-builder

WORKDIR /app
COPY . .

# Build core
WORKDIR /app/core
RUN cargo build --release --features "ffi"

# Stage 2: Build C++ Bindings
FROM ubuntu:22.04 as cpp-builder

RUN apt-get update && apt-get install -y \
    cmake \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=rust-builder /app /app

WORKDIR /app/bindings/cpp
RUN mkdir build && cd build && \
    cmake .. && \
    make

# Stage 3: Final Image
FROM python:3.11-slim

WORKDIR /app

# Install dependencies for running
RUN apt-get update && apt-get install -y \
    libgcc1 \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

# Copy artifacts
COPY --from=rust-builder /app/core/target/release/libsecure_protocol.so /usr/local/lib/
COPY --from=cpp-builder /app/bindings/cpp/build/libsecure_protocol_cpp.so /usr/local/lib/
COPY --from=rust-builder /app/bindings/python /app/bindings/python
COPY --from=rust-builder /app/tools /app/tools

# Setup Python
WORKDIR /app/bindings/python
RUN pip install .

# Setup Env
ENV LD_LIBRARY_PATH=/usr/local/lib
ENV PYTHONPATH=/app/bindings/python

# Default command
CMD ["python3", "/app/tools/python-tools/secure-chat.py"]
