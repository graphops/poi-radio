FROM rust:1-bullseye AS build-image

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget \
    curl \
    libpq-dev \
    pkg-config \
    libssl-dev \
    clang \
    build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates

COPY . /poi-radio
WORKDIR /poi-radio

RUN sh install-golang.sh
ENV PATH=$PATH:/usr/local/go/bin

# Make test scripts executable
RUN chmod +x scripts/e2e/*.sh

# Build the application
RUN cargo build
