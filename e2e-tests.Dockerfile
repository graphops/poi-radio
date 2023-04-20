FROM rust:1-bullseye AS build-image

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        wget \
        curl \
        libpq-dev \
        pkg-config \
        libssl-dev \
        clang \
        build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates

COPY . /poi-radio
WORKDIR /poi-radio

RUN sh install-golang.sh
ENV PATH=$PATH:/usr/local/go/bin

RUN cargo build

FROM debian:bullseye-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpq-dev \
        pkg-config \
        libssl-dev \
        ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build-image "/poi-radio/target/debug/integration-tests" "/usr/local/bin/integration-tests"
ENTRYPOINT [ "/usr/local/bin/integration-tests" ]
