FROM debian:latest

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

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o rustup-init.sh \
&& sh rustup-init.sh -y --default-toolchain stable --no-modify-path
ENV PATH="/root/.cargo/bin:${PATH}" 

COPY . /poi-radio
WORKDIR /poi-radio

RUN sh install-golang.sh
ENV PATH=$PATH:/usr/local/go/bin

RUN cargo build
CMD ["cargo", "run"]
