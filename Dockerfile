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
	upx \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates

COPY . /poi-radio
WORKDIR /poi-radio

RUN sh install-golang.sh
ENV PATH=$PATH:/usr/local/go/bin

RUN cargo build --release

FROM alpine:3.17.3 as upx
RUN apk update \
    && apk add upx
COPY --from=build-image /poi-radio/target/release/poi-radio /poi-radio/target/release/poi-radio
RUN upx --overlay=strip --best /poi-radio/target/release/poi-radio

FROM gcr.io/distroless/cc AS runtime
COPY --from=build-image /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=build-image /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build-image /etc/passwd /etc/passwd
COPY --from=build-image /etc/group /etc/group
COPY --from=upx "/poi-radio/target/release/poi-radio" "/usr/local/bin/poi-radio"
ENTRYPOINT [ "/usr/local/bin/poi-radio" ]
