FROM rust:1.90.0-slim AS builder
WORKDIR /build
COPY . .
ARG BUILD_PROFILE=maxperf

RUN apt update && apt install -y \
    make libssl-dev pkg-config libfindbin-libs-perl llvm clang \
    && cargo build --profile $BUILD_PROFILE --bin operator --locked \
    && cp /build/target/$BUILD_PROFILE/operator /build/helios-operator

FROM ubuntu:25.04 AS run
WORKDIR /app

COPY --from=builder /build/helios-operator /usr/local/bin

RUN apt-get update && apt-get install -y ca-certificates libpq-dev adduser \
    && apt clean \
    && adduser --disabled-password --gecos "" --no-create-home --uid 1001 bridge \
    && chown -R bridge:bridge /usr/local/bin/helios-operator

USER bridge

ENTRYPOINT ["/usr/local/bin/helios-operator"]
