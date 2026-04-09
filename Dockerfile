# Stage 1: Build
FROM rust:1.77-bookworm AS builder
WORKDIR /build
COPY . .
RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates librocksdb-dev && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/rustoshi /usr/local/bin/rustoshi
RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 8333 8332
ENTRYPOINT ["rustoshi"]
CMD ["--datadir=/data", "--network", "mainnet"]
