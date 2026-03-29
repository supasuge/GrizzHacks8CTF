FROM rust:1.86-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd -r -s /usr/sbin/nologin chall
WORKDIR /home/chall
COPY --from=builder /build/target/release/orbital-salvage /home/chall/orbital-salvage
COPY flag.txt /home/chall/flag.txt
RUN chown -R chall:chall /home/chall && \
    chmod 0555 /home/chall/orbital-salvage && \
    chmod 0444 /home/chall/flag.txt
USER chall
ENV LISTEN_ADDR=0.0.0.0:31337
EXPOSE 31337
CMD ["/home/chall/orbital-salvage"]
