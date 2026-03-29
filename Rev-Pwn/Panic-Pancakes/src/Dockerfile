## PANCAKE PANIC — Dockerfile
#
# This Dockerfile builds and runs the challenge in an isolated
# environment. It compiles the vulnerable binary in a builder stage to
# ensure the libc version used at compile time matches what will be
# available at runtime. The final image only includes the compiled
# binary, the flag and socat to expose the service on a TCP port.

FROM ubuntu:22.04 AS builder

# Install just enough packages to compile a C program.
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libc6-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY pancake_panic.c .

# Build the binary. The flags mirror those in the Makefile so that
# the compiled binary behaves identically to local builds. The final
# release binary is stripped of symbols (-s) to make reverse
# engineering slightly harder.
RUN gcc pancake_panic.c -o pancake_panic \
        -fno-stack-protector \
        -z execstack \
        -no-pie \
        -O0 \
        -m64 \
        -fcf-protection=none \
        -s \
        -w

FROM ubuntu:22.04

# Minimal runtime: socat to serve the binary over TCP. We install no
# compilers or development tools in the runtime image.
RUN apt-get update && \
    apt-get install -y --no-install-recommends socat && \
    rm -rf /var/lib/apt/lists/*

# Create an unprivileged user for the challenge and copy the binary
# and flag into their home directory. The binary will run setuid
# root so that it can read the flag (which is root‑owned) but the
# network service itself runs as the unprivileged user.
RUN useradd --no-create-home --shell /usr/sbin/nologin --uid 1337 ctf
WORKDIR /home/ctf
COPY --from=builder /build/pancake_panic ./pancake_panic
COPY flag.txt ./flag.txt

# Set correct permissions. The flag is readable only by root and the
# binary is owned by root but executable by the ctf user. The setuid
# bit (4750) allows the binary to run as root when executed by ctf.
RUN chown root:root flag.txt && chmod 400 flag.txt && \
    chown root:ctf pancake_panic && chmod 4750 pancake_panic

# Drop privileges for the network service itself. Although the binary
# runs with elevated privileges due to the setuid bit, socat and its
# child processes run as the ctf user. This helps limit the impact
# of unexpected behaviour.
USER ctf

EXPOSE 7331
`
# socat forks a new PTY for each incoming connection. A timeout of
# 120 seconds prevents hung connections from persisting indefinitely.
CMD ["socat", "TCP-LISTEN:7331,reuseaddr,fork", "EXEC:./pancake_panic,pty,rawer,sigint,sighup,timeout=120"]