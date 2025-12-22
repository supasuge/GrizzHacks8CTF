#!/bin/sh
set -eu

# -T 60: idle timeout
# -t 60: read timeout
# fork: handle multiple clients
exec socat -T 60 -t 60 TCP-LISTEN:1347,reuseaddr,fork EXEC:"python3 /chal/chal.py",pty,stderr,setsid,sigint,sane
