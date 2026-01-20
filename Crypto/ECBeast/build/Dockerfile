FROM python:3.12-slim-bookworm
LABEL maintainer="supasuge"
LABEL description="ECBeast - ECB Byte-at-a-Time Oracle CTF Challenge"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install only what's needed
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    socat \
    supervisor \
    netcat-openbsd \
  && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pycryptodome

# Create unprivileged user
RUN useradd -m -d /home/ctf -s /bin/bash ctf

WORKDIR /challenge
COPY chal.py /challenge/chal.py
COPY flag.txt /challenge/flag.txt
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY entrypoint.sh /challenge/entrypoint.sh

# Permissions:
# - chal readable/executable by all
# - flag readable only by root + group ctf
# - directory accessible by root + group ctf
RUN chmod 555 /challenge/chal.py \
 && chmod 440 /challenge/flag.txt \
 && chown -R root:ctf /challenge \
 && chmod 750 /challenge

EXPOSE 1337

CMD ["/usr/bin/supervisord"]

