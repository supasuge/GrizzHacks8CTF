FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 10001 ctf

WORKDIR /chal
COPY chal.py /chal/chal.py
COPY flag.txt /chal/flag.txt
COPY start.sh /chal/start.sh
# immutable permissions/file system


RUN chmod 555 /chal/chal.py /chal/start.sh && chmod 444 /chal/flag.txt

USER ctf
EXPOSE 1347

CMD ["/chal/start.sh"]
