FROM alpine:3.20

RUN apk add --no-cache \
    python3 py3-pip py3-virtualenv \
    nginx openssl ca-certificates \
    bash \
    build-base libffi-dev openssl-dev python3-dev cargo

WORKDIR /app

# Create venv and install pinned deps inside it
RUN python3 -m venv /opt/venv \
 && . /opt/venv/bin/activate \
 && pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir cryptography==42.0.8 requests==2.32.3

ENV PATH="/opt/venv/bin:$PATH"

COPY script.py /app/generate_pki.py
COPY entrypoint.sh /app/entrypoint.sh
COPY nginx.conf.template /app/nginx.conf.template

RUN chmod +x /app/entrypoint.sh

EXPOSE 80 443
ENTRYPOINT ["/app/entrypoint.sh"]