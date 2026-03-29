FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    DB_PATH=/app/state.db \
    FLAG_PATH=/app/flag.txt \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

# Supervisor + CA certs
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates supervisor \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN python -m pip install -U pip \
  && python -m pip install --no-cache-dir -r /app/requirements.txt

# Install Chromium + Linux deps Playwright needs (done as root)
RUN python -m playwright install --with-deps chromium

COPY app.py /app/app.py
COPY bot_worker.py /app/bot_worker.py
COPY supervisord.conf /app/supervisord.conf
COPY start.sh /app/start.sh
COPY templates /app/templates
COPY static /app/static
COPY flag.txt /app/flag.txt

RUN chmod +x /app/start.sh

# Non-root runtime user
RUN useradd -m -u 10001 appuser \
 && mkdir -p /app \
 && mkdir -p /ms-playwright \
 && chown -R appuser:appuser /app /tmp /ms-playwright

USER appuser

EXPOSE 8080
CMD ["/usr/bin/supervisord", "-c", "/app/supervisord.conf"]
