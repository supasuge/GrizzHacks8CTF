FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=1337

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app.py /app/app.py
COPY templates /app/templates
COPY static /app/static
COPY scrolls /app/scrolls
COPY scrolls_evil /app/scrolls_evil
COPY scrolls_evil/flag.txt /app/scrolls_evil/flag.txt


RUN useradd -m -u 10001 appuser
USER appuser

EXPOSE 1337
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:1337", "app:app"]

