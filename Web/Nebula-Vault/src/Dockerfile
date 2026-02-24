FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.txt /app/requirements.txt
# Install minimal runtime dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app.py /app/app.py
COPY templates /app/templates
COPY static /app/static
COPY uploads /app/uploads
COPY flag.txt /app/flag.txt

# Ensure proper permissions
RUN chmod 444 /app/flag.txt && \
    chmod 755 /app/uploads

# Expose updated port
EXPOSE 6969

# Run via Gunicorn on port 6969
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:6969", "app:app"]