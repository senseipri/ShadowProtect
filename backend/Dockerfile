# ── ShadowMesh Backend Dockerfile ─────────────────────────────────────────
FROM python:3.11-slim

# System deps for psutil and aiosqlite
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        gcc \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source (overridden by volume mount in dev)
COPY . .

# Create data directory for SQLite persistence
RUN mkdir -p /app/data

EXPOSE 8000

# --reload enables hot-reload when the volume mount is active
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]