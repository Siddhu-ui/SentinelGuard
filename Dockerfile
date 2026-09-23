# ---- Stage 1: build the frontend -------------------------------------------
FROM node:22-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- Stage 2: Python backend + built frontend -------------------------------
FROM python:3.12-slim-bookworm
WORKDIR /app/backend

# libmagic1 for python-magic; gcc as a fallback for any sdist-only package
RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 gcc \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./
COPY --from=frontend-build /app/frontend/dist /app/frontend/dist

ENV PYTHONUNBUFFERED=1 \
    PORT=8080 \
    UPLOAD_DIR=/data/uploads \
    DATABASE_URL=sqlite:////data/sentinelguard.db

EXPOSE 8080
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}"]
