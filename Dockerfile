# Multi-stage build for React Frontend + Flask Backend

# Stage 1: Build Frontend
FROM node:18-alpine AS frontend-builder
WORKDIR /app
COPY forensic-ai-hub/package*.json ./
RUN npm install
COPY forensic-ai-hub/ ./
RUN npm run build

# Stage 2: Production Runtime
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Backend Dependencies
COPY forensic-ai-hub/backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Backend Code
COPY forensic-ai-hub/backend ./backend
COPY forensic-ai-hub/backend/predictions ./backend/predictions
COPY forensic-ai-hub/backend/utils ./backend/utils
COPY forensic-ai-hub/backend/models ./backend/models
COPY forensic-ai-hub/backend/database.py ./backend/

# Copy Built Frontend Assets
COPY --from=frontend-builder /app/dist/index.html ./backend/templates/index.html
COPY --from=frontend-builder /app/dist/assets ./backend/static/assets

# Environment Variables
ENV FLASK_APP=backend/app.py
ENV PYTHONPATH=/app

# Expose Port
EXPOSE 5000

# Run with Gunicorn (Production)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "backend.app:app"]
