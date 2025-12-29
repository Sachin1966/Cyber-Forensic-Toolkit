# Base Image
FROM python:3.10-slim

# Install system dependencies for Scapy and PCAP analysis
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set Working Directory for the build process
WORKDIR /app

# Copy Requirements (path relative to root context)
COPY forensic-ai-hub/backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Entire Repo (so we have access to /app/train_dynamic.py, /app/dataset, etc.)
COPY . .

# Change Working Directory to Backend for execution
WORKDIR /app/forensic-ai-hub/backend

# Environment Variables (Overridden by Render)
ENV FLASK_ENV=production
ENV PORT=5000
ENV PYTHONPATH=/app/forensic-ai-hub/backend:$PYTHONPATH

# Expose Port
EXPOSE 5000

# Start Application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
