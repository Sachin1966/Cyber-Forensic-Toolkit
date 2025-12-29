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

# Change Working Directory to Package Root
WORKDIR /app/forensic-ai-hub

# Environment Variables (Overridden by Render)
ENV FLASK_ENV=production
ENV PORT=5000

# Expose Port
EXPOSE 5000

# Start Application as a Package
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "backend.app:app"]
