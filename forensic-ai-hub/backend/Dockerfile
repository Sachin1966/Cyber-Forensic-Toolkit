# Base Image
FROM python:3.10-slim

# Install system dependencies for Scapy and PCAP analysis
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set Working Directory
WORKDIR /app

# Copy Requirements and Install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Application Code
COPY . .

# Environment Variables (Overridden by Render)
ENV FLASK_ENV=production
ENV PORT=5000

# Expose Port
EXPOSE 5000

# Start Application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
