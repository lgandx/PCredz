# syntax=docker/dockerfile:1
FROM python:3.11-slim-bookworm

LABEL maintainer="Laurent Gaffie <lgaffie@secorizon.com>"
LABEL description="PCredz - Network credential extraction tool"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    gcc \
    g++ \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install --no-cache-dir pcapy-ng

# Create working directory
WORKDIR /opt/Pcredz

# Copy Pcredz
COPY Pcredz /opt/Pcredz/Pcredz

# Create logs directory
RUN mkdir -p /opt/Pcredz/logs

# Make Pcredz executable
RUN chmod +x /opt/Pcredz/Pcredz

# Set entrypoint
ENTRYPOINT ["/opt/Pcredz/Pcredz"]
CMD ["--help"]
