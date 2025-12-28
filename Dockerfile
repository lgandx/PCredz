# Dockerfile for PCredz with pcapy-ng
FROM python:3.11-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpcap0.8 \
    libpcap-dev \
    gcc \
    file \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /opt/pcredz

# Copy application files
COPY requirements.txt setup.py ./
COPY pcredz/ ./pcredz/
COPY run_pcredz.py ./
COPY README.md ./
COPY tests/ ./tests/

# Install PCredz
RUN pip install --no-cache-dir -e .

# Create logs directory
RUN mkdir -p logs

# Set Python environment
ENV PYTHONUNBUFFERED=1

# Default working directory for PCAPs
WORKDIR /pcaps

# Entry point
ENTRYPOINT ["python3", "-m", "pcredz"]
CMD ["--help"]

# Build: docker build -t pcredz .
# Run:   docker run -v $(pwd):/pcaps pcredz -f /pcaps/capture.pcap -o /pcaps/logs/
# Live:  docker run --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN pcredz -i eth0
