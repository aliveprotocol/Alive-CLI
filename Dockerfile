# Start with a base Python 3.10 image
FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libsm6 \
    libxext6 \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Working directory in the container
WORKDIR /app

# Copy project files
COPY . .

# Install
RUN pip install . --use-pep517

# Default variables
ENV ALIVE_BATCH_INTERVAL=60
ENV ALIVE_DATA_DIR=/app/data
ENV ALIVE_RECORD_FOLDER=/app/record

# Run daemon
CMD ["alive_docker"]