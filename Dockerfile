# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Set environment variables to avoid writing .pyc files and buffering stdout
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Create and set the working directory
WORKDIR /app

# Install system dependencies (needed for compilation or packet capture if necessary)
# libpcap-dev is required for advanced Scapy sniffing
RUN apt-get update && apt-get install -y \
    gcc \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file and install dependencies
COPY requirements.txt /app/
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

# Create backup and log directories
RUN mkdir -p /app/backups /app/logs /app/reports

# Copy the rest of the application code
COPY . /app/

# Expose the dashboard port (default 5000)
EXPOSE 5000

# The startup script will run both the monitor and dashboard
# We can use a simple bash script or just run the dashboard directly if we are using separate containers.
# Let's run a simple script to start both processes.
COPY docker-entrypoint.sh /app/
RUN chmod +x /app/docker-entrypoint.sh

ENTRYPOINT ["/app/docker-entrypoint.sh"]
