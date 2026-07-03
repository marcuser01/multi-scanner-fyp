# Use official Python runtime as a parent image
FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Install OS-level dependencies (WeasyPrint PDF, Curl, Docker CLI)
RUN apt-get update && apt-get install -y \
    curl wget apt-transport-https ca-certificates gnupg \
    libpango-1.0-0 libpangoft2-1.0-0 libffi-dev libgdk-pixbuf-2.0-0 libhtml-parser-perl \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy Binary
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Create non-root system user (UID 1000)
RUN groupadd -g 1000 riskwise && useradd -u 1000 -g riskwise -m riskwise

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application and set ownership to non-root user
COPY . .
RUN mkdir -p /app/data /app/uploads && chown -R riskwise:riskwise /app

# Switch to non-root user
USER riskwise

# Configure the entrypoint script
RUN chmod +x /app/scripts/entrypoint.sh
EXPOSE 8000
CMD ["/app/scripts/entrypoint.sh"]