FROM ubuntu:22.04

# Set labels for metadata
LABEL maintainer="DFIR Tools Repository"
LABEL description="Containerized nmap for network security scanning"
LABEL version="1.0"

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update package list and install nmap and required utilities
RUN apt-get update && \
    apt-get install -y \
        nmap \
        netcat-openbsd \
        iputils-ping \
        dnsutils \
        curl \
        wget \
        net-tools \
        iproute2 \
        ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for security
RUN useradd -m -u 1000 -s /bin/bash nmapuser

# Create output directory with appropriate permissions
RUN mkdir -p /output && \
    chown nmapuser:nmapuser /output

# Copy the entrypoint script
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Switch to non-root user
USER nmapuser

# Set working directory
WORKDIR /output

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Default command arguments (can be overridden)
CMD ["--help"]