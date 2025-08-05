# Multi-stage build for optimized image size
FROM ubuntu:22.04 AS builder

# Set labels for metadata
LABEL maintainer="DFIR Tools Repository"
LABEL description="Containerized nmap for network security scanning"
LABEL version="2.0"
LABEL org.opencontainers.image.source="https://github.com/your-repo/nmap-container"
LABEL org.opencontainers.image.documentation="https://github.com/your-repo/nmap-container/blob/main/README.md"
LABEL org.opencontainers.image.licenses="MIT"

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Create cache mount directory for better build caching
RUN mkdir -p /var/cache/apt/archives/partial

# Update package list and install build dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        netcat-openbsd \
        iputils-ping \
        dnsutils \
        curl \
        wget \
        net-tools \
        iproute2 \
        ca-certificates \
        procps \
        tini

# Production stage with minimal components
FROM ubuntu:22.04 AS production

# Copy tini for proper signal handling
COPY --from=builder /usr/bin/tini /usr/bin/tini

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install only runtime dependencies
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        nmap \
        netcat-openbsd \
        iputils-ping \
        dnsutils \
        curl \
        wget \
        net-tools \
        iproute2 \
        ca-certificates \
        procps && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && \
    find /var/log -type f -exec truncate -s 0 {} \;

# Create a non-root user for security with specific UID/GID
RUN groupadd -g 1000 nmapgroup && \
    useradd -m -u 1000 -g 1000 -s /bin/bash nmapuser && \
    usermod -L nmapuser

# Create output directory with appropriate permissions and proper structure
RUN mkdir -p /output /tmp/nmap-temp && \
    chown -R nmapuser:nmapgroup /output /tmp/nmap-temp && \
    chmod 755 /output && \
    chmod 1777 /tmp/nmap-temp

# Copy the entrypoint script with proper ownership
COPY --chown=root:root entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh

# Add health check for container monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD nmap --version >/dev/null 2>&1 || exit 1

# Set environment variables for optimization
ENV NMAP_PRIVILEGED=0 \
    NMAP_TEMP_DIR=/tmp/nmap-temp \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Switch to non-root user
USER nmapuser

# Set working directory
WORKDIR /output

# Use tini as PID 1 for proper signal handling
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]

# Default command arguments (can be overridden)
CMD ["--help"]