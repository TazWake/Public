---
description: Rules for building and reviewing Docker components, including dockerfiles, docker-compose.yml and related files.
globs:
alwaysApply: false
---

- Apply these rules unless explicitly instructed otherwise in the chat.
- If you are unsure about the applicability of a rule, ask questions for clarity.

# Docker files

Use a Minimal Base Image: Start with a lean, minimal base image like alpine, scratch, or distroless to reduce the attack surface. Smaller images contain fewer packages, fewer vulnerabilities, and are faster to download.

Run as a Non-root User: Include a USER instruction to run the application as a non-privileged user. This is a critical security practice to prevent container breakout and limit the impact of a compromised container.

Multi-stage Builds: Use multi-stage builds to create a lean final image. The first stage can include build dependencies (like compilers), while the final stage only contains the application and its runtime dependencies. This drastically reduces the image size.

Pin Image Versions: Always specify a version tag for your base image (e.g., FROM python:3.9-slim-buster) instead of using latest. This ensures reproducible builds and prevents unexpected changes.

Clean Up After Installation: Use a single RUN instruction with chained commands (&&) to install packages and immediately clean up the package manager's cache. This prevents unnecessary layers and reduces the final image size.

Copy Only What's Needed: Use a .dockerignore file to exclude unnecessary files like .git directories, README.md files, or test data. This keeps the build context small and the final image size minimal.

Avoid Sensitive Data: Never hardcode secrets, passwords, or API keys directly in the Dockerfile. Use build arguments with ARG and docker build --secret, or better yet, use a secret management system like Docker Secrets or Kubernetes Secrets at runtime.

One Process Per Container: Design your containers to run a single, primary process. This follows the UNIX philosophy and simplifies monitoring, scaling, and debugging.

Sign and Scan Images: Integrate image signing and scanning into your CI/CD pipeline. Use tools like Docker Content Trust or vulnerability scanners like Trivy or Clair to ensure the integrity and security of your images.

# Docker Compose Files

Define and Isolate Networks: Explicitly define and use networks in your docker-compose.yml file. This allows you to control which containers can communicate with each other and isolate services that don't need to interact.

Use restart Policies: Implement restart policies like on-failure or unless-stopped to ensure services automatically recover from failures. This is crucial for maintaining uptime and availability.

Manage Volumes Securely: Be mindful of volume mounts. Bind mounts (volumes: - /host/path:/container/path) can be a security risk if not managed carefully. Prefer named volumes, which are managed by Docker and are more secure by default.

Limit Resource Usage: Use the mem_limit and cpu_shares options to set resource constraints for your containers. This prevents a single misbehaving container from consuming all system resources and impacting other services.

Map Ports Carefully: Only map ports that are absolutely necessary to expose to the host machine. Use ports to map specific ports and expose to simply make a port available to other linked services on the same network.

Leverage Environment Files: Instead of hardcoding environment variables in the docker-compose.yml file, use .env files. This keeps configuration separate from the service definition and prevents sensitive information from being exposed in source control.

Implement Health Checks: Use the healthcheck instruction to define how to test a container's health. This allows Docker Compose to automatically restart unhealthy containers, improving the overall reliability of your services.

Keep Services Up-to-Date: Regularly update the image tags in your compose file to pull the latest versions of your services and their dependencies. This is a basic but crucial step to patch known vulnerabilities.