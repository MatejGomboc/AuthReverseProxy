FROM debian:13-slim AS downloader

WORKDIR /tmp/downloads

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    curl -fsSL -o setup.deb.sh "https://dl.cloudsmith.io/public/task/task/setup.deb.sh" && \
    curl -fsSL -o install.sh "https://claude.ai/install.sh" && \
    curl -fsSL -o packages-microsoft-prod.deb "https://packages.microsoft.com/config/debian/13/packages-microsoft-prod.deb"

FROM debian:13-slim

LABEL org.opencontainers.image.title="AuthReverseProxy Development Environment" \
    org.opencontainers.image.description="AuthReverseProxy Development Environment" \
    org.opencontainers.image.authors="Matej Gomboc" \
    org.opencontainers.image.source="https://github.com/MatejGomboc/AuthReverseProxy" \
    org.opencontainers.image.vendor="https://github.com/MatejGomboc" \
    org.opencontainers.image.licenses="AGPL-3.0-only"

WORKDIR /root

ENV PATH="/root/.local/bin:${PATH}"

COPY --from=downloader /tmp/downloads/* /tmp/

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ca-certificates git curl && \
    # Install Task
    bash /tmp/setup.deb.sh && \
    apt-get update && \
    apt-get install -y --no-install-recommends task && \
    # Install Claude Code
    bash /tmp/install.sh && \
    # Install .NET Core 10 SDK
    dpkg -i /tmp/packages-microsoft-prod.deb && \
    apt-get update && \
    apt-get install -y --no-install-recommends dotnet-sdk-10.0 && \
    # Cleanup
    rm -rf /tmp/* && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    # Verify installations and update Claude Code
    task --version && \
    dotnet --info && \
    claude update

CMD ["/bin/bash"]
