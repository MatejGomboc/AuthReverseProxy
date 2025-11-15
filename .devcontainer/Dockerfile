FROM debian:13-slim AS downloader

ARG TASK_VERSION=v3.45.5

USER root:root

WORKDIR /root

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates wget && \
    wget -q "https://dl.cloudsmith.io/public/task/task/setup.deb.sh" && \
    wget -q "https://claude.ai/install.sh" && \
    wget -q "https://packages.microsoft.com/config/debian/13/packages-microsoft-prod.deb"

FROM debian:13-slim

LABEL org.opencontainers.image.title="AuthReverseProxy Development Environment" \
    org.opencontainers.image.description="AuthReverseProxy Development Environment" \
    org.opencontainers.image.authors="Matej Gomboc" \
    org.opencontainers.image.source="https://github.com/MatejGomboc" \
    org.opencontainers.image.vendor="https://github.com/MatejGomboc" \
    org.opencontainers.image.licenses="Private"

USER root:root

WORKDIR /root

ENV PATH="/root/.local/bin:${PATH}"

COPY --from=downloader /root/setup.deb.sh /root/
COPY --from=downloader /root/install.sh /root/
COPY --from=downloader /root/packages-microsoft-prod.deb /root/

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ca-certificates git wget curl && \
    \
    bash /root/setup.deb.sh && \
    rm /root/setup.deb.sh && \
    apt-get update && \
    apt-get install -y --no-install-recommends task && \
    \
    bash /root/install.sh && \
    rm /root/install.sh && \
    \
    dpkg -i /root/packages-microsoft-prod.deb && \
    rm /root/packages-microsoft-prod.deb && \
    apt-get update && \
    apt-get install -y --no-install-recommends dotnet-sdk-10.0 && \
    \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/* && \
    task --version && \
    dotnet --info && \
    claude update

CMD ["/bin/bash"]
