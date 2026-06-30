# Agent Vault isolation image. Built locally on first use by EnsureImage.
FROM node:26-bookworm-slim@sha256:4e2e85a824f938e41a61e9e819f0c7c11432f7d60f470b96214d3ead2f0dd63e

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      iptables iproute2 ca-certificates curl git python3 gosu iputils-ping \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code

RUN useradd -m -s /bin/bash claude

COPY init-firewall.sh /usr/local/sbin/init-firewall.sh
COPY entrypoint.sh    /usr/local/sbin/entrypoint.sh
RUN chmod 0755 /usr/local/sbin/init-firewall.sh /usr/local/sbin/entrypoint.sh

WORKDIR /workspace

ENTRYPOINT ["/usr/local/sbin/entrypoint.sh"]
CMD ["claude"]
