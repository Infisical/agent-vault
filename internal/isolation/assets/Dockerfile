# Agent Vault isolation image. Built locally on first use by EnsureImage.
FROM node:26-bookworm-slim@sha256:79723b41edbedf595f62e943a9f8b0ba9af5b1e61045c5f8f59c2c02c1212a16

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
