# Agent Vault isolation image. Built locally on first use by EnsureImage.
FROM node:26-bookworm-slim@sha256:1e96b01216cab31612cd1f9480e83413472dee8686d423cb4c1ec62bf8a26e9e

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
