# Agent Vault sandbox image. Built locally on first use by EnsureImage.
#
# TODO(v2): pin FROM by @sha256:... digest. Today the content-hash tag
# covers the Dockerfile + scripts only, not the resolved base image.
FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      iptables iproute2 ca-certificates curl git python3 gosu \
 && rm -rf /var/lib/apt/lists/*

RUN npm install -g @anthropic-ai/claude-code

RUN useradd -m -s /bin/bash claude

COPY init-firewall.sh /usr/local/sbin/init-firewall.sh
COPY entrypoint.sh    /usr/local/sbin/entrypoint.sh
RUN chmod 0755 /usr/local/sbin/init-firewall.sh /usr/local/sbin/entrypoint.sh

WORKDIR /workspace

ENTRYPOINT ["/usr/local/sbin/entrypoint.sh"]
CMD ["claude"]
