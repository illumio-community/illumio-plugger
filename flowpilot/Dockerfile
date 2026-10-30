# Fetch stage: download the pinned FlowPilot release and verify it against
# SHA256SUMS. FlowPilot (github.com/alexgoller/flowpilot, Apache-2.0) ships a
# static linux binary per arch plus LICENSE/NOTICE/THIRD_PARTY_LICENSES.md,
# which the BSD/MIT licences of its ported+bundled code require us to ship too.
FROM python:3.12-slim AS fetch
ARG FLOWPILOT_VERSION=0.9.0
ARG TARGETARCH=amd64
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) A=x86_64 ;; \
      arm64) A=aarch64 ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    base="https://github.com/alexgoller/flowpilot/releases/download/v${FLOWPILOT_VERSION}"; \
    cd /tmp; \
    curl -fsSL -o flowpilot "$base/flowpilot-${FLOWPILOT_VERSION}-${A}-linux"; \
    curl -fsSL -o SHA256SUMS "$base/SHA256SUMS"; \
    curl -fsSL -o LICENSE "$base/LICENSE"; \
    curl -fsSL -o NOTICE "$base/NOTICE"; \
    curl -fsSL -o THIRD_PARTY_LICENSES.md "$base/THIRD_PARTY_LICENSES.md"; \
    grep "flowpilot-${FLOWPILOT_VERSION}-${A}-linux" SHA256SUMS \
      | sed "s#flowpilot-${FLOWPILOT_VERSION}-${A}-linux#flowpilot#" \
      | sha256sum -c -; \
    chmod +x flowpilot

FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# FlowPilot binary + the licence files it ships with.
COPY --from=fetch /tmp/flowpilot /usr/local/bin/flowpilot
COPY --from=fetch /tmp/LICENSE /tmp/NOTICE /tmp/THIRD_PARTY_LICENSES.md /usr/local/share/flowpilot/

COPY . .

COPY plugin.yaml /.plugger/plugin.yaml
COPY .plugger/metadata.yaml /.plugger/metadata.yaml

EXPOSE 8080
EXPOSE 2055/udp 4739/udp 6343/udp 514/udp
CMD ["python3", "main.py"]
