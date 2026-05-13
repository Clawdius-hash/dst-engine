FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y \
    git \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/dst-engine

RUN git clone https://github.com/MassDeterministicEngines/dst-engine.git .

RUN npm install -g tsx
RUN npm install --legacy-peer-deps

RUN printf '#!/bin/sh\nexec tsx /opt/dst-engine/src/dst-cli.ts "$@"\n' \
    > /usr/local/bin/dst-cli \
    && chmod +x /usr/local/bin/dst-cli

ENV NODE_ENV=production

# Keep it empty for CI systems
# Run it with just dst-cli <flags>
ENTRYPOINT []
