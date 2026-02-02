# Stage 1: Build the Rust server
FROM rust:latest AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace
COPY Cargo.toml Cargo.lock ./
COPY ldk-server ./ldk-server
COPY ldk-server-client ./ldk-server-client
COPY ldk-server-protos ./ldk-server-protos
COPY ldk-server-cli ./ldk-server-cli
COPY ldk-server-gui ./ldk-server-gui

# Build the server binary
RUN cargo build --release --bin ldk-server

# Stage 2: Server runtime
FROM debian:bookworm-slim AS server

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/ldk-server /usr/local/bin/ldk-server
COPY umbrel/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

VOLUME /data
EXPOSE 3001 3002

ENTRYPOINT ["/entrypoint.sh"]

# Stage 3: Web GUI (nginx serving WASM + reverse proxy to API)
FROM nginx:alpine AS web

# Copy pre-built WASM GUI
COPY ldk-server-gui/dist /usr/share/nginx/html

# Nginx config: serve GUI + proxy /api to server
RUN echo 'server { \
    listen 80; \
    root /usr/share/nginx/html; \
    index index.html; \
    \
    location / { \
        try_files $uri $uri/ /index.html; \
    } \
    \
    location /api/ { \
        proxy_pass https://server:3002/; \
        proxy_ssl_verify off; \
        proxy_set_header Host $host; \
        proxy_set_header X-Real-IP $remote_addr; \
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; \
        proxy_set_header X-Forwarded-Proto $scheme; \
    } \
}' > /etc/nginx/conf.d/default.conf

EXPOSE 80
