ARG BUILD_FROM
FROM $BUILD_FROM

# Image de base HA (Alpine + s6-overlay + bashio déjà inclus).
# v3.0.0 : réintroduction de Caddy comme reverse proxy TLS, en plus de
# l'Ingress HA (conservé comme accès de secours). Caddy gère automatiquement
# les certificats Let's Encrypt via HTTP-01 sur le port 80.

RUN apk add --no-cache nodejs npm python3 make g++ curl

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev

COPY server.js ./
COPY public ./public

# Téléchargement du binaire Caddy officiel depuis les releases GitHub (plus
# fiable que l'API caddyserver.com/api/download, et qu'un paquet Alpine
# potentiellement absent/ancien sur armv7). Version figée pour la reproductibilité.
ARG BUILD_ARCH
ENV CADDY_VERSION=2.8.4
RUN set -eu; \
    case "${BUILD_ARCH}" in \
      amd64)   CADDY_ARCH=amd64 ;; \
      aarch64) CADDY_ARCH=arm64 ;; \
      armv7)   CADDY_ARCH=armv7 ;; \
      armhf)   CADDY_ARCH=armv6 ;; \
      i386)    CADDY_ARCH=386 ;; \
      *) echo "Architecture non supportée pour Caddy : ${BUILD_ARCH}" && exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/caddyserver/caddy/releases/download/v${CADDY_VERSION}/caddy_${CADDY_VERSION}_linux_${CADDY_ARCH}.tar.gz" -o /tmp/caddy.tar.gz; \
    tar xzf /tmp/caddy.tar.gz -C /usr/local/bin caddy; \
    rm /tmp/caddy.tar.gz; \
    chmod +x /usr/local/bin/caddy; \
    /usr/local/bin/caddy version

COPY rootfs /
RUN chmod a+x /etc/services.d/sci-app/run \
    && chmod a+x /etc/services.d/caddy/run \
    && chmod a+x /etc/cont-init.d/*.sh 2>/dev/null || true

# Le point d'entrée (s6-overlay) est déjà défini par l'image de base HA.
