ARG BUILD_FROM
FROM $BUILD_FROM

# Image de base HA (Alpine + s6-overlay + bashio déjà inclus).
# v3.4.0 : Caddy retiré — le reverse proxy TLS est maintenant géré par
# Nginx Proxy Manager (point d'entrée central pour tous les services HA),
# qui redirige en interne vers le port 3000 de cet add-on. L'Ingress HA
# reste disponible comme accès de secours.

RUN apk add --no-cache nodejs npm python3 make g++

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev

COPY server.js ./
COPY public ./public

COPY rootfs /
RUN chmod a+x /etc/services.d/sci-app/run \
    && chmod a+x /etc/cont-init.d/*.sh 2>/dev/null || true

# Le point d'entrée (s6-overlay) est déjà défini par l'image de base HA.
