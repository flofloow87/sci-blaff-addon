ARG BUILD_FROM
FROM $BUILD_FROM

# Image de base HA (Alpine + s6-overlay + bashio déjà inclus).
# Plus besoin de Caddy/TLS ici : l'accès distant passe par l'Ingress de Home
# Assistant (via Nabu Casa), qui gère déjà le HTTPS de bout en bout.
RUN apk add --no-cache nodejs npm python3 make g++

WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev

COPY server.js ./
COPY public ./public

COPY rootfs /
RUN chmod a+x /etc/services.d/sci-app/run

# Le point d'entrée (s6-overlay) est déjà défini par l'image de base HA.
