# Build stage
FROM node@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS builder

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci

COPY . .
RUN npm run build

# Production stage
FROM nginx@sha256:fed7e14be83cbd2661a75cdc5b872d936cf155d46c327084d30b8df19ae88d72

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]

# Git commit this image was built from (set by: NETRA_REVISION=$(git rev-parse HEAD) docker compose build).
# Declared last so changing it does not invalidate the build cache.
ARG NETRA_REVISION=unknown
LABEL org.opencontainers.image.revision=$NETRA_REVISION
