# syntax=docker/dockerfile:1
# Build context: apps/ui.  docker build apps/ui
FROM --platform=$BUILDPLATFORM node:24-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

# Static files + /api reverse proxy. Runs as uid 101 on port 8080.
FROM nginxinc/nginx-unprivileged:1.29-alpine
ENV API_URL=http://cvedetector-api:8080
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8080
