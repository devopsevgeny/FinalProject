# Multi-stage build for ConfMgr frontend

FROM node:22.12.0-alpine AS builder
WORKDIR /app

ARG VITE_API_BASE=/api
ARG VITE_API_KEY=
ENV VITE_API_BASE=${VITE_API_BASE}
ENV VITE_API_KEY=${VITE_API_KEY}

COPY app/package*.json ./
RUN npm config set fetch-retries 6 \
    && npm config set fetch-retry-mintimeout 20000 \
    && npm config set fetch-retry-maxtimeout 180000 \
    && npm config set fetch-timeout 120000 \
    && npm ci
COPY app .
RUN npm run build

FROM nginx:1.27-alpine AS runtime
RUN mkdir -p /etc/nginx/certs
COPY --from=builder /app/dist /usr/share/nginx/html
COPY app/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
EXPOSE 443
CMD ["nginx", "-g", "daemon off;"]
