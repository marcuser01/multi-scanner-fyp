# Stage 1: Build the React Application
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# Stage 2: Serve with Nginx over HTTPS (Non-Root Hardened)
FROM nginx:alpine

# Install OpenSSL and generate a self-signed certificate for local HTTPS testing
RUN apk add --no-cache openssl && \
    mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt \
    -subj "/C=MY/ST=Selangor/L=Puchong/O=RiskwiseSecurity/CN=localhost"

# Copy custom hardened config
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html

# HARDENING & EXPLICIT SYSTEMS FIXES:
# 1. Strip the "user" directive entirely (only valid if started as root)
# 2. Use a robust, POSIX-compatible sed regex to redirect the PID path to /tmp/nginx.pid
RUN sed -i '/user  nginx;/d' /etc/nginx/nginx.conf && \
    sed -i 's|pid .*|pid /tmp/nginx.pid;|g' /etc/nginx/nginx.conf

# HARDENING: Grant unprivileged 'nginx' user full ownership over required system write/read paths
# We include /var/lib/nginx (Crucial: Alpine writes temp client bodies here) and /var/log/nginx
RUN mkdir -p /var/cache/nginx \
             /var/log/nginx \
             /var/lib/nginx/tmp/client_body \
             /var/lib/nginx/tmp/proxy \
             /var/lib/nginx/tmp/fastcgi \
             /var/lib/nginx/tmp/uwsgi \
             /var/lib/nginx/tmp/scgi \
    && chown -R nginx:nginx /usr/share/nginx/html \
                            /var/cache/nginx \
                            /var/log/nginx \
                            /var/lib/nginx \
                            /etc/nginx \
    && chmod -R 770 /var/lib/nginx

# Switch to the default non-root Nginx system user (UID 101)
USER nginx

# Expose unprivileged HTTP and HTTPS ports
EXPOSE 8080 8443

CMD ["nginx", "-g", "daemon off;"]