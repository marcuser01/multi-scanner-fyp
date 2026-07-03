# Stage 1: Build the React Application
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# Stage 2: Serve with Nginx over HTTPS
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

# Expose both HTTP and HTTPS ports
EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]