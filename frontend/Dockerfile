# ── Stage 1 : build ──────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Installer les dépendances en premier (layer cache)
COPY package*.json ./
RUN npm ci

# Copier les sources et builder
COPY . .
RUN npm run build

# ── Stage 2 : serve ──────────────────────────────────────────────
FROM nginx:alpine

# Remplacer la config nginx par défaut
COPY nginx.conf /etc/nginx/nginx.conf

# Copier les assets buildés
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
