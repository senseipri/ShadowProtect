# ── ShadowMesh Frontend Dockerfile ────────────────────────────────────────
FROM node:20-alpine

RUN apk add --no-cache curl

WORKDIR /app

# Install pnpm globally (matches packageManager field in package.json)
RUN npm install -g pnpm

# Install dependencies first (cache layer)
COPY package.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile

# Copy source (overridden by volume mount in dev)
COPY . .

EXPOSE 3000

# next dev enables hot-reload when the volume mount is active
CMD ["pnpm", "dev"]