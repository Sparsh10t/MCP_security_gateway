FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npx tsc --noEmit

FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY --from=builder /app/src ./src
COPY tsconfig.json ./
COPY config ./config
COPY policies ./policies
EXPOSE 5000
CMD ["npx", "tsx", "src/server.ts"]
