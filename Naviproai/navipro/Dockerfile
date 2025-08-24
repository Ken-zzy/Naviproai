# Stage 1: Builder
# This stage installs all dependencies (including dev) and builds the app.
FROM node:20-alpine AS builder

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install --legacy-peer-deps

COPY . .
RUN npm run build

# Stage 2: Production
# This stage creates the final, lean image for production.
FROM node:20-alpine AS production

WORKDIR /usr/src/app
ENV NODE_ENV=production

# Copy package.json and package-lock.json from the builder stage
COPY --from=builder /usr/src/app/package*.json ./
RUN npm ci --only=production --legacy-peer-deps
COPY --from=builder /usr/src/app/dist ./dist

EXPOSE 3000
CMD ["node", "dist/src/main.js"]