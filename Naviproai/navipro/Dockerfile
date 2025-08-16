# ---- Base Stage ----
# Use a specific Node.js version for consistency.
FROM node:20-alpine AS base
WORKDIR /usr/src/app

# ---- Dependencies Stage ----
FROM base AS dependencies
# Copy package.json and package-lock.json
COPY package*.json ./
# Install all dependencies, including devDependencies for the build step
RUN npm install

# ---- Build Stage ----
FROM dependencies AS build
# Copy the rest of the application source code
COPY . .
# Build the application
RUN npm run build

# ---- Production Stage ----
FROM base AS production
# Copy built artifacts and production node_modules from previous stages
COPY --from=build /usr/src/app/dist ./dist
COPY --from=dependencies /usr/src/app/node_modules ./node_modules

EXPOSE 3000
# Command to run the application
CMD ["node", "dist/main"]