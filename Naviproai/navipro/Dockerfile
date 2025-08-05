# Stage 1: Install production dependencies
# This stage creates a lean node_modules folder with only production dependencies.
FROM node:20-alpine AS dependencies

# Set the working directory
WORKDIR /usr/src/app

# Copy package files and install only production dependencies
COPY package.json package-lock.json* ./
RUN npm install --omit=dev


# Stage 2: Build the application
# This stage builds the TypeScript source code into JavaScript.
FROM node:20-alpine AS builder

WORKDIR /usr/src/app

# Copy package files and install ALL dependencies (including devDependencies)
COPY package.json package-lock.json* ./
RUN npm install

# Copy the rest of the application source code
COPY . .

# Generate the production build using the script from your package.json
RUN npm run build


# Stage 3: Setup the final production image
# This stage creates the final, small image to be deployed.
FROM node:20-alpine AS production

ENV NODE_ENV=production
WORKDIR /usr/src/app

# Copy the pruned production dependencies and the compiled code from previous stages
COPY --from=dependencies /usr/src/app/node_modules ./node_modules
COPY --from=builder /usr/src/app/dist ./dist
COPY package.json .

# The "start:prod" script in your package.json is "node dist/main"
CMD ["node", "dist/main"]
