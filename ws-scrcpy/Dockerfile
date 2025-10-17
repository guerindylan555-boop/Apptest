FROM node:20-slim

# Install necessary dependencies for ADB and ws-scrcpy
RUN apt-get update && apt-get install -y \
    adb \
    android-tools-adb \
    build-essential \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install all dependencies (including dev for building)
RUN npm ci

# Copy source code
COPY . .

# Build the application
RUN npm run dist

# Change to dist directory
WORKDIR /app/dist

# Expose ws-scrcpy port
EXPOSE 8000

# Start the application
CMD ["npm", "start"]
