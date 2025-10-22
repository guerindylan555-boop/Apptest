FROM node:20-slim

# Install Android SDK dependencies and automation tools
RUN apt-get update && apt-get install -y \
    openjdk-17-jdk \
    wget \
    unzip \
    python3 \
    python3-pip \
    openssl \
    aapt \
    && rm -rf /var/lib/apt/lists/*

# Install mitmproxy for proxy capture
RUN pip3 install --break-system-packages mitmproxy

# Set up Android SDK
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV PATH="${PATH}:${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin:${ANDROID_SDK_ROOT}/platform-tools"

# Install Android SDK command line tools (adb only, emulator managed externally)
RUN mkdir -p ${ANDROID_SDK_ROOT}/cmdline-tools && \
    wget -q https://dl.google.com/android/repository/commandlinetools-linux-9477386_latest.zip && \
    unzip -q commandlinetools-linux-9477386_latest.zip -d ${ANDROID_SDK_ROOT}/cmdline-tools && \
    mv ${ANDROID_SDK_ROOT}/cmdline-tools/cmdline-tools ${ANDROID_SDK_ROOT}/cmdline-tools/latest && \
    rm commandlinetools-linux-9477386_latest.zip

# Accept licenses and install only the components needed for adb connectivity
RUN yes | sdkmanager --licenses && \
    sdkmanager "platform-tools" "platforms;android-33"

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install all dependencies (including dev for building)
RUN npm ci

# Copy source code
COPY . .

# Build TypeScript
RUN npm run build

# Remove dev dependencies to reduce image size
RUN npm prune --production

# Default to external emulator/streamer integration
ENV EXTERNAL_EMULATOR=true

# Expose backend port
EXPOSE 3001

# Start ADB server in network mode and then start the application
CMD adb -a -P 5037 start-server && npm run start:prod
