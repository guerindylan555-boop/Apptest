FROM node:20-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install Android tooling dependencies and useful tooling
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    unzip \
    openjdk-17-jdk \
    python3 \
    python3-pip \
    socat \
    net-tools \
    aapt \
    && rm -rf /var/lib/apt/lists/*

# Install mitmproxy for proxy capture
RUN pip3 install --break-system-packages mitmproxy

# Android SDK environment configuration
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_HOME=${ANDROID_SDK_ROOT}
ENV PATH=$PATH:${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin:${ANDROID_SDK_ROOT}/platform-tools

# Install Android command line tools
RUN mkdir -p ${ANDROID_SDK_ROOT}/cmdline-tools && \
    wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O /tmp/cmdline-tools.zip && \
    unzip -q /tmp/cmdline-tools.zip -d ${ANDROID_SDK_ROOT}/cmdline-tools && \
    mv ${ANDROID_SDK_ROOT}/cmdline-tools/cmdline-tools ${ANDROID_SDK_ROOT}/cmdline-tools/latest && \
    rm /tmp/cmdline-tools.zip

# Accept licenses and install platform tools (adb, fastboot)
RUN yes | sdkmanager --licenses && \
    sdkmanager \
      "platform-tools"

# Copy backend package files and install dependencies
WORKDIR /app
COPY backend/package*.json ./
RUN npm ci

# Copy backend source and build
COPY backend/ ./
RUN npm run build && npm prune --production

# Entrypoint script to start adb server before the app
COPY backend/scripts/entrypoint.sh /usr/local/bin/backend-entrypoint.sh
RUN chmod +x /usr/local/bin/backend-entrypoint.sh

ENV EXTERNAL_EMULATOR=false \
    AVD_NAME=autoapp-external \
    EMULATOR_ADB_PORT=5555 \
    EMULATOR_GRPC_ENDPOINT=http://envoy:8080 \
    EMULATOR_WEBRTC_PUBLIC_URL=http://127.0.0.1:9000

EXPOSE 3001

ENTRYPOINT ["/usr/local/bin/backend-entrypoint.sh"]
