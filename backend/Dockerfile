FROM node:20-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install Android emulator dependencies and useful tooling
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    unzip \
    openjdk-17-jdk \
    python3 \
    python3-pip \
    qemu-kvm \
    libvirt-daemon-system \
    libvirt-clients \
    libglu1-mesa \
    libgl1-mesa-dev \
    libx11-6 \
    libxcb1 \
    libnss3 \
    libxcursor1 \
    libxrandr2 \
    libxi6 \
    libxrender1 \
    libxfixes3 \
    libxdamage1 \
    libxtst6 \
    libxcomposite1 \
    libasound2 \
    libpulse0 \
    libsdl2-2.0-0 \
    libdbus-glib-1-2 \
    libnotify4 \
    socat \
    net-tools \
    aapt \
    && rm -rf /var/lib/apt/lists/*

# Install mitmproxy for proxy capture
RUN pip3 install --break-system-packages mitmproxy

# Android SDK environment configuration
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV ANDROID_HOME=${ANDROID_SDK_ROOT}
ENV ANDROID_AVD_HOME=${ANDROID_SDK_ROOT}/avd
ENV PATH=$PATH:${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin:${ANDROID_SDK_ROOT}/platform-tools:${ANDROID_SDK_ROOT}/emulator

# Install Android command line tools
RUN mkdir -p ${ANDROID_SDK_ROOT}/cmdline-tools && \
    wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip -O /tmp/cmdline-tools.zip && \
    unzip -q /tmp/cmdline-tools.zip -d ${ANDROID_SDK_ROOT}/cmdline-tools && \
    mv ${ANDROID_SDK_ROOT}/cmdline-tools/cmdline-tools ${ANDROID_SDK_ROOT}/cmdline-tools/latest && \
    rm /tmp/cmdline-tools.zip

# Accept licenses and install emulator + system image
RUN yes | sdkmanager --licenses && \
    sdkmanager \
      "platform-tools" \
      "emulator" \
      "platforms;android-34" \
      "system-images;android-34;google_apis;x86_64"

# Create a default AVD with snapshots disabled
RUN mkdir -p ${ANDROID_AVD_HOME} && \
    echo "no" | avdmanager create avd -n autoapp-local -k "system-images;android-34;google_apis;x86_64" --device "pixel_6" --force && \
    printf '\nfastboot.forceColdBoot = yes\nfastboot.forceFastBoot = no\nfirstboot.bootFromDownloadableSnapshot = no\nfirstboot.bootFromLocalSnapshot = no\nfirstboot.saveToLocalSnapshot = no\n' >> ${ANDROID_AVD_HOME}/autoapp-local.avd/config.ini && \
    rm -rf ${ANDROID_AVD_HOME}/autoapp-local.avd/snapshots

# Install ws-scrcpy globally for streaming
RUN npm install -g ws-scrcpy

WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
RUN npm ci

# Copy source and build
COPY . .
RUN npm run build && npm prune --production

# Entrypoint script to start adb server before the app
COPY scripts/entrypoint.sh /usr/local/bin/backend-entrypoint.sh
RUN chmod +x /usr/local/bin/backend-entrypoint.sh

ENV EXTERNAL_EMULATOR=false \
    AVD_NAME=autoapp-local \
    EMULATOR_CONSOLE_PORT=5554 \
    EMULATOR_ADB_PORT=5555 \
    ADB_SERVER_PORT=5555 \
    ANDROID_ADB_SERVER_PORT=5555 \
    ADB_SERVER_SOCKET=tcp:127.0.0.1:5555 \
    WS_SCRCPY_PORT=8000 \
    WS_SCRCPY_BIN=/usr/local/bin/ws-scrcpy

EXPOSE 3001 8000 5555

ENTRYPOINT ["/usr/local/bin/backend-entrypoint.sh"]
