#!/bin/bash

# MyMaynDrive APK Analysis Tools Setup Script
# This script installs all necessary tools for comprehensive APK reverse engineering

echo "[+] Starting installation of APK analysis tools..."

# Update package list
sudo apt-get update

# Install basic dependencies
sudo apt-get install -y \
    python3 \
    python3-pip \
    default-jdk \
    git \
    wget \
    curl \
    unzip \
    build-essential \
    android-tools-adb \
    android-tools-fastboot

# Install Python packages for APK analysis
pip3 install --upgrade pip
pip3 install \
    androguard \
    frida-tools \
    objection \
    requests \
    beautifulsoup4 \
    cryptography \
    pyyaml

# Install JADX (Java APK Decompiler)
echo "[+] Installing JADX..."
cd /opt
sudo git clone https://github.com/skylot/jadx.git
cd jadx
sudo ./gradlew build
sudo ln -sf /opt/jadx/build/jadx/bin/jadx /usr/local/bin/jadx
sudo ln -sf /opt/jadx/build/jadx/bin/jadx-gui /usr/local/bin/jadx-gui

# Install APKTool
echo "[+] Installing APKTool..."
cd /opt
sudo wget https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar
sudo mv apktool_2.9.3.jar /usr/local/bin/apktool.jar
sudo wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool
sudo mv apktool /usr/local/bin/
sudo chmod +x /usr/local/bin/apktool

# Install Ghidra (for native code analysis)
echo "[+] Installing Ghidra..."
cd /opt
sudo wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2.1_build/ghidra_11.2.1_PUBLIC_20241107.zip
sudo unzip ghidra_11.2.1_PUBLIC_20241107.zip
sudo ln -sf /opt/ghidra_11.2.1_PUBLIC/ghidraRun /usr/local/bin/ghidra

# Install MobSF (Mobile Security Framework)
echo "[+] Installing MobSF..."
cd /opt
sudo git clone https://github.com/MobSF/Mobile-Security-Framework-MobsF.git
cd Mobile-Security-Framework-MobsF
sudo pip3 install -r requirements.txt

# Create analysis environment
echo "[+] Setting up analysis environment..."
mkdir -p ~/mobsf-data
mkdir -p ~/frida-scripts

# Download common Frida scripts
cat > ~/frida-scripts/ssl_bypass.js << 'EOF'
// SSL Certificate Bypass Script
Java.perform(function() {
    var CertificatePinner = null;
    try {
        CertificatePinner = Java.use('okhttp3.CertificatePinner');
    } catch (err) {
        console.log('[-] OkHttpClient not found');
    }

    if (CertificatePinner) {
        console.log('[+] Bypassing SSL Certificate Pinning');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] SSL Certificate Pinning bypassed for: ' + hostname);
            return;
        };
    }
});
EOF

cat > ~/frida-scripts/api_monitor.js << 'EOF'
// API Monitoring Script
Java.perform(function() {
    console.log('[+] Starting API monitoring...');

    // Monitor SharedPreferences
    var SharedPreferences = Java.use('android.app.SharedPreferencesImpl');
    SharedPreferences.getString.implementation = function(key, defValue) {
        console.log('[SharedPreferences] getString called: ' + key);
        return this.getString(key, defValue);
    };

    // Monitor HttpURLConnection
    var HttpURLConnection = Java.use('java.net.HttpURLConnection');
    HttpURLConnection.connect.implementation = function() {
        console.log('[HTTP] Connection requested to: ' + this.getURL().toString());
        return this.connect();
    };
});
EOF

echo "[+] Installation complete!"
echo ""
echo "[+] Tools installed:"
echo "    - JADX: Java APK Decompiler"
echo "    - APKTool: APK modification and smali analysis"
echo "    - Ghidra: Native code reverse engineering"
echo "    - MobSF: Mobile Security Framework"
echo "    - Androguard: Python APK analysis"
echo "    - Frida: Dynamic instrumentation"
echo "    - Objection: Runtime mobile exploration"
echo ""
echo "[+] Next steps:"
echo "    1. Place your APK file in the analysis directory"
echo "    2. Start Android emulator"
echo "    3. Run: adb devices to verify connection"
echo "    4. Begin analysis with Phase 1 tools"