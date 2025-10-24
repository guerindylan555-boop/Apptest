#!/usr/bin/env python3
"""
Phase 3: Dynamic Analysis Framework for MyMaynDrive APK
This script handles runtime analysis using Frida and other dynamic tools
"""

import os
import sys
import subprocess
import time
import json
import argparse
from pathlib import Path
from datetime import datetime

class DynamicAnalyzer:
    def __init__(self, package_name, output_dir):
        self.package_name = package_name
        self.output_dir = Path(output_dir)
        self.phase3_dir = self.output_dir / "phase3_dynamic"
        self.phase3_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories
        self.frida_scripts_dir = self.phase3_dir / "frida_scripts"
        self.frida_logs_dir = self.phase3_dir / "frida_logs"
        self.network_logs_dir = self.phase3_dir / "network_logs"
        self.memory_dumps_dir = self.phase3_dir / "memory_dumps"

        for dir in [self.frida_scripts_dir, self.frida_logs_dir,
                   self.network_logs_dir, self.memory_dumps_dir]:
            dir.mkdir(exist_ok=True)

    def log(self, message, phase="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{phase}] {message}")

    def check_device_connection(self):
        """Check if Android device/emulator is connected"""
        try:
            result = subprocess.run(["adb", "devices"], capture_output=True, text=True)
            if "device" in result.stdout and len(result.stdout.strip().split('\n')) > 2:
                self.log("Android device connected")
                return True
            else:
                self.log("No Android device connected", "ERROR")
                return False
        except Exception as e:
            self.log(f"Failed to check device connection: {e}", "ERROR")
            return False

    def install_frida_server(self):
        """Install Frida server on the device"""
        self.log("Installing Frida server on device...")

        try:
            # Get device architecture
            result = subprocess.run(["adb", "shell", "getprop", "ro.product.cpu.abi"],
                                  capture_output=True, text=True)
            arch = result.stdout.strip()

            # Download Frida server (this would need to be automated)
            frida_server_url = f"https://github.com/frida/frida/releases/latest/download/frida-server-{arch}-android.xz"

            self.log(f"Frida server URL for {arch}: {frida_server_url}")
            self.log("Please manually download and install Frida server:")
            self.log(f"1. wget {frida_server_url}")
            self.log("2. unxz frida-server-*.xz")
            self.log("3. adb push frida-server-* /data/local/tmp/")
            self.log("4. adb shell 'chmod 755 /data/local/tmp/frida-server-*'")
            self.log("5. adb shell '/data/local/tmp/frida-server-* &'")

            return {"status": "manual_install_required", "arch": arch, "url": frida_server_url}

        except Exception as e:
            self.log(f"Failed to prepare Frida server installation: {e}", "ERROR")
            return {"status": "failed", "error": str(e)}

    def create_frida_scripts(self):
        """Create comprehensive Frida scripts for MyMaynDrive analysis"""
        self.log("Creating Frida analysis scripts...")

        scripts = {}

        # SSL Pinning Bypass Script
        ssl_script = """
// Comprehensive SSL Certificate Pinning Bypass
Java.perform(function() {
    console.log("[+] Starting SSL pinning bypass...");

    // TrustManager implementation bypass
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocsp, certPin) {
        console.log('[+] Bypassed TrustManagerImpl for: ' + host);
        return untrustedChain;
    };

    // OkHttp3 CertificatePinner bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log('[+] Bypassed OkHttp3 CertificatePinner for: ' + hostname);
            return;
        };
        console.log('[+] OkHttp3 CertificatePinner bypass loaded');
    } catch (err) {
        console.log('[-] OkHttp3 not found');
    }

    // HttpsURLConnection bypass
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultSSLSocketFactory.implementation = function(sslSocketFactory) {
            console.log('[+] Bypassed HttpsURLConnection SSL factory');
            return;
        };
    } catch (err) {
        console.log('[-] HttpsURLConnection bypass failed');
    }

    console.log('[+] SSL pinning bypass complete');
});
"""

        # Network Traffic Monitoring Script
        network_script = """
// Network Traffic Monitoring
Java.perform(function() {
    console.log("[+] Starting network traffic monitoring...");

    // Hook HttpURLConnection
    var HttpURLConnection = Java.use('java.net.HttpURLConnection');
    HttpURLConnection.connect.implementation = function() {
        var url = this.getURL().toString();
        console.log('[HTTP] Connecting to: ' + url);
        this.connect();
    };

    // Hook OkHttpClient
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        OkHttpClient.newCall.implementation = function(request) {
            var url = request.url().toString();
            var method = request.method();
            console.log('[OkHttp] ' + method + ' ' + url);

            // Log headers
            var headers = request.headers();
            for (var i = 0; i < headers.size(); i++) {
                console.log('[Header] ' + headers.name(i) + ': ' + headers.value(i));
            }

            return this.newCall(request);
        };
    } catch (err) {
        console.log('[-] OkHttpClient not found');
    }

    // Hook Volley (if used)
    try {
        var HurlStack = Java.use('com.android.volley.toolbox.HurlStack');
        HurlStack.executeRequest.implementation = function(request, additionalHeaders) {
            var url = request.getUrl();
            console.log('[Volley] Request to: ' + url);
            return this.executeRequest(request, additionalHeaders);
        };
    } catch (err) {
        console.log('[-] Volley not found');
    }

    console.log('[+] Network monitoring active');
});
"""

        # File System Monitoring Script
        filesystem_script = """
// File System Access Monitoring
Java.perform(function() {
    console.log("[+] Starting file system monitoring...");

    // Hook File operations
    var File = Java.use('java.io.File');
    File.$init.overload('java.lang.String').implementation = function(path) {
        console.log('[File] Access: ' + path);
        return this.$init(path);
    };

    // Hook SharedPreferences
    var SharedPreferencesImpl = Java.use('android.app.SharedPreferencesImpl');
    SharedPreferencesImpl.getString.implementation = function(key, defValue) {
        if (key.toLowerCase().includes('password') ||
            key.toLowerCase().includes('token') ||
            key.toLowerCase().includes('key')) {
            console.log('[SharedPreferences] Sensitive key accessed: ' + key + ' = ' + defValue);
        }
        return this.getString(key, defValue);
    };

    SharedPreferencesImpl.putString.implementation = function(key, value) {
        if (key.toLowerCase().includes('password') ||
            key.toLowerCase().includes('token') ||
            key.toLowerCase().includes('key')) {
            console.log('[SharedPreferences] Sensitive data stored: ' + key + ' = ' + value);
        }
        return this.putString(key, value);
    };

    // Hook SQLite operations
    var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
    SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
        if (sql.toLowerCase().includes('password') ||
            sql.toLowerCase().includes('token') ||
            sql.toLowerCase().includes('key')) {
            console.log('[SQLite] Sensitive query: ' + sql);
        }
        return this.execSQL(sql);
    };

    console.log('[+] File system monitoring active');
});
"""

        # Encryption/Cryptography Monitoring Script
        crypto_script = """
// Cryptography Operations Monitoring
Java.perform(function() {
    console.log("[+] Starting cryptography monitoring...");

    // Hook Cipher operations
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.doFinal.overload('[B').implementation = function(input) {
        var algorithm = this.getAlgorithm();
        console.log('[Crypto] ' + algorithm + ' operation on ' + input.length + ' bytes');
        var result = this.doFinal(input);
        console.log('[Crypto] Output: ' + result.length + ' bytes');
        return result;
    };

    // Hook MessageDigest (hashing)
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.digest.overload('[B').implementation = function(input) {
        var algorithm = this.getAlgorithm();
        console.log('[Hash] ' + algorithm + ' on ' + input.length + ' bytes');
        return this.digest(input);
    };

    // Hook KeyGenerator
    var KeyGenerator = Java.use('javax.crypto.KeyGenerator');
    KeyGenerator.generateKey.implementation = function() {
        var algorithm = this.getAlgorithm();
        console.log('[KeyGen] Generating key for: ' + algorithm);
        return this.generateKey();
    };

    console.log('[+] Cryptography monitoring active');
});
"""

        # Write scripts to files
        script_files = {
            "ssl_bypass.js": ssl_script,
            "network_monitor.js": network_script,
            "filesystem_monitor.js": filesystem_script,
            "crypto_monitor.js": crypto_script
        }

        for filename, content in script_files.items():
            script_path = self.frida_scripts_dir / filename
            with open(script_path, 'w') as f:
                f.write(content)
            scripts[filename] = str(script_path)

        return scripts

    def run_frida_analysis(self, script_name, duration=60):
        """Run Frida script for specified duration"""
        script_path = self.frida_scripts_dir / script_name
        log_file = self.frida_logs_dir / f"{script_name.replace('.js', '.log')}"

        self.log(f"Running Frida script: {script_name} for {duration} seconds")

        try:
            # Start the app
            subprocess.run(["adb", "shell", "monkey", "-p", self.package_name, "-c", "android.intent.category.LAUNCHER", "1"],
                         capture_output=True)
            time.sleep(3)

            # Run Frida
            cmd = [
                "frida", "-U",
                "-f", self.package_name,
                "-l", str(script_path),
                "--no-pause"
            ]

            with open(log_file, 'w') as f:
                process = subprocess.Popen(cmd, stdout=f, stderr=subprocess.PIPE, text=True)

                # Let it run for specified duration
                time.sleep(duration)

                # Terminate the process
                process.terminate()
                stdout, stderr = process.communicate(timeout=10)

            self.log(f"Frida analysis completed: {script_name}")
            return {"status": "success", "log_file": str(log_file)}

        except Exception as e:
            self.log(f"Frida analysis failed for {script_name}: {e}", "ERROR")
            return {"status": "failed", "error": str(e)}

    def monitor_network_traffic(self):
        """Monitor network traffic during app usage"""
        self.log("Setting up network traffic monitoring...")

        # Setup proxy configuration
        proxy_script = """
# Network Traffic Monitoring Setup
# This script needs to be run on the host to set up proxy

echo "[+] Setting up network monitoring..."

# Check if Burp Suite is running
if ! pgrep -f "burpsuite" > /dev/null; then
    echo "[-] Burp Suite is not running. Please start Burp Suite first."
    exit 1
fi

# Get host IP
HOST_IP=$(hostname -I | awk '{print $1}')
PROXY_PORT=8080

echo "[+] Configuring emulator proxy to ${HOST_IP}:${PROXY_PORT}"

# Set proxy on emulator
adb shell settings put global http_proxy ${HOST_IP}:${PROXY_PORT}

# Install Burp certificate (if not already installed)
echo "[+] Installing Burp certificate..."
adb push ~/.BurpSuite/cacert.der /sdcard/
# Manual step required: Install certificate in device settings

echo "[+] Network monitoring configured"
echo "[+] Start tcpdump for additional monitoring:"
echo "tcpdump -i any -w network_capture.pcap host ${HOST_IP}"
"""

        script_path = self.phase3_dir / "setup_network_monitoring.sh"
        with open(script_path, 'w') as f:
            f.write(proxy_script)

        os.chmod(script_path, 0o755)

        return {
            "status": "ready",
            "script": str(script_path),
            "instructions": [
                "Start Burp Suite on port 8080",
                "Run the network monitoring setup script",
                "Install Burp certificate on the emulator",
                "Use the app while monitoring traffic"
            ]
        }

    def perform_memory_analysis(self):
        """Perform memory dump and analysis"""
        self.log("Preparing memory analysis...")

        try:
            # Get process ID
            result = subprocess.run(["adb", "shell", "pidof", self.package_name],
                                  capture_output=True, text=True)

            if not result.stdout.strip():
                self.log("App not running, starting app first...")
                subprocess.run(["adb", "shell", "monkey", "-p", self.package_name, "-c", "android.intent.category.LAUNCHER", "1"])
                time.sleep(5)

                result = subprocess.run(["adb", "shell", "pidof", self.package_name],
                                      capture_output=True, text=True)

            pid = result.stdout.strip()
            if not pid:
                return {"status": "failed", "error": "Could not find app process"}

            self.log(f"Found app process PID: {pid}")

            # Create memory dump script
            memory_script = f"""
# Memory Dump Script for MyMaynDrive
PID="{pid}"
PACKAGE="{self.package_name}"
DUMP_FILE="/sdcard/{self.package_name}_memory.dump"

echo "[+] Dumping memory for process $PID ($PACKAGE)"

# Check if we have root access
if ! adb shell 'su -c "echo test"' 2>/dev/null; then
    echo "[-] No root access available for memory dump"
    exit 1
fi

# Create memory dump using gdb
adb shell "su -c 'gdb --pid=$PID -batch -ex \"generate-core-file $DUMP_FILE\"'"

# Pull the dump file
adb pull $DUMP_FILE {self.memory_dumps_dir}/

echo "[+] Memory dump completed: {self.memory_dumps_dir}/{self.package_name}_memory.dump"
"""

            script_path = self.phase3_dir / "dump_memory.sh"
            with open(script_path, 'w') as f:
                f.write(memory_script)

            os.chmod(script_path, 0o755)

            return {
                "status": "ready",
                "pid": pid,
                "script": str(script_path),
                "requires_root": True
            }

        except Exception as e:
            self.log(f"Memory analysis preparation failed: {e}", "ERROR")
            return {"status": "failed", "error": str(e)}

    def generate_dynamic_report(self, results):
        """Generate dynamic analysis report"""
        self.log("Generating dynamic analysis report...")

        report = {
            "package_name": self.package_name,
            "analysis_date": datetime.now().isoformat(),
            "dynamic_analysis_results": results,
            "recommendations": self.generate_dynamic_recommendations(results)
        }

        report_file = self.phase3_dir / "dynamic_analysis_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        # Generate markdown report
        self.generate_dynamic_markdown_report(report)

        return report

    def generate_dynamic_recommendations(self, results):
        """Generate recommendations based on dynamic analysis"""
        recommendations = []

        # Analyze network logs
        if "network_monitoring" in results:
            if results["network_monitoring"].get("http_traffic"):
                recommendations.append("SECURE_COMMUNICATIONS: All API communications should use HTTPS")
            if results["network_monitoring"].get("cert_pinning_bypassed"):
                recommendations.append("IMPLEMENT_CERT_PINNING: SSL pinning was bypassed, implement proper certificate pinning")

        # Analyze file system access
        if "filesystem_monitoring" in results:
            if results["filesystem_monitoring"].get("sensitive_data_written"):
                recommendations.append("SECURE_STORAGE: Sensitive data should be stored in encrypted form")
            if results["filesystem_monitoring"].get("insecure_permissions"):
                recommendations.append("REVIEW_FILE_PERMISSIONS: Review file access permissions")

        # Analyze crypto usage
        if "crypto_monitoring" in results:
            crypto_results = results["crypto_monitoring"]
            if crypto_results.get("weak_algorithms"):
                recommendations.append("STRONG_CRYPTOGRAPHY: Use strong encryption algorithms (AES-256, RSA-2048+)")
            if crypto_results.get("hardcoded_keys"):
                recommendations.append("REMOVE_HARDCODED_KEYS: Remove hardcoded encryption keys")

        return recommendations

    def generate_dynamic_markdown_report(self, report):
        """Generate markdown report for dynamic analysis"""
        markdown_file = self.phase3_dir / "dynamic_analysis_report.md"

        with open(markdown_file, 'w') as f:
            f.write("# MyMaynDrive Dynamic Analysis Report\n\n")
            f.write(f"**Package:** {report['package_name']}\n")
            f.write(f"**Analysis Date:** {report['analysis_date']}\n\n")

            f.write("## Dynamic Analysis Results\n\n")

            results = report["dynamic_analysis_results"]

            # Network Analysis Section
            if "network_monitoring" in results:
                f.write("### Network Monitoring\n\n")
                network = results["network_monitoring"]
                f.write(f"- **HTTP Requests Captured:** {network.get('http_requests_count', 0)}\n")
                f.write(f"- **HTTPS Requests:** {network.get('https_requests_count', 0)}\n")
                f.write(f"- **SSL Pinning Status:** {'Bypassed' if network.get('cert_pinning_bypassed') else 'Active'}\n\n")

            # File System Analysis Section
            if "filesystem_monitoring" in results:
                f.write("### File System Monitoring\n\n")
                fs = results["filesystem_monitoring"]
                f.write(f"- **Files Accessed:** {fs.get('files_accessed_count', 0)}\n")
                f.write(f"- **Sensitive Data Written:** {'Yes' if fs.get('sensitive_data_written') else 'No'}\n")
                f.write(f"- **SharedPreferences Used:** {fs.get('sharedprefs_count', 0)}\n\n")

            # Cryptography Analysis Section
            if "crypto_monitoring" in results:
                f.write("### Cryptography Monitoring\n\n")
                crypto = results["crypto_monitoring"]
                f.write(f"- **Encryption Operations:** {crypto.get('encryption_ops', 0)}\n")
                f.write(f"- **Hashing Operations:** {crypto.get('hash_ops', 0)}\n")
                f.write(f"- **Key Generation Events:** {crypto.get('keygen_ops', 0)}\n\n")

            # Recommendations
            f.write("## Security Recommendations\n\n")
            for rec in report["recommendations"]:
                f.write(f"1. {rec}\n")
            f.write("\n")

            f.write("---\n")
            f.write("*Dynamic Analysis Report Generated by APK Analysis Framework*\n")

    def run_full_dynamic_analysis(self):
        """Run complete dynamic analysis pipeline"""
        self.log(f"Starting dynamic analysis for {self.package_name}")

        if not self.check_device_connection():
            return False

        results = {}

        try:
            # Create Frida scripts
            scripts = self.create_frida_scripts()
            results["scripts_created"] = list(scripts.keys())

            # Run each Frida script
            for script_name in scripts.keys():
                self.log(f"Running analysis with {script_name}")
                result = self.run_frida_analysis(script_name, duration=60)
                results[script_name.replace('.js', '_analysis')] = result
                time.sleep(5)  # Brief pause between analyses

            # Setup network monitoring
            network_setup = self.monitor_network_traffic()
            results["network_monitoring"] = network_setup

            # Prepare memory analysis
            memory_analysis = self.perform_memory_analysis()
            results["memory_analysis"] = memory_analysis

            # Generate report
            report = self.generate_dynamic_report(results)

            self.log("Dynamic analysis completed successfully!")
            self.log(f"Results saved to: {self.phase3_dir}")

            return True

        except Exception as e:
            self.log(f"Dynamic analysis failed: {e}", "ERROR")
            return False

def main():
    parser = argparse.ArgumentParser(description="Dynamic Analysis for Android APK")
    parser.add_argument("package_name", help="Android package name (e.g., com.example.app)")
    parser.add_argument("-o", "--output", default="analysis_output", help="Output directory")
    parser.add_argument("--duration", type=int, default=60, help="Duration for each Frida script (seconds)")

    args = parser.parse_args()

    analyzer = DynamicAnalyzer(args.package_name, args.output)
    analyzer.run_full_dynamic_analysis()

if __name__ == "__main__":
    main()