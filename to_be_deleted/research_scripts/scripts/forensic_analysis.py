#!/usr/bin/env python3
"""
Phase 4: Forensic Analysis Framework for MyMaynDrive APK
This script handles advanced forensic techniques including memory forensics,
cryptographic analysis, and behavioral reconstruction
"""

import os
import sys
import subprocess
import time
import json
import re
import argparse
from pathlib import Path
from datetime import datetime
import hashlib

class ForensicAnalyzer:
    def __init__(self, package_name, output_dir):
        self.package_name = package_name
        self.output_dir = Path(output_dir)
        self.phase4_dir = self.output_dir / "phase4_forensic"
        self.phase4_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories
        self.memory_forensics_dir = self.phase4_dir / "memory_forensics"
        self.crypto_analysis_dir = self.phase4_dir / "crypto_analysis"
        self.timeline_dir = self.phase4_dir / "timeline_analysis"
        self.behavioral_dir = self.phase4_dir / "behavioral_analysis"
        self.evidence_dir = self.phase4_dir / "evidence"

        for dir in [self.memory_forensics_dir, self.crypto_analysis_dir,
                   self.timeline_dir, self.behavioral_dir, self.evidence_dir]:
            dir.mkdir(exist_ok=True)

    def log(self, message, phase="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{phase}] {message}")

    def extract_apk_evidence(self, apk_path):
        """Extract forensic evidence from APK file"""
        self.log("Extracting forensic evidence from APK...")

        evidence = {
            "apk_metadata": self.extract_apk_metadata(apk_path),
            "certificate_analysis": self.analyze_certificates(apk_path),
            "signature_analysis": self.analyze_signatures(apk_path),
            "resource_forensics": self.analyze_resources(apk_path),
            "file_hashing": self.calculate_file_hashes(apk_path)
        }

        evidence_file = self.evidence_dir / "apk_evidence.json"
        with open(evidence_file, 'w') as f:
            json.dump(evidence, f, indent=2, default=str)

        return evidence

    def extract_apk_metadata(self, apk_path):
        """Extract comprehensive APK metadata"""
        self.log("Extracting APK metadata...")

        metadata = {}

        try:
            # Use aapt for detailed metadata
            cmd = ["aapt", "dump", "badging", str(apk_path)]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                # Parse aapt output
                for line in result.stdout.split('\n'):
                    if line.startswith('package:'):
                        # Extract package info
                        parts = line.split()
                        metadata["package_name"] = parts[1].split('=')[1].strip("'")
                        metadata["version_code"] = parts[2].split('=')[1].strip("'")
                        metadata["version_name"] = parts[3].split('=')[1].strip("'")
                    elif line.startswith('launchable-activity:'):
                        # Extract main activity
                        parts = line.split()
                        metadata["main_activity"] = parts[1].split('=')[1].strip("'")
                    elif line.startswith('sdkVersion:'):
                        metadata["min_sdk"] = line.split(':')[1].strip()
                    elif line.startswith('targetSdkVersion:'):
                        metadata["target_sdk"] = line.split(':')[1].strip()
                    elif line.startswith('uses-permission:'):
                        if "permissions" not in metadata:
                            metadata["permissions"] = []
                        permission = line.split("'")[1]
                        metadata["permissions"].append(permission)

            # Get file size and timestamps
            apk_stat = Path(apk_path).stat()
            metadata["file_size"] = apk_stat.st_size
            metadata["created_time"] = apk_stat.st_ctime
            metadata["modified_time"] = apk_stat.st_mtime

        except Exception as e:
            self.log(f"Metadata extraction failed: {e}", "ERROR")

        return metadata

    def analyze_certificates(self, apk_path):
        """Analyze APK signing certificates"""
        self.log("Analyzing APK certificates...")

        cert_analysis = {}

        try:
            # Extract APK to analyze certificates
            extract_dir = self.evidence_dir / "extracted_apk"
            extract_dir.mkdir(exist_ok=True)

            subprocess.run(["unzip", "-q", str(apk_path), "-d", str(extract_dir)], check=True)

            # Find and analyze certificate files
            cert_files = []
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    if file.endswith('.RSA') or file.endswith('.DSA') or file.endswith('.EC'):
                        cert_files.append(os.path.join(root, file))

            cert_analysis["certificate_files"] = cert_files

            for cert_file in cert_files:
                try:
                    # Use keytool to analyze certificate
                    cmd = ["keytool", "-printcert", "-file", cert_file]
                    result = subprocess.run(cmd, capture_output=True, text=True)

                    cert_info = {
                        "file": cert_file,
                        "analysis": result.stdout if result.returncode == 0 else "Analysis failed"
                    }

                    if "analysis" not in cert_analysis:
                        cert_analysis["analysis"] = []
                    cert_analysis["analysis"].append(cert_info)

                except Exception as e:
                    self.log(f"Certificate analysis failed for {cert_file}: {e}", "ERROR")

        except Exception as e:
            self.log(f"Certificate analysis failed: {e}", "ERROR")

        return cert_analysis

    def analyze_signatures(self, apk_path):
        """Analyze APK for malware signatures and patterns"""
        self.log("Analyzing malware signatures...")

        signature_analysis = {
            "suspicious_strings": [],
            "malware_patterns": [],
            "obfuscation_indicators": []
        }

        try:
            # Extract strings from APK
            extract_dir = self.evidence_dir / "extracted_apk"
            strings_file = self.evidence_dir / "extracted_strings.txt"

            with open(strings_file, 'w') as f:
                for root, dirs, files in os.walk(extract_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            cmd = ["strings", file_path]
                            result = subprocess.run(cmd, capture_output=True, text=True)
                            if result.stdout:
                                f.write(f"=== {file_path} ===\n")
                                f.write(result.stdout + "\n\n")
                        except:
                            continue

            # Analyze strings for suspicious patterns
            suspicious_patterns = {
                "ad_networks": [
                    r'admob', r'adsense', r'facebook.*ads', r'twitter.*ads',
                    r'google.*ads', r'mopub', r'unityads'
                ],
                "tracking": [
                    r'google.*analytics', r'firebase.*analytics', r'mixpanel',
                    r'flurry', r'appsflyer', r'branch', r'adjust'
                ],
                "malware_indicators": [
                    r'root.*check', r'su.*binary', r'system.*bin.*su',
                    r'busybox', r'adb.*shell', r'shell.*exec'
                ],
                "crypto_mining": [
                    r'cryptonight', r'monero', r'bitcoin', r'ethereum.*mining',
                    r'xmrig', r'cpuminer'
                ],
                "data_exfiltration": [
                    r'upload.*data', r'exfiltrate', r'steal.*data',
                    r'command.*control', r'c2.*server'
                ]
            }

            with open(strings_file, 'r') as f:
                content = f.read().lower()

                for category, patterns in suspicious_patterns.items():
                    matches = []
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            matches.append(pattern)

                    if matches:
                        signature_analysis["suspicious_strings"].append({
                            "category": category,
                            "patterns": matches
                        })

            # Check for obfuscation indicators
            obfuscation_indicators = [
                r'proguard', r'dexguard', r'allatori', r'yguard',
                r'rename', r'obfuscat', r'encrypt.*string'
            ]

            for indicator in obfuscation_indicators:
                if re.search(indicator, content, re.IGNORECASE):
                    signature_analysis["obfuscation_indicators"].append(indicator)

        except Exception as e:
            self.log(f"Signature analysis failed: {e}", "ERROR")

        return signature_analysis

    def analyze_resources(self, apk_path):
        """Analyze APK resources for hidden data"""
        self.log("Analyzing APK resources...")

        resource_analysis = {
            "suspicious_assets": [],
            "encrypted_files": [],
            "hidden_data": []
        }

        try:
            extract_dir = self.evidence_dir / "extracted_apk"
            assets_dir = extract_dir / "assets"
            res_dir = extract_dir / "res"

            # Analyze assets directory
            if assets_dir.exists():
                for root, dirs, files in os.walk(assets_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        file_size = os.path.getsize(file_path)

                        # Check for suspicious files
                        if file.endswith(('.dex', '.so', '.jar', '.zip')):
                            resource_analysis["suspicious_assets"].append({
                                "file": file_path,
                                "type": "executable_archive",
                                "size": file_size
                            })

                        # Check for potentially encrypted files (high entropy)
                        if file_size > 100:  # Only check files larger than 100 bytes
                            entropy = self.calculate_file_entropy(file_path)
                            if entropy > 7.0:  # High entropy suggests encryption
                                resource_analysis["encrypted_files"].append({
                                    "file": file_path,
                                    "entropy": entropy,
                                    "size": file_size
                                })

            # Analyze resources directory
            if res_dir.exists():
                for root, dirs, files in os.walk(res_dir):
                    for file in files:
                        if file.endswith(('.xml', '.json')):
                            file_path = os.path.join(root, file)
                            # Check for hardcoded secrets in resource files
                            with open(file_path, 'r', errors='ignore') as f:
                                content = f.read()
                                if self.contains_secrets(content):
                                    resource_analysis["hidden_data"].append({
                                        "file": file_path,
                                        "type": "potential_secrets"
                                    })

        except Exception as e:
            self.log(f"Resource analysis failed: {e}", "ERROR")

        return resource_analysis

    def calculate_file_entropy(self, file_path):
        """Calculate Shannon entropy of a file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            if not data:
                return 0

            # Calculate byte frequencies
            byte_counts = {}
            for byte in data:
                byte_counts[byte] = byte_counts.get(byte, 0) + 1

            # Calculate entropy
            entropy = 0
            data_len = len(data)
            for count in byte_counts.values():
                probability = count / data_len
                if probability > 0:
                    entropy -= probability * (probability.bit_length() - 1)

            return entropy

        except Exception as e:
            self.log(f"Entropy calculation failed for {file_path}: {e}", "ERROR")
            return 0

    def contains_secrets(self, content):
        """Check if content contains potential secrets"""
        secret_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api[_-]?key\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']',
            r'private[_-]?key\s*=\s*["\'][^"\']+["\']',
            r'access[_-]?token\s*=\s*["\'][^"\']+["\']',
            r'client[_-]?secret\s*=\s*["\'][^"\']+["\']'
        ]

        for pattern in secret_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True

        return False

    def calculate_file_hashes(self, apk_path):
        """Calculate various file hashes for integrity verification"""
        self.log("Calculating file hashes...")

        hashes = {}

        try:
            with open(apk_path, 'rb') as f:
                data = f.read()

            hashes["md5"] = hashlib.md5(data).hexdigest()
            hashes["sha1"] = hashlib.sha1(data).hexdigest()
            hashes["sha256"] = hashlib.sha256(data).hexdigest()
            hashes["sha512"] = hashlib.sha512(data).hexdigest()

            # Calculate CRC32
            import zlib
            hashes["crc32"] = format(zlib.crc32(data) & 0xFFFFFFFF, '08x')

        except Exception as e:
            self.log(f"Hash calculation failed: {e}", "ERROR")

        return hashes

    def perform_memory_forensics(self):
        """Perform advanced memory forensics"""
        self.log("Starting memory forensics...")

        memory_analysis = {
            "memory_dumps": [],
            "string_extraction": {},
            "process_analysis": {},
            "network_connections": {}
        }

        try:
            # Get running processes
            result = subprocess.run(["adb", "shell", "ps"], capture_output=True, text=True)
            if result.returncode == 0:
                processes = []
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    if self.package_name in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            processes.append({
                                "user": parts[0],
                                "pid": parts[1],
                                "name": ' '.join(parts[8:])
                            })

                memory_analysis["process_analysis"]["target_processes"] = processes

            # Check if we can perform memory analysis
            result = subprocess.run(["adb", "shell", "su -c 'echo test'"], capture_output=True, text=True)
            if result.returncode == 0:
                memory_analysis["root_access"] = True
                self.log("Root access available for memory forensics")

                # Create memory dump script
                dump_script = f"""
# Advanced Memory Dump Script for {self.package_name}
TARGET_PACKAGE="{self.package_name}"
OUTPUT_DIR="/sdcard/memory_forensics"

echo "[+] Creating output directory: $OUTPUT_DIR"
adb shell "mkdir -p $OUTPUT_DIR"

# Find all processes for the target package
PIDS=$(adb shell "ps | grep $TARGET_PACKAGE | awk '{{print $2}}'")

for PID in $PIDS; do
    echo "[+] Dumping memory for PID: $PID"

    # Create memory map
    adb shell "su -c 'cat /proc/$PID/maps' > $OUTPUT_DIR/maps_$PID.txt"

    # Dump process memory using gdb if available
    if adb shell "which gdb" >/dev/null 2>&1; then
        adb shell "su -c 'gdb --pid=$PID -batch -ex \"generate-core-file $OUTPUT_DIR/core_$PID\"'"
    fi

    # Alternative: use /proc/$PID/mem (if accessible)
    adb shell "su -c 'cp /proc/$PID/mem $OUTPUT_DIR/mem_$PID.bin' 2>/dev/null"
done

# Extract strings from memory dumps
for DUMP_FILE in $(adb shell "find $OUTPUT_DIR -name '*.bin'"); do
    BASENAME=$(basename $DUMP_FILE .bin)
    adb shell "strings $DUMP_FILE > $OUTPUT_DIR/strings_$BASENAME.txt"
done

echo "[+] Memory dump completed"
echo "[+] Pulling files to local machine..."
adb pull $OUTPUT_DIR {self.memory_forensics_dir}/
"""

                script_path = self.memory_forensics_dir / "advanced_memory_dump.sh"
                with open(script_path, 'w') as f:
                    f.write(dump_script)

                os.chmod(script_path, 0o755)

                memory_analysis["dump_script"] = str(script_path)
                memory_analysis["output_directory"] = str(self.memory_forensics_dir)

            else:
                memory_analysis["root_access"] = False
                self.log("No root access available - limited memory forensics")

        except Exception as e:
            self.log(f"Memory forensics setup failed: {e}", "ERROR")

        return memory_analysis

    def perform_cryptographic_analysis(self):
        """Analyze cryptographic implementations and find weaknesses"""
        self.log("Performing cryptographic analysis...")

        crypto_analysis = {
            "crypto_libraries": [],
            "implementation_weaknesses": [],
            "hardcoded_keys": [],
            "randomness_analysis": {}
        }

        try:
            extract_dir = self.evidence_dir / "extracted_apk"

            # Find and analyze cryptographic libraries
            crypto_patterns = {
                "java_crypto": [
                    "javax.crypto.Cipher",
                    "javax.crypto.KeyGenerator",
                    "javax.crypto.Mac",
                    "java.security.MessageDigest",
                    "java.security.Signature"
                ],
                "bouncy_castle": [
                    "org.bouncycastle",
                    "BouncyCastleProvider"
                ],
                "android_crypto": [
                    "android.security.keystore",
                    "android.security.KeyChain"
                ],
                "native_crypto": [
                    "libcrypto.so",
                    "libssl.so",
                    "openssl"
                ]
            }

            for category, patterns in crypto_patterns.items():
                found_patterns = []
                for root, dirs, files in os.walk(extract_dir):
                    for file in files:
                        if file.endswith(('.smali', '.java', '.dex')):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r', errors='ignore') as f:
                                    content = f.read()
                                    for pattern in patterns:
                                        if pattern in content:
                                            found_patterns.append({
                                                "file": file_path,
                                                "pattern": pattern
                                            })
                            except:
                                continue

                if found_patterns:
                    crypto_analysis["crypto_libraries"].append({
                        "category": category,
                        "implementations": found_patterns
                    })

            # Search for hardcoded cryptographic keys
            key_patterns = [
                r'private\s+static\s+final\s+String\s+\w*[Kk]ey\s*=\s*"[^"]+"',
                r'byte\[\]\s+\w*[Kk]ey\s*=\s*\{[^}]+\}',
                r'SecretKeySpec\s+[^=]+=\s*new\s+SecretKeySpec\(',
                r'KeyGenerator\.getInstance\("[^"]+"\)',
                r' IvParameterSpec\s+[^=]+=\s*new\s+IvParameterSpec\('
            ]

            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    if file.endswith(('.java', '.smali')):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', errors='ignore') as f:
                                content = f.read()
                                for pattern in key_patterns:
                                    matches = re.findall(pattern, content)
                                    if matches:
                                        crypto_analysis["hardcoded_keys"].append({
                                            "file": file_path,
                                            "pattern": pattern,
                                            "matches": matches
                                        })
                        except:
                            continue

            # Analyze for common cryptographic weaknesses
            weakness_patterns = {
                "des_usage": r'DES/CBC/',
                "md5_usage": r'MD5',
                "sha1_usage": r'SHA-?1',
                "ecb_mode": r'/ECB/',
                "no_salt": r'PBEKeySpec\([^,)]+\)',
                "static_iv": r'IvParameterSpec\s*\(\s*"[^"]*"\s*\)'
            }

            for weakness, pattern in weakness_patterns.items():
                found = False
                for root, dirs, files in os.walk(extract_dir):
                    for file in files:
                        if file.endswith(('.java', '.smali')):
                            file_path = os.path.join(root, file)
                            try:
                                with open(file_path, 'r', errors='ignore') as f:
                                    content = f.read()
                                    if re.search(pattern, content):
                                        found = True
                                        break
                            except:
                                continue
                    if found:
                        break

                if found:
                    crypto_analysis["implementation_weaknesses"].append({
                        "weakness": weakness,
                        "pattern": pattern,
                        "severity": "high" if weakness in ["des_usage", "ecb_mode"] else "medium"
                    })

        except Exception as e:
            self.log(f"Cryptographic analysis failed: {e}", "ERROR")

        return crypto_analysis

    def create_timeline_analysis(self):
        """Create timeline of app behavior"""
        self.log("Creating timeline analysis framework...")

        timeline_framework = {
            "log_collection": self.create_log_collection_script(),
            "event_correlation": self.create_event_correlation_script(),
            "behavioral_patterns": {}
        }

        return timeline_framework

    def create_log_collection_script(self):
        """Create script to collect comprehensive logs"""
        script_content = f"""
# Timeline Analysis - Log Collection Script for {self.package_name}
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_DIR="{self.timeline_dir}/logs_$TIMESTAMP"
OUTPUT_DIR="{self.timeline_dir}"

echo "[+] Creating log directory: $LOG_DIR"
mkdir -p "$LOG_DIR"

# Start collecting logs
echo "[+] Starting log collection..."

# System logs
adb logcat -v time > "$LOG_DIR/system_log.txt" &
LOGCAT_PID=$!

# Kernel messages
adb shell "dmesg" > "$LOG_DIR/kernel_log.txt" 2>/dev/null &

# Network connections
adb shell "netstat -an" > "$LOG_DIR/network_connections.txt" &
NETSTAT_PID=$!

# Running processes
adb shell "ps aux" > "$LOG_DIR/processes.txt" &

# Installed packages
adb shell "pm list packages -f" > "$LOG_DIR/installed_packages.txt" &

# Device information
adb shell "getprop" > "$LOG_DIR/device_properties.txt" &

# File system (selected directories)
adb shell "find /data/data/{self.package_name} -type f -ls 2>/dev/null" > "$LOG_DIR/app_files.txt" &

# Network interfaces
adb shell "ip addr show" > "$LOG_DIR/network_interfaces.txt" &

# ARP table
adb shell "arp -a" > "$LOG_DIR/arp_table.txt" &

echo "[+] Log collection started. PIDs:"
echo "    Logcat: $LOGCAT_PID"
echo "    Netstat: $NETSTAT_PID"
echo ""
echo "[+] Let the app run for the desired time, then stop collection:"
echo "    kill $LOGCAT_PID"
echo "    kill $NETSTAT_PID"
echo ""
echo "[+] Logs will be saved to: $LOG_DIR"
"""

        script_path = self.timeline_dir / "collect_logs.sh"
        with open(script_path, 'w') as f:
            f.write(script_content)

        os.chmod(script_path, 0o755)

        return {
            "script_path": str(script_path),
            "description": "Comprehensive log collection for timeline analysis"
        }

    def create_event_correlation_script(self):
        """Create script to correlate events from different sources"""
        script_content = f"""
# Event Correlation Script for {self.package_name}
# This script correlates events from logs, network traffic, and file system changes

import json
import re
from datetime import datetime

class EventCorrelator:
    def __init__(self, log_dir):
        self.log_dir = log_dir
        self.events = []

    def parse_logcat(self, log_file):
        events = []
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    if '{self.package_name}' in line:
                        # Parse timestamp and event
                        match = re.match(r'(\\d{{2}}-\\d{{2}}\\s+\\d{{2}}:\\d{{2}}:\\d{{2}}\\.\\d{{3}})\\s+(\\d+)\\s+(\\d+)\\s+(\\w)\\s+([^:]+):(.*)', line)
                        if match:
                            timestamp_str, pid, tid, level, tag, message = match.groups()
                            events.append({{
                                'timestamp': timestamp_str,
                                'pid': pid,
                                'tid': tid,
                                'level': level,
                                'tag': tag,
                                'message': message.strip(),
                                'source': 'logcat'
                            }})
        except Exception as e:
            print(f"Error parsing logcat: {{e}}")

        return events

    def parse_network_log(self, log_file):
        events = []
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    if 'ESTABLISHED' in line and ('80' in line or '443' in line):
                        # Parse network connection
                        events.append({{
                            'timestamp': datetime.now().strftime('%m-%d %H:%M:%S.%f')[:-3],
                            'message': line.strip(),
                            'source': 'network'
                        }})
        except Exception as e:
            print(f"Error parsing network log: {{e}}")

        return events

    def correlate_events(self):
        # Parse all log files
        all_events = []

        # Parse logcat
        logcat_file = f"{{self.log_dir}}/system_log.txt"
        if os.path.exists(logcat_file):
            all_events.extend(self.parse_logcat(logcat_file))

        # Parse network logs
        network_file = f"{{self.log_dir}}/network_connections.txt"
        if os.path.exists(network_file):
            all_events.extend(self.parse_network_log(network_file))

        # Sort events by timestamp
        all_events.sort(key=lambda x: x.get('timestamp', ''))

        return all_events

if __name__ == "__main__":
    import sys
    import os

    if len(sys.argv) != 2:
        print("Usage: python correlate_events.py <log_directory>")
        sys.exit(1)

    log_dir = sys.argv[1]
    correlator = EventCorrelator(log_dir)
    events = correlator.correlate_events()

    # Save correlated events
    output_file = f"{{log_dir}}/correlated_events.json"
    with open(output_file, 'w') as f:
        json.dump(events, f, indent=2)

    print(f"Correlated {{len(events)}} events saved to {{output_file}}")
"""

        script_path = self.timeline_dir / "correlate_events.py"
        with open(script_path, 'w') as f:
            f.write(script_content)

        os.chmod(script_path, 0o755)

        return {
            "script_path": str(script_path),
            "description": "Event correlation across multiple data sources"
        }

    def generate_forensic_report(self, evidence, memory_analysis, crypto_analysis, timeline_analysis):
        """Generate comprehensive forensic report"""
        self.log("Generating forensic analysis report...")

        report = {
            "package_name": self.package_name,
            "analysis_date": datetime.now().isoformat(),
            "evidence_analysis": evidence,
            "memory_forensics": memory_analysis,
            "cryptographic_analysis": crypto_analysis,
            "timeline_analysis": timeline_analysis,
            "security_findings": self.extract_security_findings(evidence, memory_analysis, crypto_analysis),
            "recommendations": self.generate_forensic_recommendations(evidence, memory_analysis, crypto_analysis)
        }

        # Save JSON report
        report_file = self.phase4_dir / "forensic_analysis_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        # Generate markdown report
        self.generate_forensic_markdown_report(report)

        return report

    def extract_security_findings(self, evidence, memory_analysis, crypto_analysis):
        """Extract key security findings from all analyses"""
        findings = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }

        # Evidence analysis findings
        if evidence.get("signature_analysis", {}).get("malware_patterns"):
            findings["critical"].append("Potential malware signatures detected")

        if evidence.get("signature_analysis", {}).get("suspicious_strings"):
            for sus in evidence["signature_analysis"]["suspicious_strings"]:
                if sus["category"] == "malware_indicators":
                    findings["critical"].append(f"Malware indicators found: {sus['patterns']}")
                elif sus["category"] == "data_exfiltration":
                    findings["high"].append(f"Data exfiltration patterns: {sus['patterns']}")

        # Cryptographic analysis findings
        if crypto_analysis.get("hardcoded_keys"):
            findings["high"].append("Hardcoded cryptographic keys detected")

        if crypto_analysis.get("implementation_weaknesses"):
            for weakness in crypto_analysis["implementation_weaknesses"]:
                if weakness["severity"] == "high":
                    findings["high"].append(f"Cryptographic weakness: {weakness['weakness']}")
                else:
                    findings["medium"].append(f"Cryptographic weakness: {weakness['weakness']}")

        # Resource analysis findings
        if evidence.get("resource_forensics", {}).get("encrypted_files"):
            findings["medium"].append("High-entropy files detected (possible encryption)")

        return findings

    def generate_forensic_recommendations(self, evidence, memory_analysis, crypto_analysis):
        """Generate forensic analysis recommendations"""
        recommendations = []

        # Evidence-based recommendations
        if evidence.get("signature_analysis", {}).get("malware_patterns"):
            recommendations.append("MALWARE_INVESTIGATION: Immediate investigation required for potential malware")

        if evidence.get("signature_analysis", {}).get("obfuscation_indicators"):
            recommendations.append("DEOBFUSCATION: Further analysis needed to deobfuscate code")

        # Cryptographic recommendations
        if crypto_analysis.get("hardcoded_keys"):
            recommendations.append("REMOVE_HARDCODED_KEYS: Remove all hardcoded cryptographic keys")

        if crypto_analysis.get("implementation_weaknesses"):
            recommendations.append("UPDATE_CRYPTOGRAPHY: Use modern, secure cryptographic algorithms")

        # Memory forensics recommendations
        if memory_analysis.get("root_access"):
            recommendations.append("ROOT_PROTECTION: Implement root detection and protection")

        # General recommendations
        recommendations.extend([
            "CONTINUOUS_MONITORING: Implement runtime monitoring for suspicious activities",
            "CODE_REVIEW: Conduct thorough code review for security issues",
            "PENETRATION_TESTING: Perform comprehensive penetration testing"
        ])

        return recommendations

    def generate_forensic_markdown_report(self, report):
        """Generate forensic analysis markdown report"""
        markdown_file = self.phase4_dir / "forensic_analysis_report.md"

        with open(markdown_file, 'w') as f:
            f.write("# MyMaynDrive Forensic Analysis Report\n\n")
            f.write(f"**Package:** {report['package_name']}\n")
            f.write(f"**Analysis Date:** {report['analysis_date']}\n\n")

            # Executive Summary
            f.write("## Executive Summary\n\n")
            findings = report["security_findings"]
            f.write(f"- **Critical Findings:** {len(findings['critical'])}\n")
            f.write(f"- **High Risk Findings:** {len(findings['high'])}\n")
            f.write(f"- **Medium Risk Findings:** {len(findings['medium'])}\n")
            f.write(f"- **Low Risk Findings:** {len(findings['low'])}\n\n")

            # Security Findings
            f.write("## Security Findings\n\n")

            for severity in ["critical", "high", "medium", "low"]:
                if findings[severity]:
                    f.write(f"### {severity.title()} Severity\n\n")
                    for finding in findings[severity]:
                        f.write(f"- ❌ {finding}\n")
                    f.write("\n")

            # Evidence Analysis
            evidence = report["evidence_analysis"]
            if evidence.get("signature_analysis", {}).get("suspicious_strings"):
                f.write("## Suspicious Patterns Detected\n\n")
                for sus in evidence["signature_analysis"]["suspicious_strings"]:
                    f.write(f"### {sus['category'].replace('_', ' ').title()}\n")
                    for pattern in sus["patterns"]:
                        f.write(f"- `{pattern}`\n")
                    f.write("\n")

            # Cryptographic Analysis
            crypto = report["cryptographic_analysis"]
            if crypto.get("implementation_weaknesses"):
                f.write("## Cryptographic Weaknesses\n\n")
                for weakness in crypto["implementation_weaknesses"]:
                    f.write(f"- **{weakness['weakness']}** (Severity: {weakness['severity']})\n")
                f.write("\n")

            # Recommendations
            f.write("## Security Recommendations\n\n")
            for rec in report["recommendations"]:
                f.write(f"1. {rec}\n")
            f.write("\n")

            # Next Steps
            f.write("## Recommended Next Steps\n\n")
            f.write("1. **Immediate Action:** Address all critical and high-risk findings\n")
            f.write("2. **Code Review:** Thoroughly review suspicious code sections\n")
            f.write("3. **Security Testing:** Conduct comprehensive penetration testing\n")
            f.write("4. **Continuous Monitoring:** Implement runtime security monitoring\n")
            f.write("5. **Developer Training:** Train developers on secure coding practices\n\n")

            f.write("---\n")
            f.write("*Forensic Analysis Report Generated by APK Analysis Framework*\n")

    def run_full_forensic_analysis(self, apk_path):
        """Run complete forensic analysis pipeline"""
        self.log(f"Starting forensic analysis for {self.package_name}")

        results = {}

        try:
            # Phase 1: Extract and analyze evidence
            evidence = self.extract_apk_evidence(apk_path)
            results["evidence"] = evidence

            # Phase 2: Memory forensics
            memory_analysis = self.perform_memory_forensics()
            results["memory_forensics"] = memory_analysis

            # Phase 3: Cryptographic analysis
            crypto_analysis = self.perform_cryptographic_analysis()
            results["cryptographic_analysis"] = crypto_analysis

            # Phase 4: Timeline analysis
            timeline_analysis = self.create_timeline_analysis()
            results["timeline_analysis"] = timeline_analysis

            # Generate comprehensive report
            report = self.generate_forensic_report(evidence, memory_analysis, crypto_analysis, timeline_analysis)

            self.log("Forensic analysis completed successfully!")
            self.log(f"Results saved to: {self.phase4_dir}")

            return True

        except Exception as e:
            self.log(f"Forensic analysis failed: {e}", "ERROR")
            return False

def main():
    parser = argparse.ArgumentParser(description="Forensic Analysis for Android APK")
    parser.add_argument("package_name", help="Android package name")
    parser.add_argument("apk_path", help="Path to APK file")
    parser.add_argument("-o", "--output", default="analysis_output", help="Output directory")

    args = parser.parse_args()

    analyzer = ForensicAnalyzer(args.package_name, args.output)
    analyzer.run_full_forensic_analysis(args.apk_path)

if __name__ == "__main__":
    main()