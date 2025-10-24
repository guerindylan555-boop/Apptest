#!/usr/bin/env python3
"""
MyMaynDrive APK Network Traffic Monitor
This script monitors network traffic during dynamic analysis
"""

import os
import sys
import time
import subprocess
import threading
import json
import re
from datetime import datetime
from pathlib import Path

class NetworkMonitor:
    def __init__(self, output_dir="reports/dynamic_analysis"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.monitoring = False
        self.packets = []

        # Network interfaces to monitor
        self.interfaces = ["wlan0", "eth0", "rmnet0", "rmnet_data0"]

        # Patterns to look for
        self.sensitive_patterns = {
            "google_maps_api": r"AIza[A-Za-z0-9_-]{35}",
            "stripe_keys": r"sk_[a-zA-Z0-9]{24,}",
            "stripe_publishable": r"pk_[a-zA-Z0-9]{24,}",
            "firebase_config": r"firebase.*\.json",
            "payment_endpoints": r"(stripe\.com|braintreegateway\.com|paypal\.com)",
            "analytics": r"(google-analytics\.com|firebase\.com)",
            "api_keys": r"(api[_-]?key|token|secret)[=:][\"']?([a-zA-Z0-9_-]{16,})",
        }

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")

    def check_tshark(self):
        """Check if tshark is available for network monitoring"""
        try:
            result = subprocess.run(['tshark', '--version'], capture_output=True, text=True)
            if result.returncode == 0:
                self.log(f"TShark found: {result.stdout.split()[1]}")
                return True
            else:
                self.log("TShark not found", "ERROR")
                return False
        except FileNotFoundError:
            self.log("TShark not installed", "ERROR")
            return False

    def check_android_network(self):
        """Check if we can monitor Android network traffic"""
        try:
            # Check if we can get network interface from Android
            result = subprocess.run(['adb', 'shell', 'ip link show'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                self.log("Android network interface access confirmed")
                return True
            else:
                self.log("Cannot access Android network interfaces", "ERROR")
                return False
        except Exception as e:
            self.log(f"Error checking Android network: {e}", "ERROR")
            return False

    def start_tcpdump_monitoring(self, interface="any", duration=300):
        """Start tcpdump on Android device"""
        self.log(f"Starting tcpdump monitoring on interface: {interface}")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_file = self.output_dir / f"network_capture_{timestamp}.pcap"

        try:
            # Start tcpdump on Android device
            cmd = [
                'adb', 'shell', 'su', '-c',
                f'tcpdump -i {interface} -w /sdcard/network_capture.pcap -G {duration} -W 1'
            ]

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            self.log(f"tcpdump started, will save to: {pcap_file}")
            return process, pcap_file

        except Exception as e:
            self.log(f"Failed to start tcpdump: {e}", "ERROR")
            return None, None

    def monitor_android_network(self, duration=300):
        """Monitor Android network traffic using adb logcat and network stats"""
        self.log(f"Starting Android network monitoring for {duration} seconds")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        network_log = self.output_dir / f"android_network_{timestamp}.log"

        # Monitor network stats and connections
        monitor_script = f"""
#!/system/bin/sh
echo "=== Network Monitoring Started at $(date) ==="

# Monitor network connections every 10 seconds
for i in $(seq 1 $((duration/10))); do
    echo "=== Network Check $i at $(date) ==="

    # Active network connections
    netstat -an 2>/dev/null | grep -E "(ESTABLISHED|TIME_WAIT|CLOSE_WAIT)"

    # Network interfaces stats
    cat /proc/net/dev | grep -E "(wlan|eth|rmnet)"

    # Network usage
    cat /proc/net/dev | tail -n +3

    echo "---"
    sleep 10
done

echo "=== Network Monitoring Completed at $(date) ==="
"""

        # Create monitoring script on device
        subprocess.run(['adb', 'shell', 'echo', f'"{monitor_script}"', '>', '/sdcard/monitor_network.sh'])
        subprocess.run(['adb', 'shell', 'chmod', '755', '/sdcard/monitor_network.sh'])

        # Start monitoring in background
        cmd = ['adb', 'shell', 'sh', '/sdcard/monitor_network.sh']
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Write output to file
        with open(network_log, 'w') as f:
            f.write(f"Android Network Monitoring - {timestamp}\n")
            f.write("=" * 50 + "\n\n")

            for line in iter(process.stdout.readline, ''):
                if line:
                    f.write(line)
                    f.flush()

        return process, network_log

    def analyze_logcat_for_network(self, duration=300):
        """Analyze logcat for network-related entries"""
        self.log(f"Analyzing logcat for network entries for {duration} seconds")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        logcat_log = self.output_dir / f"network_logcat_{timestamp}.log"

        # Start logcat with network-related filters
        cmd = [
            'adb', 'logcat', '-v', 'time',
            '-s', 'NetworkSecurityConfig:*',
            '-s', 'OkHttp:*',
            '-s', 'Conscrypt:*',
            '-s', 'cr_ssl:*',
            '-s', 'ChromiumHTTP:*'
        ]

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        with open(logcat_log, 'w') as f:
            f.write(f"Network Logcat Analysis - {timestamp}\n")
            f.write("=" * 50 + "\n\n")

            start_time = time.time()
            for line in iter(process.stdout.readline, ''):
                if time.time() - start_time > duration:
                    break

                if line:
                    # Check for sensitive patterns
                    for pattern_name, pattern in self.sensitive_patterns.items():
                        if re.search(pattern, line, re.IGNORECASE):
                            f.write(f"[{pattern_name.upper()}] {line}")
                        else:
                            f.write(line)
                    f.flush()

        process.terminate()
        return logcat_log

    def analyze_network_logs(self, log_files):
        """Analyze network log files for security issues"""
        self.log("Analyzing network logs for security issues")

        analysis_results = {
            "timestamp": datetime.now().isoformat(),
            "findings": {},
            "summary": {}
        }

        total_findings = 0

        for log_file in log_files:
            if not log_file.exists():
                continue

            self.log(f"Analyzing log file: {log_file}")

            findings = []
            with open(log_file, 'r') as f:
                content = f.read()

                # Search for sensitive patterns
                for pattern_name, pattern in self.sensitive_patterns.items():
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        findings.append({
                            "pattern": pattern_name,
                            "matches": len(matches),
                            "examples": matches[:3]  # First 3 examples
                        })
                        total_findings += len(matches)

                # Check for cleartext HTTP traffic
                http_matches = re.findall(r'http://[^\s]+', content)
                if http_matches:
                    findings.append({
                        "pattern": "cleartext_http",
                        "matches": len(http_matches),
                        "examples": http_matches[:5]
                    })
                    total_findings += len(http_matches)

                # Check for suspicious domains
                suspicious_domains = re.findall(r'[a-zA-Z0-9.-]+\.(tk|ml|ga|cf|dy|am)', content)
                if suspicious_domains:
                    findings.append({
                        "pattern": "suspicious_domains",
                        "matches": len(suspicious_domains),
                        "examples": list(set(suspicious_domains))[:5]
                    })
                    total_findings += len(suspicious_domains)

            analysis_results["findings"][log_file.name] = findings

        analysis_results["summary"] = {
            "total_findings": total_findings,
            "files_analyzed": len(log_files),
            "patterns_found": len([f for findings in analysis_results["findings"].values() if findings])
        }

        # Save analysis results
        analysis_file = self.output_dir / f"network_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(analysis_file, 'w') as f:
            json.dump(analysis_results, f, indent=2, default=str)

        self.log(f"Network analysis saved to: {analysis_file}")
        return analysis_results

    def generate_network_report(self, analysis_results):
        """Generate network security report"""
        report_file = self.output_dir / f"network_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

        report_content = f"""# MyMaynDrive APK - Network Security Analysis

## Analysis Overview

- **Analysis Date**: {analysis_results['timestamp']}
- **Files Analyzed**: {analysis_results['summary']['files_analyzed']}
- **Total Findings**: {analysis_results['summary']['total_findings']}
- **Patterns Found**: {analysis_results['summary']['patterns_found']}

## Security Findings

"""

        for file_name, findings in analysis_results['findings'].items():
            if findings:
                report_content += f"### {file_name}\n\n"

                for finding in findings:
                    report_content += f"#### {finding['pattern'].replace('_', ' ').title()}\n"
                    report_content += f"- **Matches**: {finding['matches']}\n"

                    if finding.get('examples'):
                        report_content += "- **Examples**:\n"
                        for example in finding['examples']:
                            report_content += f"  - `{example[:100]}{'...' if len(example) > 100 else ''}`\n"

                    report_content += "\n"

        report_content += f"""## Summary

### Critical Findings
- **API Keys**: {'Detected' if any('api' in f['pattern'].lower() for findings in analysis_results['findings'].values() for f in findings) else 'None detected'}
- **Payment Endpoints**: {'Detected' if any('payment' in f['pattern'].lower() for findings in analysis_results['findings'].values() for f in findings) else 'None detected'}
- **Cleartext Traffic**: {'Detected' if any('cleartext' in f['pattern'].lower() for findings in analysis_results['findings'].values() for f in findings) else 'None detected'}

### Recommendations

1. **Immediate Actions**:
   - Review any API keys found in network traffic
   - Ensure all payment communications use HTTPS
   - Eliminate any cleartext HTTP communications

2. **Security Improvements**:
   - Implement SSL certificate pinning
   - Add network security configuration
   - Monitor network traffic for anomalies

3. **Monitoring**:
   - Implement real-time network traffic monitoring
   - Set up alerts for suspicious domain connections
   - Regular security audits of network communications

---

*Report generated on {datetime.now().isoformat()}*
"""

        with open(report_file, 'w') as f:
            f.write(report_content)

        self.log(f"Network security report saved to: {report_file}")
        return report_file

    def run_complete_network_analysis(self, duration=300):
        """Run complete network analysis"""
        self.log("=== Starting Complete Network Analysis ===")

        if not self.check_android_network():
            self.log("Cannot access Android network", "ERROR")
            return False

        # Start network monitoring
        network_process, network_log = self.monitor_android_network(duration)

        # Start logcat analysis
        logcat_log = self.analyze_logcat_for_network(duration)

        # Wait for monitoring to complete
        network_process.wait()

        # Analyze collected logs
        log_files = [network_log, logcat_log]
        analysis_results = self.analyze_network_logs(log_files)

        # Generate report
        report_file = self.generate_network_report(analysis_results)

        self.log("=== Network Analysis Complete ===")
        return True

def main():
    print("🌐 MyMaynDrive APK Network Monitor")
    print("=" * 40)

    monitor = NetworkMonitor()

    try:
        success = monitor.run_complete_network_analysis(duration=180)  # 3 minutes

        if success:
            print("✅ Network monitoring completed successfully!")
        else:
            print("❌ Network monitoring failed!")

    except KeyboardInterrupt:
        print("\n⚠️  Network monitoring interrupted by user")
    except Exception as e:
        print(f"❌ Network monitoring failed: {e}")

if __name__ == "__main__":
    main()