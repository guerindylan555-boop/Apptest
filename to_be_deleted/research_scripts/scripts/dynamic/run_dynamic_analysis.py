#!/usr/bin/env python3
"""
MyMaynDrive APK Dynamic Analysis Orchestrator
This script manages and runs comprehensive dynamic analysis using Frida
"""

import os
import sys
import time
import subprocess
import threading
import json
from datetime import datetime
from pathlib import Path

class DynamicAnalyzer:
    def __init__(self, package_name="fr.mayndrive.app", script_dir="scripts/dynamic"):
        self.package_name = package_name
        self.script_dir = Path(script_dir)
        self.output_dir = Path("reports/dynamic_analysis")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Analysis scripts
        self.scripts = {
            "api_keys": "hook_api_keys.js",
            "payment": "hook_payment_processing.js",
            "ssl_bypass": "hook_ssl_bypass.js",
            "data_storage": "hook_data_storage.js",
            "memory": "hook_memory_analysis.js"
        }

        self.analysis_results = {}
        self.start_time = datetime.now()

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")

    def check_device(self):
        """Check if Android device/emulator is available"""
        try:
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True)
            devices = result.stdout.strip().split('\n')[1:]  # Skip header

            if len(devices) == 0 or (len(devices) == 1 and '' in devices):
                return False

            for device in devices:
                if device.strip() and 'device' in device:
                    self.log(f"Device found: {device.split()[0]}")
                    return True

            return False
        except Exception as e:
            self.log(f"Error checking device: {e}", "ERROR")
            return False

    def wait_for_device(self, timeout=120):
        """Wait for device to be ready"""
        self.log("Waiting for device to be ready...")

        for i in range(timeout):
            if self.check_device():
                self.log("Device is ready!")
                return True

            time.sleep(1)

        self.log("Timeout waiting for device", "ERROR")
        return False

    def install_apk(self):
        """Install the MyMaynDrive APK"""
        apk_path = "app.apk"

        if not os.path.exists(apk_path):
            self.log(f"APK not found: {apk_path}", "ERROR")
            return False

        self.log(f"Installing APK: {apk_path}")

        try:
            # Uninstall existing app
            subprocess.run(['adb', 'uninstall', self.package_name],
                         capture_output=True)

            # Install APK
            result = subprocess.run(['adb', 'install', '-r', apk_path],
                                  capture_output=True, text=True)

            if result.returncode == 0:
                self.log("APK installed successfully")
                return True
            else:
                self.log(f"Failed to install APK: {result.stderr}", "ERROR")
                return False

        except Exception as e:
            self.log(f"Error installing APK: {e}", "ERROR")
            return False

    def run_frida_script(self, script_name, output_file):
        """Run a single Frida script and capture output"""
        script_path = self.script_dir / script_name

        if not script_path.exists():
            self.log(f"Script not found: {script_path}", "ERROR")
            return False

        self.log(f"Running Frida script: {script_name}")

        try:
            # Use Frida to spawn and hook the application
            cmd = [
                'frida', '-U', '-f', self.package_name,
                '-l', str(script_path),
                '--no-pause',
                '--runtime=V8'
            ]

            # Start the process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            # Write output to file
            with open(output_file, 'w') as f:
                f.write(f"=== {script_name} Analysis ===\n")
                f.write(f"Started at: {datetime.now().isoformat()}\n\n")

                # Read output in real-time
                for line in iter(process.stdout.readline, ''):
                    if line:
                        print(line.strip())  # Also display on console
                        f.write(line)
                        f.flush()

                # Write any stderr
                stderr_output = process.stderr.read()
                if stderr_output:
                    f.write(f"\n=== STDERR ===\n{stderr_output}")

                f.write(f"\n=== Analysis completed at: {datetime.now().isoformat()} ===\n")

            return_code = process.wait()

            if return_code == 0:
                self.log(f"Script {script_name} completed successfully")
                return True
            else:
                self.log(f"Script {script_name} failed with code {return_code}", "WARN")
                return False

        except Exception as e:
            self.log(f"Error running script {script_name}: {e}", "ERROR")
            return False

    def run_all_scripts(self, duration=300):
        """Run all Frida scripts for specified duration"""
        self.log(f"Starting dynamic analysis for {duration} seconds...")

        # Create output file for this run
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        main_output = self.output_dir / f"dynamic_analysis_{timestamp}.txt"

        # Start all scripts in parallel
        threads = []
        script_outputs = {}

        for analysis_type, script_name in self.scripts.items():
            output_file = self.output_dir / f"{analysis_type}_{timestamp}.txt"
            script_outputs[analysis_type] = output_file

            # Create thread for each script
            thread = threading.Thread(
                target=self.run_frida_script,
                args=(script_name, output_file)
            )
            threads.append(thread)
            thread.start()

        # Wait for specified duration
        self.log(f"Analysis running for {duration} seconds...")
        time.sleep(duration)

        # Note: In a real scenario, you'd want proper process termination
        self.log("Analysis duration completed")

        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=30)

        return script_outputs

    def analyze_results(self, script_outputs):
        """Analyze the results from all scripts"""
        self.log("Analyzing dynamic analysis results...")

        analysis_summary = {
            "start_time": self.start_time.isoformat(),
            "end_time": datetime.now().isoformat(),
            "package_name": self.package_name,
            "findings": {},
            "summary": {}
        }

        # Analyze each script output
        for analysis_type, output_file in script_outputs.items():
            if output_file.exists():
                self.log(f"Analyzing {analysis_type} results...")

                with open(output_file, 'r') as f:
                    content = f.read()

                # Count findings
                findings_count = content.count("[!]")  # Our finding indicator
                warnings_count = content.count("⚠️")
                critical_count = content.count("🚨")

                analysis_summary["findings"][analysis_type] = {
                    "file": str(output_file),
                    "findings_count": findings_count,
                    "warnings_count": warnings_count,
                    "critical_count": critical_count,
                    "total_lines": len(content.split('\n'))
                }

        # Create summary statistics
        total_findings = sum(f["findings_count"] for f in analysis_summary["findings"].values())
        total_warnings = sum(f["warnings_count"] for f in analysis_summary["findings"].values())
        total_critical = sum(f["critical_count"] for f in analysis_summary["findings"].values())

        analysis_summary["summary"] = {
            "total_findings": total_findings,
            "total_warnings": total_warnings,
            "total_critical": total_critical,
            "scripts_executed": len(analysis_summary["findings"]),
            "analysis_duration_seconds": (datetime.now() - self.start_time).total_seconds()
        }

        # Save analysis summary
        summary_file = self.output_dir / f"dynamic_analysis_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_file, 'w') as f:
            json.dump(analysis_summary, f, indent=2, default=str)

        self.log(f"Analysis summary saved to: {summary_file}")

        # Print summary
        self.log("=== DYNAMIC ANALYSIS SUMMARY ===")
        self.log(f"Total Findings: {total_findings}")
        self.log(f"Total Warnings: {total_warnings}")
        self.log(f"Total Critical: {total_critical}")
        self.log(f"Scripts Executed: {len(analysis_summary['findings'])}")
        self.log(f"Duration: {analysis_summary['summary']['analysis_duration_seconds']:.2f} seconds")

        return analysis_summary

    def generate_report(self, analysis_summary):
        """Generate a comprehensive dynamic analysis report"""
        report_file = self.output_dir / f"dynamic_analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

        report_content = f"""# MyMaynDrive APK - Dynamic Analysis Report

## Analysis Overview

- **Package**: {self.package_name}
- **Start Time**: {analysis_summary['start_time']}
- **End Time**: {analysis_summary['end_time']}
- **Duration**: {analysis_summary['summary']['analysis_duration_seconds']:.2f} seconds
- **Scripts Executed**: {analysis_summary['summary']['scripts_executed']}

## Executive Summary

- **Total Findings**: {analysis_summary['summary']['total_findings']}
- **Total Warnings**: {analysis_summary['summary']['total_warnings']}
- **Total Critical Issues**: {analysis_summary['summary']['total_critical']}

## Detailed Findings

"""

        for analysis_type, findings in analysis_summary['findings'].items():
            report_content += f"""### {analysis_type.replace('_', ' ').title()} Analysis

- **Findings**: {findings['findings_count']}
- **Warnings**: {findings['warnings_count']}
- **Critical**: {findings['critical_count']}
- **Output File**: `{findings['file']}`

"""

        report_content += f"""## Key Findings

1. **API Key Usage**: {'Detected' if analysis_summary['findings'].get('api_keys', {}).get('findings_count', 0) > 0 else 'Not Detected'}
2. **Payment Processing**: {'Activity Detected' if analysis_summary['findings'].get('payment', {}).get('findings_count', 0) > 0 else 'No Activity'}
3. **SSL/Bypass**: {'Bypassed Successfully' if analysis_summary['findings'].get('ssl_bypass', {}).get('findings_count', 0) > 0 else 'No Bypass Activity'}
4. **Data Storage**: {'Sensitive Operations' if analysis_summary['findings'].get('data_storage', {}).get('findings_count', 0) > 0 else 'No Sensitive Operations'}
5. **Memory Analysis**: {'Secrets Found' if analysis_summary['findings'].get('memory', {}).get('findings_count', 0) > 0 else 'No Secrets in Memory'}

## Recommendations

### Immediate Actions
1. Review critical findings marked with 🚨 in the detailed output files
2. Investigate any API key usage detected in runtime
3. Validate SSL bypass effectiveness for security testing

### Further Analysis
1. Extend analysis duration for more comprehensive coverage
2. Test specific user workflows to trigger more functionality
3. Combine with network traffic analysis for complete security assessment

## Next Steps

1. Review individual script output files for detailed findings
2. Cross-reference with static analysis results
3. Implement security controls for identified issues
4. Conduct regression testing after fixes

---

*Report generated on {datetime.now().isoformat()}*
*Analysis framework: MyMaynDrive Dynamic Analyzer*
"""

        with open(report_file, 'w') as f:
            f.write(report_content)

        self.log(f"Dynamic analysis report saved to: {report_file}")
        return report_file

    def run_complete_analysis(self, duration=300):
        """Run the complete dynamic analysis pipeline"""
        self.log("=== Starting Complete Dynamic Analysis ===")

        # Check device
        if not self.check_device():
            if not self.wait_for_device():
                return False

        # Install APK
        if not self.install_apk():
            return False

        # Run all scripts
        script_outputs = self.run_all_scripts(duration)

        # Analyze results
        analysis_summary = self.analyze_results(script_outputs)

        # Generate report
        report_file = self.generate_report(analysis_summary)

        self.log("=== Dynamic Analysis Complete ===")
        return True

def main():
    print("🔍 MyMaynDrive APK Dynamic Analysis")
    print("=" * 50)

    analyzer = DynamicAnalyzer()

    try:
        success = analyzer.run_complete_analysis(duration=180)  # 3 minutes

        if success:
            print("✅ Dynamic analysis completed successfully!")
        else:
            print("❌ Dynamic analysis failed!")

    except KeyboardInterrupt:
        print("\n⚠️  Analysis interrupted by user")
    except Exception as e:
        print(f"❌ Analysis failed: {e}")

if __name__ == "__main__":
    main()