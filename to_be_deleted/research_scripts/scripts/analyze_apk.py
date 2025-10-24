#!/usr/bin/env python3
"""
MyMaynDrive APK Comprehensive Analysis Framework
This script orchestrates the multi-phase reverse engineering process
"""

import os
import sys
import subprocess
import json
import argparse
from pathlib import Path
from datetime import datetime

class APKAnalyzer:
    def __init__(self, apk_path, output_dir):
        self.apk_path = Path(apk_path)
        self.output_dir = Path(output_dir)
        self.results = {}

        # Create output directories
        self.phase1_dir = self.output_dir / "phase1_automated"
        self.phase2_dir = self.output_dir / "phase2_static"
        self.phase3_dir = self.output_dir / "phase3_dynamic"
        self.phase4_dir = self.output_dir / "phase4_forensic"
        self.reports_dir = self.output_dir / "reports"

        for dir in [self.phase1_dir, self.phase2_dir, self.phase3_dir,
                   self.phase4_dir, self.reports_dir]:
            dir.mkdir(parents=True, exist_ok=True)

    def log(self, message, phase="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{phase}] {message}")

    def validate_apk(self):
        """Validate that the APK file exists and is readable"""
        if not self.apk_path.exists():
            self.log(f"APK file not found: {self.apk_path}", "ERROR")
            return False

        if not self.apk_path.suffix.lower() == '.apk':
            self.log(f"File is not an APK: {self.apk_path}", "ERROR")
            return False

        self.log(f"APK file validated: {self.apk_path} ({self.apk_path.stat().st_size / 1024 / 1024:.2f} MB)")
        return True

    def phase1_automated_scanning(self):
        """Phase 1: Automated security scanning"""
        self.log("Starting Phase 1: Automated Security Scanning")

        results = {
            "androguard": self.run_androguard(),
            "mobsf": self.run_mobsf(),
            "permissions": self.extract_permissions(),
            "strings": self.extract_strings()
        }

        self.results["phase1"] = results
        self.save_json_results(self.phase1_dir / "phase1_results.json", results)
        return results

    def run_androguard(self):
        """Run Androguard analysis"""
        self.log("Running Androguard analysis...")

        try:
            # Basic androguard analysis
            cmd = [
                "python3", "-c",
                f"""
import androguard
a, d, dx = androguard.misc.Analyze('{self.apk_path}')
analysis = {{
    'activities': [x.name for x in a.get_activities()],
    'services': [x.name for x in a.get_services()],
    'receivers': [x.name for x in a.get_receivers()],
    'permissions': list(a.get_permissions()),
    'main_activity': a.get_main_activity(),
    'exported_activities': [x.name for x in a.get_activities() if x.is_exported()],
    'native_libraries': [lib for lib in a.get_libraries() if 'native' in str(lib)]
}}
print(json.dumps(analysis))
"""
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                self.log(f"Androguard error: {result.stderr}", "ERROR")
                return {}

        except Exception as e:
            self.log(f"Androguard failed: {e}", "ERROR")
            return {}

    def run_mobsf(self):
        """Run MobSF analysis (if available)"""
        self.log("MobSF analysis requires manual setup - skipping automated run")
        return {"status": "requires_manual_setup"}

    def extract_permissions(self):
        """Extract APK permissions using aapt"""
        self.log("Extracting APK permissions...")

        try:
            cmd = ["aapt", "dump", "permissions", str(self.apk_path)]
            result = subprocess.run(cmd, capture_output=True, text=True)

            permissions = []
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        permissions.append(line.strip())

            return {"permissions": permissions}

        except Exception as e:
            self.log(f"Permission extraction failed: {e}", "ERROR")
            return {}

    def extract_strings(self):
        """Extract strings from APK"""
        self.log("Extracting strings from APK...")

        try:
            # Extract APK
            extract_dir = self.phase1_dir / "extracted"
            extract_dir.mkdir(exist_ok=True)

            cmd = ["unzip", "-q", str(self.apk_path), "-d", str(extract_dir)]
            subprocess.run(cmd, check=True)

            # Extract strings from files
            strings_file = self.phase1_dir / "extracted_strings.txt"
            with open(strings_file, 'w') as f:
                # Search for strings in various file types
                for root, dirs, files in os.walk(extract_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            cmd_strings = ["strings", file_path]
                            result = subprocess.run(cmd_strings, capture_output=True, text=True)
                            if result.stdout:
                                f.write(f"=== {file_path} ===\n")
                                f.write(result.stdout + "\n\n")
                        except:
                            continue

            # Analyze strings for potential secrets
            secrets = self.analyze_strings_for_secrets(strings_file)
            return {"strings_file": str(strings_file), "potential_secrets": secrets}

        except Exception as e:
            self.log(f"String extraction failed: {e}", "ERROR")
            return {}

    def analyze_strings_for_secrets(self, strings_file):
        """Analyze extracted strings for potential secrets"""
        import re

        secrets = {
            "api_keys": [],
            "urls": [],
            "emails": [],
            "potential_passwords": []
        }

        patterns = {
            "api_keys": [
                r'[A-Za-z0-9]{32,}',  # Generic API keys
                r'AIza[0-9A-Za-z_-]{35}',  # Google API keys
                r'[a-f0-9]{40}',  # SHA1 hashes
            ],
            "urls": [
                r'https?://[^\s<>"{}|\\^`\[\]]+',
                r'ftp://[^\s<>"{}|\\^`\[\]]+',
            ],
            "emails": [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            ],
            "potential_passwords": [
                r'password["\s]*[:=]["\s]*([A-Za-z0-9@#$%^&+=]+)',
                r'secret["\s]*[:=]["\s]*([A-Za-z0-9@#$%^&+=]+)',
            ]
        }

        try:
            with open(strings_file, 'r') as f:
                content = f.read()

                for category, regex_list in patterns.items():
                    for pattern in regex_list:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            secrets[category].extend(matches)

        except Exception as e:
            self.log(f"String analysis failed: {e}", "ERROR")

        return secrets

    def phase2_static_analysis(self):
        """Phase 2: Advanced static analysis"""
        self.log("Starting Phase 2: Advanced Static Analysis")

        results = {
            "jadx": self.run_jadx_analysis(),
            "apktool": self.run_apktool_analysis(),
            "manifest": self.analyze_manifest(),
            "native_libs": self.analyze_native_libraries()
        }

        self.results["phase2"] = results
        self.save_json_results(self.phase2_dir / "phase2_results.json", results)
        return results

    def run_jadx_analysis(self):
        """Run JADX decompilation"""
        self.log("Running JADX decompilation...")

        try:
            output_dir = self.phase2_dir / "jadx_output"
            cmd = ["jadx", str(self.apk_path), "-d", str(output_dir)]
            result = subprocess.run(cmd, capture_output=True, text=True)

            return {
                "status": "success" if result.returncode == 0 else "failed",
                "output_dir": str(output_dir),
                "stdout": result.stdout,
                "stderr": result.stderr
            }

        except Exception as e:
            self.log(f"JADX analysis failed: {e}", "ERROR")
            return {"status": "failed", "error": str(e)}

    def run_apktool_analysis(self):
        """Run APKTool analysis"""
        self.log("Running APKTool analysis...")

        try:
            output_dir = self.phase2_dir / "apktool_output"
            cmd = ["apktool", "d", str(self.apk_path), "-o", str(output_dir)]
            result = subprocess.run(cmd, capture_output=True, text=True)

            return {
                "status": "success" if result.returncode == 0 else "failed",
                "output_dir": str(output_dir),
                "stdout": result.stdout,
                "stderr": result.stderr
            }

        except Exception as e:
            self.log(f"APKTool analysis failed: {e}", "ERROR")
            return {"status": "failed", "error": str(e)}

    def analyze_manifest(self):
        """Analyze AndroidManifest.xml"""
        self.log("Analyzing AndroidManifest.xml...")

        try:
            cmd = ["aapt", "dump", "xmltree", str(self.apk_path), "AndroidManifest.xml"]
            result = subprocess.run(cmd, capture_output=True, text=True)

            manifest_info = {
                "raw_output": result.stdout if result.returncode == 0 else "",
                "security_issues": []
            }

            if result.returncode == 0:
                # Look for potential security issues
                output = result.stdout
                if "android:debuggable=\"true\"" in output:
                    manifest_info["security_issues"].append("Debuggable application")
                if "android:allowBackup=\"true\"" in output:
                    manifest_info["security_issues"].append("Backup allowed")
                if "android:usesCleartextTraffic=\"true\"" in output:
                    manifest_info["security_issues"].append("Cleartext traffic allowed")

            return manifest_info

        except Exception as e:
            self.log(f"Manifest analysis failed: {e}", "ERROR")
            return {"error": str(e)}

    def analyze_native_libraries(self):
        """Analyze native libraries"""
        self.log("Analyzing native libraries...")

        native_libs = []
        try:
            cmd = ["unzip", "-l", str(self.apk_path)]
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'lib/' in line and '.so' in line:
                        native_libs.append(line.strip())

        except Exception as e:
            self.log(f"Native library analysis failed: {e}", "ERROR")

        return {"native_libraries": native_libs}

    def save_json_results(self, file_path, data):
        """Save results to JSON file"""
        try:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            self.log(f"Results saved to: {file_path}")
        except Exception as e:
            self.log(f"Failed to save results: {e}", "ERROR")

    def generate_report(self):
        """Generate comprehensive vulnerability report"""
        self.log("Generating comprehensive vulnerability report...")

        report = {
            "apk_file": str(self.apk_path),
            "analysis_date": datetime.now().isoformat(),
            "results": self.results,
            "summary": self.generate_summary(),
            "recommendations": self.generate_recommendations()
        }

        report_file = self.reports_dir / "comprehensive_analysis_report.json"
        self.save_json_results(report_file, report)

        # Generate human-readable report
        self.generate_markdown_report(report)

        return report

    def generate_summary(self):
        """Generate analysis summary"""
        summary = {
            "total_permissions": 0,
            "dangerous_permissions": [],
            "exported_components": [],
            "native_libraries": [],
            "potential_secrets": [],
            "security_issues": []
        }

        # Analyze Phase 1 results
        if "phase1" in self.results:
            phase1 = self.results["phase1"]
            if "androguard" in phase1:
                summary["total_permissions"] = len(phase1["androguard"].get("permissions", []))
                summary["exported_components"] = phase1["androguard"].get("exported_activities", [])
            if "strings" in phase1:
                summary["potential_secrets"] = phase1["strings"].get("potential_secrets", {})

        # Analyze Phase 2 results
        if "phase2" in self.results:
            phase2 = self.results["phase2"]
            if "manifest" in phase2:
                summary["security_issues"] = phase2["manifest"].get("security_issues", [])
            if "native_libs" in phase2:
                summary["native_libraries"] = phase2["native_libs"].get("native_libraries", [])

        return summary

    def generate_recommendations(self):
        """Generate security recommendations"""
        recommendations = []

        if "phase2" in self.results:
            manifest = self.results["phase2"].get("manifest", {})
            security_issues = manifest.get("security_issues", [])

            for issue in security_issues:
                if "Debuggable" in issue:
                    recommendations.append("DISABLE_DEBUGGING: Set android:debuggable=\"false\" in production")
                elif "Backup allowed" in issue:
                    recommendations.append("SECURE_BACKUP: Set android:allowBackup=\"false\" or implement proper backup security")
                elif "Cleartext traffic" in issue:
                    recommendations.append("ENCRYPT_TRAFFIC: Use HTTPS and set android:usesCleartextTraffic=\"false\"")

        if "phase1" in self.results:
            secrets = self.results["phase1"].get("strings", {}).get("potential_secrets", {})
            if secrets.get("api_keys"):
                recommendations.append("SECURE_API_KEYS: Remove hardcoded API keys, use secure storage")
            if secrets.get("potential_passwords"):
                recommendations.append("REMOVE_PASSWORDS: Remove hardcoded passwords from the application")

        return recommendations

    def generate_markdown_report(self, report):
        """Generate human-readable markdown report"""
        markdown_file = self.reports_dir / "vulnerability_report.md"

        try:
            with open(markdown_file, 'w') as f:
                f.write("# MyMaynDrive APK Security Analysis Report\n\n")
                f.write(f"**Analysis Date:** {report['analysis_date']}\n")
                f.write(f"**APK File:** {report['apk_file']}\n\n")

                # Summary Section
                f.write("## Executive Summary\n\n")
                summary = report["summary"]
                f.write(f"- **Total Permissions:** {summary['total_permissions']}\n")
                f.write(f"- **Exported Components:** {len(summary['exported_components'])}\n")
                f.write(f"- **Native Libraries:** {len(summary['native_libraries'])}\n")
                f.write(f"- **Security Issues Found:** {len(summary['security_issues'])}\n\n")

                # Security Issues
                if summary['security_issues']:
                    f.write("## Security Issues\n\n")
                    for issue in summary['security_issues']:
                        f.write(f"- ❌ {issue}\n")
                    f.write("\n")

                # Potential Secrets
                secrets = summary['potential_secrets']
                if any(secrets.values()):
                    f.write("## Potential Hardcoded Secrets\n\n")
                    for secret_type, values in secrets.items():
                        if values:
                            f.write(f"### {secret_type.replace('_', ' ').title()}\n")
                            for value in values[:5]:  # Limit to first 5
                                f.write(f"- `{value[:50]}...`\n" if len(str(value)) > 50 else f"- `{value}`\n")
                            f.write("\n")

                # Recommendations
                f.write("## Security Recommendations\n\n")
                for rec in report["recommendations"]:
                    f.write(f"1. {rec}\n")
                f.write("\n")

                # Next Steps
                f.write("## Next Steps for Deep Analysis\n\n")
                f.write("1. **Dynamic Analysis:** Run the app in an emulator with Frida hooking\n")
                f.write("2. **Network Analysis:** Monitor network traffic for data leaks\n")
                f.write("3. **Memory Analysis:** Dump memory during runtime\n")
                f.write("4. **Native Code Analysis:** Analyze .so files with Ghidra\n")
                f.write("5. **Permission Abuse Testing:** Test each permission's usage\n\n")

                f.write("---\n")
                f.write("*Report generated by APK Analysis Framework*\n")

            self.log(f"Markdown report generated: {markdown_file}")

        except Exception as e:
            self.log(f"Failed to generate markdown report: {e}", "ERROR")

    def run_full_analysis(self):
        """Run complete analysis pipeline"""
        self.log(f"Starting comprehensive analysis of {self.apk_path}")

        if not self.validate_apk():
            return False

        try:
            # Phase 1: Automated Scanning
            self.phase1_automated_scanning()

            # Phase 2: Static Analysis
            self.phase2_static_analysis()

            # Generate Report
            report = self.generate_report()

            self.log("Analysis completed successfully!")
            self.log(f"Results saved to: {self.output_dir}")
            self.log(f"Report: {self.reports_dir / 'vulnerability_report.md'}")

            return True

        except Exception as e:
            self.log(f"Analysis failed: {e}", "ERROR")
            return False

def main():
    parser = argparse.ArgumentParser(description="Comprehensive APK Analysis Framework")
    parser.add_argument("apk_path", help="Path to the APK file")
    parser.add_argument("-o", "--output", default="analysis_output", help="Output directory")
    parser.add_argument("--phase", choices=["1", "2", "all"], default="all", help="Analysis phase to run")

    args = parser.parse_args()

    analyzer = APKAnalyzer(args.apk_path, args.output)

    if args.phase == "1":
        analyzer.phase1_automated_scanning()
    elif args.phase == "2":
        analyzer.phase2_static_analysis()
    else:
        analyzer.run_full_analysis()

if __name__ == "__main__":
    main()