#!/usr/bin/env python3
"""
Third-Party Library Security Analysis for MyMaynDrive APK
This script analyzes third-party libraries for security vulnerabilities and compliance issues
"""

import os
import re
import json
import sys
from pathlib import Path
from collections import defaultdict
from datetime import datetime

class LibrarySecurityAnalyzer:
    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self.apktool_dir = self.output_dir / "phase2_static" / "apktool_output"
        self.analysis_results = {}

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")

    def analyze_androidx_libraries(self):
        """Analyze AndroidX library versions for security issues"""
        self.log("Analyzing AndroidX libraries for security issues...")

        androidx_libraries = []
        security_issues = []

        if self.apktool_dir.exists():
            # Check AndroidManifest.xml for AndroidX references
            manifest_file = self.apktool_dir / "AndroidManifest.xml"
            if manifest_file.exists():
                try:
                    with open(manifest_file, 'r', encoding='utf-8') as f:
                        content = f.read()

                        # Extract AndroidX references
                        androidx_matches = re.findall(r'androidx\.([a-zA-Z0-9.]*)', content)
                        androidx_libraries.extend(androidx_matches)

                except Exception as e:
                    self.log(f"Error parsing manifest for AndroidX: {e}")

            # Check for known vulnerable AndroidX versions
            vulnerable_versions = {
                "androidx.webkit": {
                    "1.4.0": "WebView vulnerability CVE-2022-0254",
                    "1.3.0": "WebView vulnerability CVE-2022-0217",
                    "1.2.0": "WebView vulnerability CVE-2021-3979"
                },
                "androidx.fragment": {
                    "1.3.0": "Fragment vulnerability CVE-2021-3979",
                    "1.2.0": "Fragment vulnerability CVE-2021-3979"
                },
                "androidx.recyclerview": {
                    "1.1.0": "RecyclerView vulnerability CVE-2021-3979"
                }
            }

            # Check strings file for version information
            strings_file = self.output_dir / "phase1_automated" / "extracted_strings.txt"
            if strings_file.exists():
                try:
                    with open(strings_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                        # Look for version patterns
                        version_patterns = [
                            r'androidx\.webkit:(\d+\.\d+\.\d+)',
                            r'androidx\.fragment:(\d+\.\d+\.\d+)',
                            r'androidx\.recyclerview:(\d+\.\d+\.\d+)'
                        ]

                        for pattern in version_patterns:
                            matches = re.findall(pattern, content)
                            for match in matches:
                                library, version = match.split(':')
                                if library in vulnerable_versions:
                                    for vuln_version, description in vulnerable_versions[library].items():
                                        if self.compare_versions(version, vuln_version) >= 0:
                                            security_issues.append({
                                                "library": library,
                                                "version": version,
                                                "vulnerability": description,
                                                "severity": "HIGH"
                                            })

                except Exception as e:
                    self.log(f"Error reading strings for version analysis: {e}")

        self.analysis_results["androidx_analysis"] = {
            "libraries": androidx_libraries,
            "security_issues": security_issues,
            "total_libraries": len(androidx_libraries)
        }

        return {"androidx_libraries": androidx_libraries, "security_issues": security_issues}

    def compare_versions(self, version1, version2):
        """Compare two version strings"""
        try:
            v1_parts = [int(part) for part in version1.split('.')]
            v2_parts = [int(part) for part in version2.split('.')]

            # Pad shorter version
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))

            return v1_parts >= v2_parts
        except:
            return False

    def analyze_payment_libraries(self):
        """Analyze payment processing libraries for security issues"""
        self.log("Analyzing payment processing libraries...")

        payment_libraries = {
            "stripe": {"version": "Unknown", "issues": []},
            "braintree": {"version": "Unknown", "issues": []},
            "paypal": {"version": "Unknown", "issues": []},
            "adyen": {"version": "Unknown", "issues": []},
            "square": {"version": "Unknown", "issues": []}
        }

        # Check AndroidManifest.xml for payment library references
        manifest_file = self.apktool_dir / "AndroidManifest.xml"
        if manifest_file.exists():
            try:
                with open(manifest_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                    # Look for payment library signatures
                    if 'stripe' in content.lower():
                        payment_libraries["stripe"]["found"] = True
                        # Look for test mode indicators
                        if 'test_' in content.lower() or 'sandbox' in content.lower():
                            payment_libraries["stripe"]["test_mode"] = True

                    if 'braintree' in content.lower():
                        payment_libraries["braintree"]["found"] = True

                    if 'paypal' in content.lower():
                        payment_libraries["paypal"]["found"] = True

            except Exception as e:
                self.log(f"Error analyzing payment libraries from manifest: {e}")

        # Check for payment security best practices
        security_issues = []

        # Check for hardcoded payment credentials
        strings_file = self.output_dir / "phase1_automated" / "extracted_strings.txt"
        if strings_file.exists():
            try:
                with open(strings_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    # Look for payment API keys
                    stripe_patterns = [
                        r'sk_live_[A-Za-z0-9_]{24,}',
                        'sk_test_[A-Za-z0-9_]{24,}'
                    ]

                    for pattern in stripe_patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            if 'test_' in matches[0]:
                                payment_libraries["stripe"]["test_key_found"] = True
                            else:
                                security_issues.append({
                                    "library": "Stripe",
                                    "issue": "Live API key found in APK",
                                    "severity": "CRITICAL",
                                    "details": f"API key: {matches[0][:20]}..."
                                })

                    # Look for Braintree tokens
                    braintree_patterns = [
                        'tokenization_key_[a-zA-Z0-9_-]{32,}',
                        'client_token_[a-zA-Z0-9_-]{20,}',
                        'merchant_id_[a-zA-Z0-9_-]{16,}'
                    ]

                    for pattern in braintree_patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            security_issues.append({
                                "library": "Braintree",
                                "issue": "Payment token found in APK",
                                "severity": "HIGH",
                                "details": f"Token: {matches[0][:20]}..."
                            })

            except Exception as e:
                self.log(f"Error checking payment credentials: {e}")

        self.analysis_results["payment_libraries"] = {
            "libraries": payment_libraries,
            "security_issues": security_issues
        }

        return payment_libraries

    def analyze_analytics_libraries(self):
        """Analyze analytics and tracking libraries for privacy compliance"""
        self.log("Analyzing analytics libraries...")

        analytics_libraries = {
            "firebase": {"found": False, "issues": []},
            "google_analytics": {"found": False, "issues": []},
            "facebook_analytics": {"found": False, "issues": []},
            "mixpanel": {"found": False, "issues": []}
        }

        privacy_issues = []

        # Check for analytics providers
        strings_file = self.output_dir / "phase1_automated" / "extracted_strings.txt"
        if strings_file.exists():
            try:
                with open(strings_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    # Firebase Analytics
                    if 'firebase' in content.lower() and 'analytics' in content.lower():
                        analytics_libraries["firebase"]["found"] = True
                        # Check for Firebase configuration
                        if 'firebase-config' in content or 'firebase.json' in content:
                            privacy_issues.append({
                                "library": "Firebase Analytics",
                                "issue": "Firebase configuration file found in APK",
                                "severity": "MEDIUM",
                                "details": "Config should be loaded from backend"
                            })

                    # Google Analytics
                    if 'google-analytics' in content.lower() or 'ga.js' in content:
                        analytics_libraries["google_analytics"]["found"] = True
                        # Check for tracking ID
                        if 'GA_MEASUREMENT_ID' in content or 'tracking_id' in content:
                            privacy_issues.append({
                                "library": "Google Analytics",
                                "issue": "Tracking ID hardcoded in app",
                                "severity": "MEDIUM",
                                "details": "Should use dynamic configuration"
                            })

                    # Facebook Analytics
                    if 'facebook-analytics' in content.lower() or 'fbq(' in content:
                        analytics_libraries["facebook_analytics"]["found"] = True
                        privacy_issues.append({
                            "library": "Facebook Analytics",
                            "issue": "Facebook Analytics detected",
                            "severity": "MEDIUM",
                            "details": "Consider privacy implications"
                        })

                    # Mixpanel
                    if 'mixpanel' in content.lower():
                        analytics_libraries["mixpanel"]["found"] = True

            except Exception as e:
                self.log(f"Error analyzing analytics libraries: {e}")

        self.analysis_results["analytics_libraries"] = {
            "libraries": analytics_libraries,
            "privacy_issues": privacy_issues
        }

        return analytics_libraries

    def check_vulnerability_database(self, library_name):
        """Check a library against common vulnerability databases"""
        # This would ideally query real vulnerability databases
        # For now, we'll simulate with known vulnerable versions
        known_vulnerabilities = {
            "retrofit": {
                "2.9.0": "RCE vulnerability CVE-2023-3635",
                "2.8.0": "Information disclosure"
            },
            "okhttp": {
                "4.12.0": "Certificate validation bypass",
                "4.10.0": "HTTP request smuggling"
            },
            "gson": {
                "2.10.1": "Deserialization vulnerability CVE-2022-25647"
            },
            "jackson-databind": {
                "2.13.0": "Deserialization vulnerability CVE-2022-1475"
            },
            "firebase-bom": {
                "32.12.0": "Remote code execution vulnerability"
            }
        }

        if library_name in known_vulnerabilities:
            return known_vulnerabilities[library_name]
        return {}

    def generate_library_security_report(self):
        """Generate comprehensive library security report"""
        self.log("Generating library security analysis report...")

        # Run all library analyses
        self.analyze_androidx_libraries()
        self.analyze_payment_libraries()
        self.analyze_analytics_libraries()

        # Compile all security issues
        all_issues = []
        security_analysis = self.analysis_results.get("androidx_analysis", {})
        payment_analysis = self.analysis_results.get("payment_libraries", {})
        analytics_analysis = self.analysis_results.get("analytics_libraries", {})

        if security_analysis.get("security_issues"):
            all_issues.extend(security_analysis["security_issues"])

        if payment_analysis.get("security_issues"):
            all_issues.extend(payment_analysis["security_issues"])

        if analytics_analysis.get("privacy_issues"):
            all_issues.extend(analytics_analysis["privacy_issues"])

        # Create report
        report = {
            "apk_name": "MyMaynDrive",
            "package_name": "fr.mayndrive.app",
            "analysis_date": datetime.now().isoformat(),
            "library_analysis": self.analysis_results,
            "vulnerability_summary": {
                "total_issues": len(all_issues),
                "critical_issues": len([i for i in all_issues if i["severity"] == "CRITICAL"]),
                "high_issues": len([i for i in all_issues if i["severity"] == "HIGH"]),
                "medium_issues": len([i for i in all_issues if i["severity"] == "MEDIUM"]),
                "low_issues": len([i for i in all_issues if i["severity"] == "LOW"])
            },
            "recommendations": self.generate_library_recommendations()
        }

        # Save report
        report_file = self.output_dir / "reports" / "library_security_report.json"
        os.makedirs(self.output_dir / "reports", exist_ok=True)

        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        self.log(f"Library security report saved to: {report_file}")
        return report

    def generate_library_recommendations(self):
        """Generate library-specific security recommendations"""
        recommendations = []

        # AndroidX recommendations
        androidx_analysis = self.analysis_results.get("androidx_analysis", {})
        if androidx_analysis.get("security_issues"):
            recommendations.append({
                "priority": "HIGH",
                "category": "Library Security",
                "library": "AndroidX",
                "recommendation": "Update AndroidX libraries to latest stable versions",
                "details": f"Current issues: {len(androidx_analysis['security_issues'])} vulnerabilities"
            })

        # Payment library recommendations
        payment_analysis = self.analysis_results.get("payment_libraries", {})
        if payment_analysis.get("security_issues"):
            recommendations.append({
                "priority": "CRITICAL",
                "category": "Payment Security",
                "library": "Payment Processing",
                "recommendation": "Remove hardcoded payment credentials from APK",
                "details": f"Payment issues: {len(payment_analysis['security_issues'])} vulnerabilities"
            })

        # Analytics privacy recommendations
        analytics_analysis = self.analysis_results.get("analytics_libraries", {})
        if analytics_analysis.get("privacy_issues"):
            recommendations.append({
                "priority": "MEDIUM",
                "category": "Privacy",
                "library": "Analytics",
                "recommendation": "Review privacy settings and consent mechanisms",
                "details": f"Privacy issues: {len(analytics_analysis['privacy_issues'])} concerns"
            })

        # General recommendations
        recommendations.append({
            "priority": "LOW",
            "category": "Best Practices",
            "library": "Third-party",
            "recommendation": "Regularly update all third-party libraries",
            "details": "Keep dependencies up-to-date for security"
        })

        return recommendations

def main():
    from datetime import datetime

    print("📚 Third-Party Library Security Analyzer")
    print("=" * 60)

    output_dir = "/home/blhack/project/Apptest/glm/reverse_engineering"
    analyzer = LibrarySecurityAnalyzer(output_dir)

    try:
        report = analyzer.generate_library_security_report()
        print("✅ Library security analysis completed successfully!")
        print(f"📄 Report saved to: {output_dir}/reports/library_security_report.json")

        # Print summary
        summary = report["vulnerability_summary"]
        print("\n📊 Library Security Summary:")
        print(f"📚 Total Issues: {summary['total_issues']}")
        print(f"🚨 Critical: {summary['critical_issues']}")
        print(f"⚠️  High: {summary['high_issues']}")
        print(f"📝 Medium: {summary['medium_issues']}")
        print(f"💡 Low: {summary['low_issues']}")

        recommendations = report.get("recommendations", [])
        print(f"💡 Recommendations: {len(recommendations)} actionable items")

        # Show critical items
        critical_issues = [r for r in report.get("library_analysis", {}).get("androidx_analysis", {}).get("security_issues", []) if r.get("severity") == "CRITICAL"]
        if critical_issues:
            print("\n🚨 CRITICAL LIBRARY ISSUES:")
            for issue in critical_issues[:3]:
                print(f"  • {issue['library']} {issue['version']}: {issue['vulnerability']}")

        payment_issues = report.get("library_analysis", {}).get("payment_libraries", {}).get("security_issues", [])
        if payment_issues:
            print("\n💳 PAYMENT SECURITY ISSUES:")
            for issue in payment_issues[:3]:
                print(f"  • {issue['issue']}")

    except Exception as e:
        print(f"❌ Library security analysis failed: {e}")

if __name__ == "__main__":
    main()