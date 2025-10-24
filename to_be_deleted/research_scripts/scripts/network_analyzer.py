#!/usr/bin/env python3
"""
Network Communication Analysis for MyMaynDrive APK
This script analyzes network endpoints, APIs, data flows, and security configurations
"""

import os
import re
import json
import sys
from pathlib import Path
from collections import defaultdict, Counter
from urllib.parse import urlparse
from datetime import datetime

class NetworkAnalyzer:
    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self.phase1_dir = self.output_dir / "phase1_automated"
        self.apktool_dir = self.output_dir / "phase2_static" / "apktool_output"
        self.analysis_results = {}

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")

    def analyze_network_endpoints(self):
        """Extract and analyze all network endpoints from the app"""
        self.log("Analyzing network endpoints...")

        endpoints = {
            "http_urls": [],
            "https_urls": [],
            "api_endpoints": [],
            "webhooks": [],
            "payment_gateways": [],
            "analytics_endpoints": [],
            "crash_reporting": [],
            "update_servers": []
        }

        # Read extracted strings for URLs
        strings_file = self.phase1_dir / "extracted_strings.txt"
        if strings_file.exists():
            try:
                with open(strings_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Extract URLs
                url_patterns = [
                    r'https?://[^\s<>"{}|\\^`\[\]]+',
                    r'api\.[^\s<>"{}|\\^`\[\]]+',
                    r'[\'"][^\'"]*\.(com|org|net|io|co|app|dev|api)[^\s<>"{}|\\^`\[\]]*[\'"]'
                ]

                for pattern in url_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        # Clean up the match
                        url = match.strip('\'"<>{}|\\^`[]')
                        if len(url) > 10:  # Filter out short false positives
                            if url.startswith('https://'):
                                endpoints["https_urls"].append(url)
                            elif url.startswith('http://'):
                                endpoints["http_urls"].append(url)
                            else:
                                endpoints["api_endpoints"].append(url)

                # Remove duplicates and categorize
                endpoints["https_urls"] = list(set(endpoints["https_urls"]))
                endpoints["http_urls"] = list(set(endpoints["http_urls"]))
                endpoints["api_endpoints"] = list(set(endpoints["api_endpoints"]))

                # Categorize specific endpoints
                all_urls = endpoints["https_urls"] + endpoints["http_urls"]

                for url in all_urls:
                    domain = urlparse(url).netloc.lower()
                    if domain:
                        # Payment gateways
                        if any(gateway in domain for gateway in ['stripe', 'braintree', 'paypal', 'adyen', 'square']):
                            endpoints["payment_gateways"].append(url)

                        # Analytics
                        elif any(analytic in domain for analytic in ['google-analytics', 'firebase', 'mixpanel', 'amplitude', 'segment']):
                            endpoints["analytics_endpoints"].append(url)

                        # Crash reporting
                        elif any(crash in domain for crash in ['crashlytics', 'sentry', 'bugsnag', 'firebase-crashlytics']):
                            endpoints["crash_reporting"].append(url)

                        # Update servers
                        elif any(update in domain for update in ['play.google.com', 'android.clients.google.com']):
                            endpoints["update_servers"].append(url)

            except Exception as e:
                self.log(f"Error reading strings file: {e}")

        # Remove duplicates from categorized lists
        for category in endpoints:
            endpoints[category] = list(set(endpoints[category]))

        self.analysis_results["network_endpoints"] = endpoints
        return endpoints

    def analyze_network_security_config(self):
        """Analyze network security configuration"""
        self.log("Analyzing network security configuration...")

        security_config = {
            "network_security_config": False,
            "cleartext_traffic_allowed": False,
            "ssl_pinning": False,
            "certificate_pinning": False,
            "trust_anchors_configured": False,
            "debug_overrides": False,
            "domain_rules": []
        }

        # Check for network_security_config.xml
        network_security_file = self.apktool_dir / "res/xml/network_security_config.xml"
        if network_security_file.exists():
            security_config["network_security_config"] = True
            try:
                with open(network_security_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                    # Check for cleartext traffic
                    if 'cleartextTrafficPermitted="true"' in content:
                        security_config["cleartext_traffic_allowed"] = True

                    # Check for SSL pinning
                    if 'pin-set' in content:
                        security_config["ssl_pinning"] = True

                    # Check for certificate pinning
                    if 'pin-certificate' in content or 'pin-subject' in content:
                        security_config["certificate_pinning"] = True

                    # Check for trust anchors
                    if 'trust-anchors' in content:
                        security_config["trust_anchors_configured"] = True

                    # Check for debug overrides
                    if 'debug-overrides' in content:
                        security_config["debug_overrides"] = True

                    # Extract domain rules
                    domain_rules = re.findall(r'<domain-config[^>]*>(.*?)</domain-config>', content, re.DOTALL)
                    security_config["domain_rules"] = domain_rules

            except Exception as e:
                self.log(f"Error parsing network security config: {e}")

        # Check AndroidManifest.xml for network security settings
        manifest_file = self.apktool_dir / "AndroidManifest.xml"
        if manifest_file.exists():
            try:
                with open(manifest_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                    if 'android:usesCleartextTraffic="true"' in content:
                        security_config["cleartext_traffic_allowed"] = True

                    if 'android:networkSecurityConfig' in content:
                        # Extract the resource reference
                        config_match = re.search(r'android:networkSecurityConfig="([^"]*)"', content)
                        if config_match:
                            self.log(f"Network security config referenced: {config_match.group(1)}")

            except Exception as e:
                self.log(f"Error parsing manifest for network security: {e}")

        self.analysis_results["network_security"] = security_config
        return security_config

    def analyze_payment_integrations(self):
        """Analyze payment processing integrations"""
        self.log("Analyzing payment integrations...")

        payment_analysis = {
            "providers": [],
            "endpoints": [],
            "test_mode_detected": False,
            "production_risks": []
        }

        # Check AndroidManifest.xml for payment components
        manifest_file = self.apktool_dir / "AndroidManifest.xml"
        if manifest_file.exists():
            try:
                with open(manifest_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                    # Look for payment providers
                    if 'stripe' in content.lower():
                        payment_analysis["providers"].append("Stripe")
                        # Check for test mode
                        if 'test_' in content.lower() or 'sandbox' in content.lower():
                            payment_analysis["test_mode_detected"] = True

                    if 'braintree' in content.lower():
                        payment_analysis["providers"].append("Braintree")

                    if 'paypal' in content.lower():
                        payment_analysis["providers"].append("PayPal")

                    # Look for payment-related activities
                    payment_activities = re.findall(r'<activity[^>]*name="([^"]*(?:stripe|braintree|paypal)[^"]*)"[^>]*>', content, re.IGNORECASE)
                    payment_analysis["endpoints"].extend(payment_activities)

            except Exception as e:
                self.log(f"Error analyzing payment integrations from manifest: {e}")

        # Check strings for payment-related content
        strings_file = self.phase1_dir / "extracted_strings.txt"
        if strings_file.exists():
            try:
                with open(strings_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    # Look for payment-related strings
                    payment_patterns = [
                        r'pk_test_[a-zA-Z0-9_]{24,}',  # Stripe test keys
                        r'sk_test_[a-zA-Z0-9_]{24,}',  # Stripe test keys
                        r'sandbox.*braintree',  # Braintree sandbox
                        r'test.*paypal',  # PayPal test
                        r'live.*api.*stripe'  # Stripe production
                    ]

                    for pattern in payment_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if 'test' in match.lower() or 'sandbox' in match.lower():
                                payment_analysis["test_mode_detected"] = True
                            else:
                                payment_analysis["production_risks"].append(f"Production payment config found: {match}")

            except Exception as e:
                self.log(f"Error analyzing payment strings: {e}")

        self.analysis_results["payment_analysis"] = payment_analysis
        return payment_analysis

    def analyze_data_collection_practices(self):
        """Analyze data collection and tracking practices"""
        self.log("Analyzing data collection practices...")

        data_collection = {
            "analytics_providers": [],
            "tracking_identifiers": [],
            "user_data_collected": [],
            "ad_networks": [],
            "crash_reporting": [],
            "performance_monitoring": []
        }

        # Check for analytics providers
        strings_file = self.phase1_dir / "extracted_strings.txt"
        if strings_file.exists():
            try:
                with open(strings_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    # Google Analytics
                    if 'google-analytics' in content.lower() or 'ga.js' in content:
                        data_collection["analytics_providers"].append("Google Analytics")

                    # Firebase Analytics
                    if 'firebase' in content.lower() and 'analytics' in content.lower():
                        data_collection["analytics_providers"].append("Firebase Analytics")

                    # Facebook Analytics
                    if 'facebook-analytics' in content.lower() or 'fbq(' in content:
                        data_collection["analytics_providers"].append("Facebook Analytics")

                    # Ad networks
                    ad_networks = ['admob', 'google-mobile-ads', 'facebook-ads', 'unity-ads']
                    for ad_network in ad_networks:
                        if ad_network in content.lower():
                            data_collection["ad_networks"].append(ad_network)

                    # Tracking identifiers
                    tracking_patterns = [
                        r'advertising_id',
                        r'device_id',
                        r'installation_id',
                        r'app_instance_id',
                        r'firebase_instance_id'
                    ]

                    for pattern in tracking_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            data_collection["tracking_identifiers"].append(pattern)

                    # User data collection
                    user_data_patterns = [
                        r'location',
                        r'camera',
                        r'microphone',
                        r'contacts',
                        r'sms',
                        r'calendar',
                        r'photos'
                    ]

                    for pattern in user_data_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            data_collection["user_data_collected"].append(pattern)

                    # Crash reporting
                    if 'crashlytics' in content.lower() or 'sentry' in content.lower():
                        data_collection["crash_reporting"].append("Crash reporting detected")

                    # Performance monitoring
                    if 'performance' in content.lower() or 'firebase.performance' in content.lower():
                        data_collection["performance_monitoring"].append("Performance monitoring detected")

            except Exception as e:
                self.log(f"Error analyzing data collection: {e}")

        # Remove duplicates
        for category in data_collection:
            data_collection[category] = list(set(data_collection[category]))

        self.analysis_results["data_collection"] = data_collection
        return data_collection

    def analyze_third_party_services(self):
        """Analyze third-party services and integrations"""
        self.log("Analyzing third-party services...")

        services = {
            "maps": [],
            "social": [],
            "storage": [],
            "analytics": [],
            "payments": [],
            "notifications": [],
            "authentication": [],
            "security": []
        }

        # Check AndroidManifest.xml for service declarations
        manifest_file = self.apktool_dir / "AndroidManifest.xml"
        if manifest_file.exists():
            try:
                with open(manifest_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                    # Maps services
                    if 'maps.googleapis.com' in content or 'google.maps' in content:
                        services["maps"].append("Google Maps")

                    # Social media integrations
                    social_patterns = ['facebook', 'twitter', 'instagram', 'linkedin', 'google-signin']
                    for social in social_patterns:
                        if social in content.lower():
                            services["social"].append(social.capitalize())

                    # Cloud storage
                    if 'firebase' in content.lower() and ('storage' in content.lower() or 'database' in content.lower()):
                        services["storage"].append("Firebase")

                    # Analytics (already analyzed in previous function)
                    if 'analytics' in content.lower():
                        services["analytics"].append("Analytics")

                    # Payments (already analyzed)
                    if any(payment in content.lower() for payment in ['stripe', 'braintree', 'paypal']):
                        services["payments"].append("Payment Processing")

                    # Push notifications
                    if 'fcm' in content.lower() or 'firebase.messaging' in content.lower():
                        services["notifications"].append("Firebase Cloud Messaging")

                    # Authentication
                    if 'google-signin' in content.lower() or 'firebase.auth' in content.lower():
                        services["authentication"].append("Google Sign-In")

                    # Security services
                    if 'safety' in content.lower() or 'play-integrity' in content.lower():
                        services["security"].append("Play Integrity API")

            except Exception as e:
                self.log(f"Error analyzing third-party services: {e}")

        # Remove duplicates
        for category in services:
            services[category] = list(set(services[category]))

        self.analysis_results["third_party_services"] = services
        return services

    def generate_network_analysis_report(self):
        """Generate comprehensive network analysis report"""
        self.log("Generating network analysis report...")

        # Run all analyses
        self.analyze_network_endpoints()
        self.analyze_network_security_config()
        self.analyze_payment_integrations()
        self.analyze_data_collection_practices()
        self.analyze_third_party_services()

        # Create comprehensive report
        report = {
            "apk_name": "MyMaynDrive",
            "package_name": "fr.mayndrive.app",
            "analysis_date": datetime.now().isoformat(),
            "network_analysis": self.analysis_results,
            "risk_assessment": self.assess_network_risks(),
            "recommendations": self.generate_network_recommendations()
        }

        # Save report
        report_file = self.output_dir / "reports" / "network_analysis_report.json"
        os.makedirs(self.output_dir / "reports", exist_ok=True)

        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        self.log(f"Network analysis report saved to: {report_file}")
        return report

    def assess_network_risks(self):
        """Assess network-related security risks"""
        risks = []

        network_security = self.analysis_results.get("network_security", {})
        endpoints = self.analysis_results.get("network_endpoints", {})
        payment_analysis = self.analysis_results.get("payment_analysis", {})
        data_collection = self.analysis_results.get("data_collection", {})

        # Check for cleartext traffic
        if network_security.get("cleartext_traffic_allowed"):
            risks.append({
                "severity": "HIGH",
                "category": "Network Security",
                "description": "Cleartext traffic is allowed - data can be intercepted",
                "impact": "Man-in-the-middle attacks possible"
            })

        # Check for HTTP URLs
        if endpoints.get("http_urls"):
            risks.append({
                "severity": "MEDIUM",
                "category": "Network Security",
                "description": f"HTTP endpoints found: {len(endpoints['http_urls'])}",
                "impact": "Unencrypted data transmission",
                "details": endpoints["http_urls"][:5]  # Show first 5
            })

        # Check payment security
        if payment_analysis.get("production_risks"):
            risks.append({
                "severity": "HIGH",
                "category": "Payment Security",
                "description": "Production payment configurations detected",
                "impact": "Payment data may be exposed",
                "details": payment_analysis["production_risks"]
            })

        # Check SSL pinning
        if not network_security.get("ssl_pinning"):
            risks.append({
                "severity": "MEDIUM",
                "category": "Network Security",
                "description": "SSL certificate pinning not implemented",
                "impact": "Vulnerable to certificate spoofing attacks"
            })

        # Check data collection privacy
        tracking_count = len(data_collection.get("tracking_identifiers", []))
        if tracking_count > 2:
            risks.append({
                "severity": "MEDIUM",
                "category": "Privacy",
                "description": f"Multiple tracking identifiers detected: {tracking_count}",
                "impact": "Privacy implications, user profiling"
            })

        return risks

    def generate_network_recommendations(self):
        """Generate network security recommendations"""
        recommendations = []

        network_security = self.analysis_results.get("network_security", {})
        endpoints = self.analysis_results.get("network_endpoints", {})

        # Security recommendations
        if not network_security.get("network_security_config"):
            recommendations.append({
                "priority": "HIGH",
                "category": "Network Security",
                "recommendation": "Implement network security configuration",
                "details": "Create res/xml/network_security_config.xml and reference it in AndroidManifest.xml"
            })

        if network_security.get("cleartext_traffic_allowed"):
            recommendations.append({
                "priority": "HIGH",
                "category": "Network Security",
                "recommendation": "Disable cleartext traffic",
                "details": "Set android:usesCleartextTraffic=\"false\" in AndroidManifest.xml"
            })

        if not network_security.get("ssl_pinning"):
            recommendations.append({
                "priority": "MEDIUM",
                "category": "Network Security",
                "recommendation": "Implement SSL certificate pinning",
                "details": "Add pin-set configuration to network_security_config.xml"
            })

        # HTTPS recommendations
        http_count = len(endpoints.get("http_urls", []))
        if http_count > 0:
            recommendations.append({
                "priority": "HIGH",
                "category": "Network Security",
                "recommendation": f"Replace {http_count} HTTP endpoints with HTTPS",
                "details": "All network communications should use HTTPS"
            })

        return recommendations

def main():
    from datetime import datetime

    print("🌐 MyMaynDrive Network Analyzer")
    print("=" * 50)

    output_dir = "/home/blhack/project/Apptest/glm/reverse_engineering"
    analyzer = NetworkAnalyzer(output_dir)

    try:
        report = analyzer.generate_network_analysis_report()
        print("✅ Network analysis completed successfully!")
        print(f"📄 Report saved to: {output_dir}/reports/network_analysis_report.json")

        # Print summary
        print("\n📊 Network Analysis Summary:")
        endpoints = report["network_analysis"].get("network_endpoints", {})
        print(f"🌐 HTTPS URLs: {len(endpoints.get('https_urls', []))}")
        print(f"🔓 HTTP URLs: {len(endpoints.get('http_urls', []))}")
        print(f"💳 Payment Gateways: {len(endpoints.get('payment_gateways', []))}")
        print(f"📊 Analytics: {len(endpoints.get('analytics_endpoints', []))}")

        security = report["network_analysis"].get("network_security", {})
        print(f"🔒 Security Config: {'✅ Configured' if security.get('network_security_config') else '❌ Not configured'}")
        print(f"🔓 SSL Pinning: {'✅ Implemented' if security.get('ssl_pinning') else '❌ Not implemented'}")

        risks = report.get("risk_assessment", [])
        print(f"⚠️  Security Risks: {len(risks)} identified")

        recommendations = report.get("recommendations", [])
        print(f"💡 Recommendations: {len(recommendations)} actionable items")

        # Show high-risk items
        high_risks = [r for r in risks if r["severity"] == "HIGH"]
        if high_risks:
            print("\n🚨 HIGH RISK ITEMS:")
            for risk in high_risks[:3]:
                print(f"  • {risk['description']}")

    except Exception as e:
        print(f"❌ Network analysis failed: {e}")

if __name__ == "__main__":
    main()