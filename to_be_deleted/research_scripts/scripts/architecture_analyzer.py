#!/usr/bin/env python3
"""
Deep Architecture Analysis for MyMaynDrive APK
This script performs comprehensive analysis of app architecture, code structure, and design patterns
"""

import os
import re
import json
import sys
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime

class ArchitectureAnalyzer:
    def __init__(self, output_dir):
        self.output_dir = Path(output_dir)
        self.apktool_dir = self.output_dir / "phase2_static" / "apktool_output"
        self.jadx_dir = self.output_dir / "phase2_static" / "jadx_output"
        self.analysis_results = {}

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{level}] {message}")

    def analyze_package_structure(self):
        """Analyze the overall package structure and architecture"""
        self.log("Analyzing package structure...")

        structure = {
            "package_name": "fr.mayndrive.app",
            "main_package": "city.knot.knotapp",
            "architecture_pattern": self.detect_architecture_pattern(),
            "package_layers": self.analyze_package_layers(),
            "entry_points": self.identify_entry_points(),
            "component_structure": self.analyze_component_structure()
        }

        self.analysis_results["package_structure"] = structure
        return structure

    def detect_architecture_pattern(self):
        """Detect the architectural pattern used in the app"""
        self.log("Detecting architectural pattern...")

        patterns = {
            "mvvm": False,
            "mvp": False,
            "mvpvm": False,
            "clean_architecture": False,
            "compose_ui": False,
            "dependency_injection": False,
            "repository_pattern": False,
            "viewmodel": False
        }

        # Search in decompiled source
        if self.jadx_dir.exists():
            for root, dirs, files in os.walk(self.jadx_dir):
                for file in files:
                    if file.endswith('.java') or file.endswith('.kt'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()

                                # Check for architectural patterns
                                if 'ViewModel' in content or 'androidx.lifecycle.ViewModel' in content:
                                    patterns['mvvm'] = True
                                    patterns['viewmodel'] = True

                                if 'Repository' in content or 'class.*Repository' in content:
                                    patterns['repository_pattern'] = True
                                    patterns['mvvm'] = True

                                if '@Inject' in content or 'Dagger' in content:
                                    patterns['dependency_injection'] = True

                                if '@Composable' in content or 'androidx.compose' in content:
                                    patterns['compose_ui'] = True

                                if 'Presenter' in content:
                                    patterns['mvp'] = True

                                if 'UseCase' in content or 'Interactor' in content:
                                    patterns['clean_architecture'] = True

                        except Exception as e:
                            continue

        # Check manifest for architecture clues
        manifest_file = self.apktool_dir / "AndroidManifest.xml"
        if manifest_file.exists():
            try:
                with open(manifest_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if 'androidx.compose' in content:
                        patterns['compose_ui'] = True
            except:
                pass

        return patterns

    def analyze_package_layers(self):
        """Analyze the package layers and their purposes"""
        layers = {
            "ui": [],
            "data": [],
            "domain": [],
            "network": [],
            "di": [],
            "utils": [],
            "models": [],
            "services": []
        }

        if self.jadx_dir.exists():
            for root, dirs, files in os.walk(self.jadx_dir):
                relative_path = os.path.relpath(root, self.jadx_dir)
                path_parts = relative_path.split(os.sep)

                # Categorize packages by layer
                if any(layer in path_parts for layer in ['ui', 'view', 'screen', 'activity', 'fragment']):
                    layers['ui'].append(relative_path)
                elif any(layer in path_parts for layer in ['data', 'repository', 'database', 'storage']):
                    layers['data'].append(relative_path)
                elif any(layer in path_parts for layer in ['domain', 'usecase', 'interactor', 'entity']):
                    layers['domain'].append(relative_path)
                elif any(layer in path_parts for layer in ['network', 'api', 'remote', 'service']):
                    layers['network'].append(relative_path)
                elif any(layer in path_parts for layer in ['di', 'injection', 'module']):
                    layers['di'].append(relative_path)
                elif any(layer in path_parts for layer in ['util', 'helper', 'extension']):
                    layers['utils'].append(relative_path)
                elif any(layer in path_parts for layer in ['model', 'entity', 'dto']):
                    layers['models'].append(relative_path)
                elif any(layer in path_parts for layer in ['service']):
                    layers['services'].append(relative_path)

        return layers

    def identify_entry_points(self):
        """Identify main entry points in the application"""
        entry_points = {
            "main_activity": None,
            "application_class": None,
            "deep_link_handlers": [],
            "services": [],
            "broadcast_receivers": [],
            "content_providers": []
        }

        # Analyze AndroidManifest.xml
        manifest_file = self.apktool_dir / "AndroidManifest.xml"
        if manifest_file.exists():
            try:
                with open(manifest_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                    # Extract main activity
                    main_activity_match = re.search(r'android:name="([^"]*MainActivity[^"]*)"', content)
                    if main_activity_match:
                        entry_points["main_activity"] = main_activity_match.group(1)

                    # Extract application class
                    app_class_match = re.search(r'android:name="([^"]*Application[^"]*)"', content)
                    if app_class_match:
                        entry_points["application_class"] = app_class_match.group(1)

                    # Extract deep link handlers
                    intent_filters = re.findall(r'<intent-filter[^>]*>.*?<data[^>]*android:scheme="([^"]*)".*?</intent-filter>', content, re.DOTALL)
                    entry_points["deep_link_handlers"] = list(set(intent_filters))

            except Exception as e:
                self.log(f"Error parsing manifest: {e}")

        return entry_points

    def analyze_component_structure(self):
        """Analyze the component structure"""
        components = {
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "fragments": [],
            "dialogs": []
        }

        if self.jadx_dir.exists():
            for root, dirs, files in os.walk(self.jadx_dir):
                for file in files:
                    if file.endswith('.java') or file.endswith('.kt'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                relative_path = os.path.relpath(file_path, self.jadx_dir)

                                # Identify component types
                                if 'extends Activity' in content or 'AppCompatActivity' in content:
                                    components["activities"].append(relative_path)
                                elif 'extends Service' in content:
                                    components["services"].append(relative_path)
                                elif 'extends BroadcastReceiver' in content:
                                    components["receivers"].append(relative_path)
                                elif 'extends ContentProvider' in content:
                                    components["providers"].append(relative_path)
                                elif 'extends Fragment' in content or 'androidx.fragment' in content:
                                    components["fragments"].append(relative_path)
                                elif 'extends Dialog' in content or 'AlertDialog' in content:
                                    components["dialogs"].append(relative_path)

                        except Exception as e:
                            continue

        return components

    def analyze_dependencies_and_libraries(self):
        """Analyze third-party dependencies and libraries"""
        self.log("Analyzing dependencies and libraries...")

        dependencies = {
            "androidx_libraries": [],
            "google_libraries": [],
            "payment_libraries": [],
            "networking_libraries": [],
            "analytics_libraries": [],
            "ui_libraries": [],
            "security_libraries": [],
            "other_libraries": []
        }

        # Check AndroidManifest.xml for library references
        manifest_file = self.apktool_dir / "AndroidManifest.xml"
        if manifest_file.exists():
            try:
                with open(manifest_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                    # AndroidX libraries
                    if 'androidx.' in content:
                        androidx_matches = re.findall(r'androidx\.([a-zA-Z0-9.]*)', content)
                        dependencies["androidx_libraries"] = list(set(androidx_matches))

                    # Google libraries
                    google_matches = re.findall(r'com\.google\.([a-zA-Z0-9.]*)', content)
                    dependencies["google_libraries"] = list(set(google_matches))

            except Exception as e:
                self.log(f"Error parsing manifest for dependencies: {e}")

        # Check for payment libraries in source code
        if self.jadx_dir.exists():
            for root, dirs, files in os.walk(self.jadx_dir):
                for file in files:
                    if file.endswith('.java') or file.endswith('.kt'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()

                                # Payment libraries
                                if 'stripe' in content.lower() or 'com.stripe' in content:
                                    dependencies["payment_libraries"].append("Stripe SDK")
                                if 'braintree' in content.lower() or 'com.braintreepayments' in content:
                                    dependencies["payment_libraries"].append("Braintree SDK")
                                if 'paypal' in content.lower() or 'com.paypal' in content:
                                    dependencies["payment_libraries"].append("PayPal SDK")

                                # Networking libraries
                                if 'retrofit' in content.lower():
                                    dependencies["networking_libraries"].append("Retrofit")
                                if 'okhttp' in content.lower():
                                    dependencies["networking_libraries"].append("OkHttp")
                                if 'volley' in content.lower():
                                    dependencies["networking_libraries"].append("Volley")

                                # Analytics libraries
                                if 'firebase' in content.lower():
                                    dependencies["analytics_libraries"].append("Firebase")
                                if 'analytics' in content.lower():
                                    dependencies["analytics_libraries"].append("Analytics SDK")

                                # Security libraries
                                if 'jackson' in content.lower():
                                    dependencies["security_libraries"].append("Jackson")
                                if 'gson' in content.lower():
                                    dependencies["security_libraries"].append("Gson")

                        except Exception as e:
                            continue

        # Remove duplicates and sort
        for category in dependencies:
            dependencies[category] = sorted(list(set(dependencies[category])))

        self.analysis_results["dependencies"] = dependencies
        return dependencies

    def analyze_security_implementations(self):
        """Analyze security implementations and patterns"""
        self.log("Analyzing security implementations...")

        security_analysis = {
            "ssl_pinning": False,
            "certificate_pinning": False,
            "root_detection": False,
            "anti_tampering": False,
            "proguard_obfuscation": False,
            "api_key_encryption": False,
            "authentication_mechanisms": [],
            "encryption_usage": [],
            "network_security_config": False
        }

        # Check for security configurations
        network_security_file = self.apktool_dir / "res/xml/network_security_config.xml"
        if network_security_file.exists():
            security_analysis["network_security_config"] = True
            try:
                with open(network_security_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if 'pin-set' in content:
                        security_analysis["certificate_pinning"] = True
            except:
                pass

        # Check AndroidManifest for security flags
        manifest_file = self.apktool_dir / "AndroidManifest.xml"
        if manifest_file.exists():
            try:
                with open(manifest_file, 'r', encoding='utf-8') as f:
                    content = f.read()

                    if 'android:debuggable="true"' in content:
                        security_analysis["debuggable"] = True

                    if 'android:allowBackup="true"' in content:
                        security_analysis["allow_backup"] = True

                    if 'android:usesCleartextTraffic="true"' in content:
                        security_analysis["cleartext_traffic"] = True

            except:
                pass

        # Check source code for security implementations
        if self.jadx_dir.exists():
            for root, dirs, files in os.walk(self.jadx_dir):
                for file in files:
                    if file.endswith('.java') or file.endswith('.kt'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()

                                # Check for SSL pinning
                                if 'CertificatePinner' in content or 'SSLContext' in content:
                                    security_analysis["ssl_pinning"] = True

                                # Check for root detection
                                if 'isRooted' in content or 'su' in content or 'root' in content:
                                    security_analysis["root_detection"] = True

                                # Check for encryption
                                if 'Cipher' in content or 'javax.crypto' in content:
                                    security_analysis["encryption_usage"].append("javax.crypto")
                                if 'AES' in content:
                                    security_analysis["encryption_usage"].append("AES")

                                # Check for authentication
                                if 'BasicAuthenticationInterceptor' in content or 'Authenticator' in content:
                                    security_analysis["authentication_mechanisms"].append("HTTP Basic")

                        except Exception as e:
                            continue

        self.analysis_results["security_analysis"] = security_analysis
        return security_analysis

    def analyze_data_storage_patterns(self):
        """Analyze data storage patterns and implementations"""
        self.log("Analyzing data storage patterns...")

        storage_patterns = {
            "shared_preferences": [],
            "sqlite_databases": [],
            "file_storage": [],
            "cloud_storage": [],
            "room_database": False,
            "data_encryption": False
        }

        # Check for storage implementations
        if self.jadx_dir.exists():
            for root, dirs, files in os.walk(self.jadx_dir):
                for file in files:
                    if file.endswith('.java') or file.endswith('.kt'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()

                                # SharedPreferences
                                if 'SharedPreferences' in content or 'PreferenceManager' in content:
                                    storage_patterns["shared_preferences"].append(os.path.relpath(file_path, self.jadx_dir))

                                # SQLite
                                if 'SQLiteDatabase' in content or 'SQLiteOpenHelper' in content:
                                    storage_patterns["sqlite_databases"].append(os.path.relpath(file_path, self.jadx_dir))

                                # Room Database
                                if 'androidx.room' in content or '@Database' in content or '@Dao' in content:
                                    storage_patterns["room_database"] = True

                                # File Storage
                                if 'FileOutputStream' in content or 'FileInputStream' in content or 'File' in content:
                                    storage_patterns["file_storage"].append(os.path.relpath(file_path, self.jadx_dir))

                                # Cloud Storage
                                if 'FirebaseStorage' in content or 'GoogleCloudStorage' in content:
                                    storage_patterns["cloud_storage"].append(os.path.relpath(file_path, self.jadx_dir))

                                # Encryption
                                if 'Cipher' in content or 'SecretKeySpec' in content or 'KeyGenerator' in content:
                                    storage_patterns["data_encryption"] = True

                        except Exception as e:
                            continue

        self.analysis_results["storage_patterns"] = storage_patterns
        return storage_patterns

    def generate_architecture_report(self):
        """Generate comprehensive architecture analysis report"""
        self.log("Generating architecture analysis report...")

        # Run all analyses
        self.analyze_package_structure()
        self.analyze_dependencies_and_libraries()
        self.analyze_security_implementations()
        self.analyze_data_storage_patterns()

        # Create report
        report = {
            "apk_name": "MyMaynDrive",
            "package_name": "fr.mayndrive.app",
            "analysis_date": datetime.now().isoformat(),
            "architecture_analysis": self.analysis_results,
            "recommendations": self.generate_architecture_recommendations()
        }

        # Save report
        report_file = self.output_dir / "reports" / "architecture_analysis_report.json"
        os.makedirs(self.output_dir / "reports", exist_ok=True)

        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        self.log(f"Architecture report saved to: {report_file}")
        return report

    def generate_architecture_recommendations(self):
        """Generate architecture-specific recommendations"""
        recommendations = []

        structure = self.analysis_results.get("package_structure", {})
        security = self.analysis_results.get("security_analysis", {})
        dependencies = self.analysis_results.get("dependencies", {})
        storage = self.analysis_results.get("storage_patterns", {})

        # Architecture pattern recommendations
        if structure.get("architecture_pattern", {}).get("compose_ui"):
            recommendations.append({
                "category": "Architecture",
                "priority": "Medium",
                "recommendation": "Modern Jetpack Compose UI detected - ensure proper ViewModel and state management implementation",
                "risk": "Potential state management issues"
            })

        # Security recommendations
        if security.get("debuggable"):
            recommendations.append({
                "category": "Security",
                "priority": "Critical",
                "recommendation": "Application is debuggable in production - set android:debuggable to false",
                "risk": "High security risk"
            })

        if not security.get("ssl_pinning"):
            recommendations.append({
                "category": "Security",
                "priority": "High",
                "recommendation": "Implement SSL certificate pinning for secure API communication",
                "risk": "Man-in-the-middle attacks possible"
            })

        # Dependency recommendations
        payment_libs = dependencies.get("payment_libraries", [])
        if payment_libs:
            recommendations.append({
                "category": "Dependencies",
                "priority": "High",
                "recommendation": f"Payment libraries detected: {', '.join(payment_libs)} - ensure PCI compliance",
                "risk": "Payment security and compliance issues"
            })

        # Storage recommendations
        if storage.get("allow_backup"):
            recommendations.append({
                "category": "Data Security",
                "priority": "Medium",
                "recommendation": "Backup enabled - review backup exclusions for sensitive data",
                "risk": "Sensitive data exposure through backups"
            })

        if not storage.get("data_encryption"):
            recommendations.append({
                "category": "Data Security",
                "priority": "Medium",
                "recommendation": "Implement encryption for sensitive data storage",
                "risk": "Data exposure if device is compromised"
            })

        return recommendations

def main():
    from datetime import datetime

    print("🏗️  MyMaynDrive Architecture Analyzer")
    print("=" * 50)

    output_dir = "/home/blhack/project/Apptest/glm/reverse_engineering"
    analyzer = ArchitectureAnalyzer(output_dir)

    try:
        report = analyzer.generate_architecture_report()
        print("✅ Architecture analysis completed successfully!")
        print(f"📄 Report saved to: {output_dir}/reports/architecture_analysis_report.json")

        # Print summary
        print("\n📊 Analysis Summary:")
        package_structure = report["architecture_analysis"].get("package_structure", {})

        if package_structure.get("architecture_pattern"):
            patterns = package_structure["architecture_pattern"]
            print(f"🏗️  Architecture: {'Compose UI' if patterns.get('compose_ui') else 'Traditional Android'}")
            print(f"📦 Pattern: {'MVVM' if patterns.get('mvvm') else 'Other'}")

        dependencies = report["architecture_analysis"].get("dependencies", {})
        total_libs = sum(len(libs) for libs in dependencies.values())
        print(f"📚 Libraries: {total_libs} dependencies detected")

        security = report["architecture_analysis"].get("security_analysis", {})
        print(f"🔒 Security: {'Issues detected' if security.get('debuggable') else 'Basic security implemented'}")

        print(f"\n💡 Recommendations: {len(report['recommendations'])} actionable items")

    except Exception as e:
        print(f"❌ Analysis failed: {e}")

if __name__ == "__main__":
    main()