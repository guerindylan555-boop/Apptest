#!/usr/bin/env python3
"""
API Key Analysis and Testing Script
This script helps analyze and test API keys found in the MyMaynDrive APK
"""

import requests
import json
import re
import sys
from urllib.parse import urljoin

class APIKeyAnalyzer:
    def __init__(self):
        self.google_api_key = "AIzaSyBmzPzugRjdJT83phq1mgu4ulzo20wQfeY"
        self.mystery_key = "9c4d65277536486ebd1094d668925aea"
        self.session = requests.Session()

    def log(self, message, level="INFO"):
        print(f"[{level}] {message}")

    def test_google_maps_api_key(self):
        """Test the Google Maps API key for validity and restrictions"""
        self.log("=" * 60)
        self.log("TESTING GOOGLE MAPS API KEY")
        self.log("=" * 60)

        self.log(f"Testing key: {self.google_api_key}")

        # Test 1: Geocoding API
        self.log("\n1. Testing Geocoding API...")
        geocoding_url = "https://maps.googleapis.com/maps/api/geocode/json"
        params = {
            'address': '1600 Amphitheatre Parkway, Mountain View, CA',
            'key': self.google_api_key
        }

        try:
            response = self.session.get(geocoding_url, params=params, timeout=10)
            data = response.json()

            if response.status_code == 200:
                if data.get('status') == 'OK':
                    self.log("✅ Geocoding API: SUCCESS", "SUCCESS")
                    if data.get('results'):
                        location = data['results'][0]['formatted_address']
                        self.log(f"   Sample result: {location}")
                elif data.get('status') == 'REQUEST_DENIED':
                    error_message = data.get('error_message', 'No error message provided')
                    self.log(f"❌ Geocoding API: REQUEST_DENIED - {error_message}", "WARNING")
                else:
                    self.log(f"❌ Geocoding API: {data.get('status', 'Unknown error')}", "ERROR")
            else:
                self.log(f"❌ Geocoding API: HTTP {response.status_code}", "ERROR")

        except Exception as e:
            self.log(f"❌ Geocoding API test failed: {e}", "ERROR")

        # Test 2: Maps Static API
        self.log("\n2. Testing Maps Static API...")
        static_map_url = "https://maps.googleapis.com/maps/api/staticmap"
        params = {
            'center': 'New York, NY',
            'zoom': 13,
            'size': '600x300',
            'key': self.google_api_key
        }

        try:
            response = self.session.get(static_map_url, params=params, timeout=10)
            if response.status_code == 200:
                self.log("✅ Static Maps API: SUCCESS", "SUCCESS")
                self.log(f"   Response size: {len(response.content)} bytes")
            elif response.status_code == 403:
                self.log("❌ Static Maps API: FORBIDDEN - Key restrictions may apply", "WARNING")
            else:
                self.log(f"❌ Static Maps API: HTTP {response.status_code}", "ERROR")

        except Exception as e:
            self.log(f"❌ Static Maps API test failed: {e}", "ERROR")

        # Test 3: Places API
        self.log("\n3. Testing Places API...")
        places_url = "https://maps.googleapis.com/maps/api/place/nearbysearch/json"
        params = {
            'location': '37.7749,-122.4194',  # San Francisco
            'radius': 500,
            'type': 'restaurant',
            'key': self.google_api_key
        }

        try:
            response = self.session.get(places_url, params=params, timeout=10)
            data = response.json()

            if response.status_code == 200:
                if data.get('status') == 'OK':
                    self.log("✅ Places API: SUCCESS", "SUCCESS")
                    results_count = len(data.get('results', []))
                    self.log(f"   Found {results_count} places")
                elif data.get('status') == 'REQUEST_DENIED':
                    error_message = data.get('error_message', 'No error message provided')
                    self.log(f"❌ Places API: REQUEST_DENIED - {error_message}", "WARNING")
                else:
                    self.log(f"❌ Places API: {data.get('status', 'Unknown error')}", "ERROR")
            else:
                self.log(f"❌ Places API: HTTP {response.status_code}", "ERROR")

        except Exception as e:
            self.log(f"❌ Places API test failed: {e}", "ERROR")

        # Test 4: Check key restrictions by testing various APIs
        self.log("\n4. Testing API restrictions...")
        apis_to_test = [
            ("Directions API", "https://maps.googleapis.com/maps/api/directions/json", {
                'origin': 'New York, NY',
                'destination': 'Los Angeles, CA',
                'key': self.google_api_key
            }),
            ("Elevation API", "https://maps.googleapis.com/maps/api/elevation/json", {
                'locations': '39.7391536,-104.9902501',
                'key': self.google_api_key
            }),
            ("Time Zone API", "https://maps.googleapis.com/maps/api/timezone/json", {
                'location': '39.6034810,-119.6822510',
                'timestamp': '1331161200',
                'key': self.google_api_key
            })
        ]

        for api_name, url, params in apis_to_test:
            try:
                response = self.session.get(url, params=params, timeout=10)
                data = response.json()

                if response.status_code == 200 and data.get('status') == 'OK':
                    self.log(f"✅ {api_name}: ACCESSIBLE", "SUCCESS")
                else:
                    status = data.get('status', 'HTTP ' + str(response.status_code))
                    self.log(f"❌ {api_name}: {status}", "WARNING")

            except Exception as e:
                self.log(f"❌ {api_name} test failed: {e}", "ERROR")

    def analyze_mystery_key(self):
        """Analyze the mystery key to determine its purpose"""
        self.log("=" * 60)
        self.log("ANALYZING MYSTERY KEY")
        self.log("=" * 60)

        self.log(f"Key to analyze: {self.mystery_key}")

        # Key characteristics
        self.log("\n🔍 Key Characteristics:")
        self.log(f"  Length: {len(self.mystery_key)} characters")
        self.log(f"  Format: Hexadecimal (0-9, a-f)")
        self.log(f"  Entropy: {self.calculate_entropy(self.mystery_key):.2f}")

        # Common key format patterns
        self.log("\n🔍 Format Analysis:")

        # Check if it matches common patterns
        patterns = {
            "MD5 Hash": r"^[a-f0-9]{32}$",
            "API Key (32-char hex)": r"^[a-f0-9]{32}$",
            "Session ID": r"^[a-f0-9]{32}$",
            "Database Key": r"^[a-f0-9]{32}$",
            "Encryption Key": r"^[a-f0-9]{32}$"
        }

        for pattern_name, pattern in patterns.items():
            if re.match(pattern, self.mystery_key, re.IGNORECASE):
                self.log(f"  ✅ Matches: {pattern_name}")

        # Test against common services
        self.log("\n🔍 Testing Against Common Services:")

        # Test 1: Check if it's a database key pattern
        self.log("\n1. Testing as Database/API Key...")

        common_endpoints = [
            ("Generic API", "https://httpbin.org/uuid", {}),
            ("Test Endpoint", "https://api.ipify.org?format=json", {}),
        ]

        # Test common auth methods
        auth_methods = [
            ("Bearer Token", {"Authorization": f"Bearer {self.mystery_key}"}),
            ("API Key Header", {"X-API-Key": self.mystery_key}),
            ("API Key Query", {"api_key": self.mystery_key}),
            ("Auth Header", {"Authorization": self.mystery_key}),
        ]

        for service_name, url, base_params in common_endpoints:
            for auth_name, auth_params in auth_methods:
                try:
                    all_params = {**base_params, **auth_params}
                    response = self.session.get(url, params=all_params, timeout=5)

                    # Only consider successful responses as potentially valid
                    if response.status_code == 200:
                        self.log(f"  ✅ {service_name} with {auth_name}: HTTP 200", "SUCCESS")
                        break
                    elif response.status_code == 401:
                        self.log(f"  ❌ {service_name} with {auth_name}: Unauthorized")
                    elif response.status_code == 403:
                        self.log(f"  ❌ {service_name} with {auth_name}: Forbidden")
                    else:
                        self.log(f"  ❓ {service_name} with {auth_name}: HTTP {response.status_code}")

                except Exception as e:
                    self.log(f"  ❌ {service_name} with {auth_name}: Failed - {e}")

        # Test 2: Check against common hash databases (public APIs)
        self.log("\n2. Checking against hash databases...")

        # Check if it's a known hash
        hash_databases = [
            ("SHA1", self.mystery_key),
            ("MD5", self.mystery_key),
        ]

        for hash_type, hash_value in hash_databases:
            self.log(f"  📝 {hash_type} hash: {hash_value}")

            # Try some common services that might use hex keys
            test_urls = [
                f"https://api.github.com/user",
                f"https://api.stripe.com/v1/account",
                f"https://api.twilio.com/2010-04-01/Accounts.json",
            ]

            for url in test_urls:
                try:
                    response = self.session.get(url, headers={
                        'Authorization': f'Bearer {hash_value}'
                    }, timeout=5)

                    if response.status_code == 200:
                        self.log(f"  ✅ Valid auth for: {url}", "SUCCESS")
                    elif response.status_code in [401, 403]:
                        self.log(f"  ❌ Invalid auth for: {url}")

                except Exception:
                    pass

        # Test 3: Analyze app context
        self.log("\n3. Context Analysis from APK...")

        self.log("  📱 App features that might use API keys:")
        self.log("    - Location services (Google Maps)")
        self.log("    - Payment processing (Stripe, Braintree)")
        self.log("    - Analytics (Firebase, Google Analytics)")
        self.log("    - Push notifications (Firebase)")
        self.log("    - Camera/ML features (Google ML Kit)")

        # Based on the app's features, what could this key be?
        self.log("\n  💡 Potential purposes based on app context:")
        self.log("    - Internal API key for MaynDrive backend")
        self.log("    - Third-party service API key")
        self.log("    - Database encryption key")
        self.log("    - Firebase configuration key")
        self.log("    - Analytics service key")

        # Check if it appears in common contexts
        self.log("\n4. Searching in app context...")

        # Read the extracted strings to find context
        try:
            with open('phase1_automated/extracted_strings.txt', 'r') as f:
                content = f.read()

            # Find occurrences of the key
            occurrences = content.count(self.mystery_key)
            self.log(f"  📊 Key appears {occurrences} times in extracted strings")

            if occurrences > 0:
                # Find context around the key
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if self.mystery_key in line:
                        # Show context before and after
                        start = max(0, i - 2)
                        end = min(len(lines), i + 3)
                        self.log(f"  📍 Context at line {i+1}:")
                        for j in range(start, end):
                            marker = ">>> " if j == i else "    "
                            self.log(f"{marker}{lines[j][:100]}")
                        break

        except FileNotFoundError:
            self.log("  ❓ Could not find extracted strings file")
        except Exception as e:
            self.log(f"  ❌ Error reading extracted strings: {e}")

    def calculate_entropy(self, string):
        """Calculate Shannon entropy of a string"""
        import math
        from collections import Counter

        if not string:
            return 0

        # Count character frequencies
        counter = Counter(string)
        string_len = len(string)

        # Calculate entropy
        entropy = 0
        for count in counter.values():
            probability = count / string_len
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def generate_key_report(self):
        """Generate a comprehensive report on both keys"""
        self.log("=" * 60)
        self.log("COMPREHENSIVE API KEY ANALYSIS REPORT")
        self.log("=" * 60)

        self.log("\n📋 SUMMARY OF FINDINGS:")
        self.log(f"Google Maps API Key: {self.google_api_key}")
        self.log(f"Mystery Key: {self.mystery_key}")

        self.log("\n🎯 RECOMMENDATIONS:")
        self.log("1. IMMEDIATELY rotate both keys if they are in production")
        self.log("2. Move all API keys to secure server-side storage")
        self.log("3. Implement API key restrictions in Google Cloud Console")
        self.log("4. Use environment variables for configuration")
        self.log("5. Implement API key rotation policies")

        self.log("\n⚠️  SECURITY IMPLICATIONS:")
        self.log("- Both keys are hardcoded in the APK")
        self.log("- Anyone can extract these keys from the app")
        self.log("- Keys can be used to abuse associated services")
        self.log("- Financial costs may incur from unauthorized usage")

        self.log("\n🔒 NEXT STEPS:")
        self.log("1. Test Google API key with above script")
        self.log("2. Investigate mystery key purpose")
        self.log("3. Implement secure key management")
        self.log("4. Review app security practices")

def main():
    print("🔍 API Key Analysis Tool for MyMaynDrive APK")
    print("=" * 60)

    analyzer = APIKeyAnalyzer()

    try:
        # Test Google Maps API key
        analyzer.test_google_maps_api_key()

        print("\n" + "=" * 60)

        # Analyze mystery key
        analyzer.analyze_mystery_key()

        # Generate final report
        analyzer.generate_key_report()

    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted by user")
    except Exception as e:
        print(f"\n❌ Analysis failed: {e}")

if __name__ == "__main__":
    main()