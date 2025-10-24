#!/bin/bash

# Google Maps API Key Testing Script
# This script helps you test the validity and restrictions of the Google Maps API key

API_KEY="AIzaSyBmzPzugRjdJT83phq1mgu4ulzo20wQfeY"

echo "🔍 Google Maps API Key Testing Script"
echo "======================================"
echo "Testing API key: $API_KEY"
echo ""

# Function to test an API endpoint
test_api() {
    local name=$1
    local url=$2
    local params=$3

    echo "Testing $name..."
    response=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$url?$params&key=$API_KEY")
    http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
    body=$(echo "$response" | sed '/HTTP_CODE:/d')

    if [ "$http_code" = "200" ]; then
        echo "✅ SUCCESS: $name (HTTP $http_code)"
        if [ -n "$body" ]; then
            # Show a small preview of the response
            echo "   Response preview: $(echo "$body" | head -c 100)..."
        fi
    elif [ "$http_code" = "403" ]; then
        echo "❌ FORBIDDEN: $name (HTTP $http_code) - Key may be restricted"
    elif [ "$http_code" = "401" ]; then
        echo "❌ UNAUTHORIZED: $name (HTTP $http_code) - Invalid key"
    else
        echo "❌ ERROR: $name (HTTP $http_code)"
        if echo "$body" | grep -q "REQUEST_DENIED"; then
            echo "   Reason: API not authorized for this key"
        elif echo "$body" | grep -q "INVALID_REQUEST"; then
            echo "   Reason: Invalid request parameters"
        fi
    fi
    echo ""
}

# Test 1: Geocoding API
echo "1️⃣  Geocoding API Test"
echo "---------------------"
test_api "Geocoding (Address → Coordinates)" \
    "https://maps.googleapis.com/maps/api/geocode/json" \
    "address=1600+Amphitheatre+Parkway,+Mountain+View,+CA"

# Test 2: Reverse Geocoding
echo "2️⃣  Reverse Geocoding Test"
echo "--------------------------"
test_api "Reverse Geocoding (Coordinates → Address)" \
    "https://maps.googleapis.com/maps/api/geocode/json" \
    "latlng=37.7749,-122.4194"

# Test 3: Static Maps API
echo "3️⃣  Static Maps API Test"
echo "-----------------------"
test_api "Static Map Generation" \
    "https://maps.googleapis.com/maps/api/staticmap" \
    "center=New+York,NY&zoom=13&size=600x300&maptype=roadmap"

# Test 4: Places API (Nearby Search)
echo "4️⃣  Places API Test"
echo "-------------------"
test_api "Places Nearby Search" \
    "https://maps.googleapis.com/maps/api/place/nearbysearch/json" \
    "location=37.7749,-122.4194&radius=500&type=restaurant"

# Test 5: Elevation API
echo "5️⃣  Elevation API Test"
echo "----------------------"
test_api "Elevation Lookup" \
    "https://maps.googleapis.com/maps/api/elevation/json" \
    "locations=39.7391536,-104.9902501"

# Test 6: Directions API
echo "6️⃣  Directions API Test"
echo "-----------------------"
test_api "Route Directions" \
    "https://maps.googleapis.com/maps/api/directions/json" \
    "origin=New+York,NY&destination=Los+Angeles,CA"

# Test 7: Time Zone API
echo "7️⃣  Time Zone API Test"
echo "-----------------------"
test_api "Time Zone Lookup" \
    "https://maps.googleapis.com/maps/api/timezone/json" \
    "location=39.6034810,-119.6822510&timestamp=1331161200"

# Test 8: Distance Matrix API
echo "8️⃣  Distance Matrix API Test"
echo "----------------------------"
test_api "Distance Matrix" \
    "https://maps.googleapis.com/maps/api/distancematrix/json" \
    "origins=New+York,NY&destinations=Los+Angeles,CA"

echo "📊 SUMMARY"
echo "========="
echo ""
echo "Key Status Analysis:"
echo "- ✅ Working APIs = APIs that return HTTP 200"
echo "- ⚠️  Restricted APIs = APIs that return HTTP 403 (key is valid but restricted)"
echo "- ❌ Blocked APIs = APIs that return REQUEST_DENIED (not enabled for this project)"
echo ""
echo "Next Steps:"
echo "1. If you see 'FORBIDDEN' → Key is valid but has restrictions"
echo "2. If you see 'REQUEST_DENIED' → APIs not enabled in Google Cloud Console"
echo "3. If you see 'UNAUTHORIZED' → Key is invalid or revoked"
echo ""
echo "🔧 To fix issues:"
echo "- Go to Google Cloud Console → APIs & Services → Credentials"
echo "- Edit the API key to add proper restrictions"
echo "- Enable required APIs in your project"
echo "- Set up billing if required"

echo ""
echo "🚨 SECURITY REMINDER:"
echo "This API key is hardcoded in the APK and should be rotated!"
echo "Move to secure server-side storage and implement key rotation."