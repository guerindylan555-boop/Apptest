// MyMaynDrive APK - API Key Monitoring Hook
// This script monitors runtime usage of API keys discovered during static analysis

console.log("[*] MyMaynDrive API Key Monitoring Hook Started");

Java.perform(function() {
    console.log("[+] Java environment initialized");

    // Monitor Google Maps API Key: AIzaSyBmzPzugRjdJT83phq1mgu4ulzo20wQfeY
    var GOOGLE_API_KEY = "AIzaSyBmzPzugRjdJT83phq1mgu4ulzo20wQfeY";

    // Hook URL construction for network requests
    try {
        var URL = Java.use("java.net.URL");
        URL.$init.overload('java.lang.String').implementation = function(url) {
            if (url.includes(GOOGLE_API_KEY)) {
                console.log("[!] GOOGLE MAPS API KEY IN USE:");
                console.log("    URL: " + url);
                console.log("    Timestamp: " + new Date().toISOString());

                // Log the API endpoint being called
                if (url.includes("maps/api")) {
                    console.log("    Service: Google Maps API");
                    if (url.includes("geocode")) {
                        console.log("    Endpoint: Geocoding");
                    } else if (url.includes("directions")) {
                        console.log("    Endpoint: Directions");
                    } else if (url.includes("staticmap")) {
                        console.log("    Endpoint: Static Maps");
                    } else if (url.includes("places")) {
                        console.log("    Endpoint: Places API");
                    }
                }
            }
            return this.$init(url);
        };
        console.log("[+] URL constructor hooked for API key monitoring");
    } catch (e) {
        console.log("[-] Failed to hook URL constructor: " + e);
    }

    // Hook HttpURLConnection for monitoring request headers
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.setRequestProperty.implementation = function(key, value) {
            if (value && value.includes(GOOGLE_API_KEY)) {
                console.log("[!] API KEY IN REQUEST HEADER:");
                console.log("    Header: " + key);
                console.log("    Value: " + value.substring(0, 50) + "...");
                console.log("    Timestamp: " + new Date().toISOString());
            }
            return this.setRequestProperty(key, value);
        };
        console.log("[+] HttpURLConnection hooked for header monitoring");
    } catch (e) {
        console.log("[-] Failed to hook HttpURLConnection: " + e);
    }

    // Hook OkHttp if used (common in modern Android apps)
    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        OkHttpClient.newCall.implementation = function(request) {
            var url = request.url().toString();
            if (url.includes(GOOGLE_API_KEY)) {
                console.log("[!] OKHTTP REQUEST WITH API KEY:");
                console.log("    URL: " + url);
                console.log("    Method: " + request.method());
                console.log("    Headers: " + request.headers().toString());
                console.log("    Timestamp: " + new Date().toISOString());
            }
            return this.newCall(request);
        };
        console.log("[+] OkHttp client hooked for API monitoring");
    } catch (e) {
        console.log("[-] OkHttp not available or already hooked: " + e);
    }

    // Hook Google Maps specific classes if available
    try {
        var GoogleMap = Java.use("com.google.android.gms.maps.GoogleMap");
        GoogleMap.setMapType.implementation = function(type) {
            console.log("[!] GoogleMap setMapType called: " + type);
            console.log("    Timestamp: " + new Date().toISOString());
            return this.setMapType(type);
        };
        console.log("[+] GoogleMap class hooked");
    } catch (e) {
        console.log("[-] Google Maps classes not available: " + e);
    }

    // Hook string operations that might reveal API keys in memory
    try {
        var String = Java.use("java.lang.String");
        String.$init.overload('[B', 'java.nio.charset.Charset').implementation = function(bytes, charset) {
            var result = String.$init.overload('[B', 'java.nio.charset.Charset').call(this, bytes, charset);

            // Check if this string contains our API key
            if (result && result.includes(GOOGLE_API_KEY)) {
                console.log("[!] API KEY DETECTED IN MEMORY:");
                console.log("    Context: String creation from byte array");
                console.log("    Length: " + result.length);
                console.log("    Timestamp: " + new Date().toISOString());

                // Get stack trace to understand where this is happening
                var stackTrace = Java.use("java.lang.Thread").currentThread().getStackTrace();
                console.log("    Stack trace:");
                for (var i = 0; i < Math.min(stackTrace.length, 5); i++) {
                    console.log("      " + stackTrace[i].toString());
                }
            }

            return result;
        };
        console.log("[+] String constructor hooked for memory monitoring");
    } catch (e) {
        console.log("[-] Failed to hook String constructor: " + e);
    }

    // Hook Firebase usage to monitor Crashlytics key
    try {
        var FirebaseCrashlytics = Java.use("com.google.firebase.crashlytics.FirebaseCrashlytics");
        FirebaseCrashlytics.recordException.implementation = function(exception) {
            console.log("[!] Firebase Crashlytics Exception Recorded:");
            console.log("    Exception: " + exception.toString());
            console.log("    Timestamp: " + new Date().toISOString());
            return this.recordException(exception);
        };
        console.log("[+] Firebase Crashlytics hooked");
    } catch (e) {
        console.log("[-] Firebase Crashlytics not available: " + e);
    }

    // Monitor SharedPreferences for API key storage
    try {
        var SharedPreferences = Java.use("android.content.SharedPreferences$Editor");
        SharedPreferences.putString.implementation = function(key, value) {
            if (value && (value.includes(GOOGLE_API_KEY) || key.toLowerCase().includes("api_key"))) {
                console.log("[!] API KEY STORED IN SHARED PREFERENCES:");
                console.log("    Key: " + key);
                console.log("    Value: " + (value.includes(GOOGLE_API_KEY) ? "GOOGLE_MAPS_API_KEY" : value.substring(0, 20) + "..."));
                console.log("    Timestamp: " + new Date().toISOString());
            }
            return this.putString(key, value);
        };
        console.log("[+] SharedPreferences hooked for key storage monitoring");
    } catch (e) {
        console.log("[-] Failed to hook SharedPreferences: " + e);
    }

    console.log("[*] API Key Monitoring Hook Setup Complete");
    console.log("[*] Monitoring for Google Maps API key: " + GOOGLE_API_KEY);
});