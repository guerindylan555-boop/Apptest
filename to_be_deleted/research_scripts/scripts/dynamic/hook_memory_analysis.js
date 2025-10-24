// MyMaynDrive APK - Memory Analysis Hook
// This script scans memory for secrets, API keys, and sensitive data

console.log("[*] MyMaynDrive Memory Analysis Hook Started");

Java.perform(function() {
    console.log("[+] Java environment initialized for memory analysis");

    // Google Maps API Key to search for
    var GOOGLE_API_KEY = "AIzaSyBmzPzugRjdJT83phq1mgu4ulzo20wQfeY";

    // Hook string creation to catch API keys in memory
    try {
        var String = Java.use("java.lang.String");

        // Hook String constructor from byte array
        String.$init.overload('[B').implementation = function(bytes) {
            var result = String.$init.overload('[B').call(this, bytes);

            // Check for API key in string creation
            if (result && result.includes(GOOGLE_API_KEY)) {
                console.log("[!] GOOGLE API KEY FOUND IN MEMORY:");
                console.log("    Context: String created from byte array");
                console.log("    Length: " + result.length);
                console.log("    First 50 chars: " + result.substring(0, 50));
                console.log("    Timestamp: " + new Date().toISOString());

                // Get stack trace
                var stackTrace = Java.use("java.lang.Thread").currentThread().getStackTrace();
                console.log("    Stack trace (top 5):");
                for (var i = 0; i < Math.min(stackTrace.length, 5); i++) {
                    console.log("      " + stackTrace[i].toString());
                }
            }

            // Check for other sensitive patterns
            if (result && result.length > 20) {
                var sensitivePatterns = [
                    /sk_[a-zA-Z0-9]{24,}/,  // Stripe secret keys
                    /pk_[a-zA-Z0-9]{24,}/,  // Stripe publishable keys
                    /ghp_[a-zA-Z0-9]{36}/,  // GitHub personal access tokens
                    /glpat-[a-zA-Z0-9_-]{20}/, // GitLab personal access tokens
                    /[a-zA-Z0-9_-]{32}==/,  // Base64 encoded tokens
                    /token.*[a-zA-Z0-9_-]{20,}/, // Generic tokens
                    /password.*[a-zA-Z0-9]{8,}/, // Passwords
                    /secret.*[a-zA-Z0-9]{16,}/, // Secrets
                ];

                for (var j = 0; j < sensitivePatterns.length; j++) {
                    if (sensitivePatterns[j].test(result)) {
                        console.log("[!] SENSITIVE DATA PATTERN IN MEMORY:");
                        console.log("    Pattern: " + sensitivePatterns[j]);
                        console.log("    Length: " + result.length);
                        console.log("    Preview: " + result.substring(0, 50) + "...");
                        console.log("    Timestamp: " + new Date().toISOString());
                        break;
                    }
                }
            }

            return result;
        };

        // Hook String constructor from byte array with charset
        String.$init.overload('[B', 'java.nio.charset.Charset').implementation = function(bytes, charset) {
            var result = String.$init.overload('[B', 'java.nio.charset.Charset').call(this, bytes, charset);

            if (result && result.includes(GOOGLE_API_KEY)) {
                console.log("[!] GOOGLE API KEY FOUND IN MEMORY (with charset):");
                console.log("    Charset: " + charset.toString());
                console.log("    Length: " + result.length);
                console.log("    Timestamp: " + new Date().toISOString());
            }

            return result;
        };

        console.log("[+] String constructors hooked for memory analysis");
    } catch (e) {
        console.log("[-] Failed to hook String constructors: " + e);
    }

    // Hook StringBuilder for potential secret concatenation
    try {
        var StringBuilder = Java.use("java.lang.StringBuilder");
        StringBuilder.toString.implementation = function() {
            var result = this.toString();

            if (result && result.includes(GOOGLE_API_KEY)) {
                console.log("[!] GOOGLE API KEY IN STRINGBUILDER:");
                console.log("    Length: " + result.length);
                console.log("    Timestamp: " + new Date().toISOString());
            }

            return result;
        };
        console.log("[+] StringBuilder hooked for memory analysis");
    } catch (e) {
        console.log("[-] Failed to hook StringBuilder: " + e);
    }

    // Hook ByteBuffer operations
    try {
        var ByteBuffer = Java.use("java.nio.ByteBuffer");
        var ByteBufferHelper = Java.use("java.nio.HeapByteBuffer");

        ByteBufferHelper.getString.overload('java.nio.charset.Charset').implementation = function(charset) {
            var result = this.getString(charset);

            if (result && result.includes(GOOGLE_API_KEY)) {
                console.log("[!] GOOGLE API KEY IN BYTEBUFFER:");
                console.log("    Charset: " + charset.toString());
                console.log("    Length: " + result.length);
                console.log("    Timestamp: " + new Date().toISOString());
            }

            return result;
        };
        console.log("[+] ByteBuffer hooked for memory analysis");
    } catch (e) {
        console.log("[-] Failed to hook ByteBuffer: " + e);
    }

    // Hook JSON parsing for sensitive data
    try {
        var JSONObject = Java.use("org.json.JSONObject");
        JSONObject.getString.implementation = function(key) {
            var result = this.getString(key);

            if (result && result.includes(GOOGLE_API_KEY)) {
                console.log("[!] GOOGLE API KEY IN JSON:");
                console.log("    Key: " + key);
                console.log("    Timestamp: " + new Date().toISOString());
            }

            // Check for other sensitive keys
            var sensitiveKeyPatterns = [
                'api_key', 'secret', 'token', 'password', 'private_key',
                'auth', 'credential', 'certificate', 'signature'
            ];

            for (var i = 0; i < sensitiveKeyPatterns.length; i++) {
                if (key.toLowerCase().includes(sensitiveKeyPatterns[i]) && result && result.length > 10) {
                    console.log("[!] SENSITIVE JSON DATA:");
                    console.log("    Key: " + key);
                    console.log("    Value length: " + result.length);
                    console.log("    Type: " + sensitiveKeyPatterns[i]);
                    console.log("    Timestamp: " + new Date().toISOString());
                    break;
                }
            }

            return result;
        };
        console.log("[+] JSONObject hooked for memory analysis");
    } catch (e) {
        console.log("[-] JSONObject not available: " + e);
    }

    // Hook Base64 decoding operations
    try {
        var Base64 = Java.use("android.util.Base64");
        Base64.decode.overload('java.lang.String', 'int').implementation = function(str, flags) {
            console.log("[!] BASE64 DECODE OPERATION:");
            console.log("    Input length: " + str.length);
            console.log("    Flags: " + flags);
            console.log("    Preview: " + str.substring(0, Math.min(50, str.length)));

            var result = Base64.decode.overload('java.lang.String', 'int').call(this, str, flags);

            // Check if decoded data contains our API key
            try {
                var decodedStr = Java.use("java.lang.String").$new(result);
                if (decodedStr.includes(GOOGLE_API_KEY)) {
                    console.log("    🚨 DECODED DATA CONTAINS GOOGLE API KEY!");
                }
            } catch (e) {
                // Not a valid string, ignore
            }

            console.log("    Timestamp: " + new Date().toISOString());

            return result;
        };
        console.log("[+] Base64 operations hooked");
    } catch (e) {
        console.log("[-] Failed to hook Base64: " + e);
    }

    // Hook memory allocation for large objects
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.gc.implementation = function() {
            console.log("[!] GARBAGE COLLECTION REQUESTED:");
            console.log("    Timestamp: " + new Date().toISOString());
            return this.gc();
        };

        Runtime.freeMemory.implementation = function() {
            var freeMemory = this.freeMemory();
            var totalMemory = this.totalMemory();
            var maxMemory = this.maxMemory();

            console.log("[!] MEMORY STATUS:");
            console.log("    Free: " + freeMemory + " bytes");
            console.log("    Total: " + totalMemory + " bytes");
            console.log("    Max: " + maxMemory + " bytes");
            console.log("    Usage: " + Math.round((totalMemory - freeMemory) / totalMemory * 100) + "%");

            return freeMemory;
        };
        console.log("[+] Runtime memory operations hooked");
    } catch (e) {
        console.log("[-] Failed to hook Runtime: " + e);
    }

    // Hook application lifecycle for memory snapshots
    try {
        var Activity = Java.use("android.app.Activity");
        Activity.onResume.implementation = function() {
            console.log("[!] ACTIVITY RESUMED - MEMORY SNAPSHOT:");
            console.log("    Activity: " + this.getClass().getSimpleName());

            // Log memory usage
            try {
                var runtime = Java.use("java.lang.Runtime").getRuntime();
                var freeMemory = runtime.freeMemory();
                var totalMemory = runtime.totalMemory();
                console.log("    Memory usage: " + Math.round((totalMemory - freeMemory) / totalMemory * 100) + "%");
            } catch (e) {
                console.log("    Could not determine memory usage");
            }

            console.log("    Timestamp: " + new Date().toISOString());

            return this.onResume();
        };
        console.log("[+] Activity lifecycle hooked for memory snapshots");
    } catch (e) {
        console.log("[-] Failed to hook Activity: " + e);
    }

    // Hook Firebase operations for potential secrets
    try {
        var FirebaseApp = Java.use("com.google.firebase.FirebaseApp");
        FirebaseApp.getInstance.overload('java.lang.String').implementation = function(name) {
            console.log("[!] FIREBASE INSTANCE ACCESSED:");
            console.log("    App name: " + name);
            console.log("    Timestamp: " + new Date().toISOString());

            var result = this.getInstance(name);

            try {
                var options = result.getOptions();
                console.log("    Project ID: " + options.getProjectId());
                console.log("    App ID: " + options.getApplicationId());
                console.log("    API Key: " + (options.getApiKey() ? "PRESENT" : "NOT_FOUND"));
            } catch (e) {
                console.log("    Could not access Firebase options");
            }

            return result;
        };
        console.log("[+] Firebase operations hooked");
    } catch (e) {
        console.log("[-] Firebase not available: " + e);
    }

    console.log("[*] Memory Analysis Hook Setup Complete");
    console.log("[*] Monitoring memory for API keys, secrets, and sensitive data");
    console.log("[*] Target API Key: " + GOOGLE_API_KEY);
});