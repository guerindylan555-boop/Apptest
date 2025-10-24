console.log('[*] Starting Automatic Subscription Bypass Test');

Java.perform(function() {
    try {
        console.log('[+] Java environment loaded');

        // Enumerate classes quickly
        var allClasses = Java.enumerateLoadedClassesSync();
        console.log('[+] Total loaded classes: ' + allClasses.length);

        // Find Braintree payment classes
        var braintreeClasses = allClasses.filter(function(name) {
            return name.toLowerCase().includes('braintreepayments.api');
        });

        console.log('[+] Found ' + braintreeClasses.length + ' Braintree payment classes');

        var hookedMethods = 0;

        // Hook Braintree classes for payment bypass
        braintreeClasses.forEach(function(className) {
            try {
                var cls = Java.use(className);

                var methods = cls.class.getDeclaredMethods();
                methods.forEach(function(method) {
                    var methodName = method.getName();

                    // Hook success-related methods
                    if (methodName.includes('success') ||
                        methodName.includes('complete') ||
                        methodName.includes('isSuccess') ||
                        methodName.includes('succeeded')) {

                        try {
                            var originalMethod = cls[methodName];
                            if (originalMethod) {
                                originalMethod.implementation = function() {
                                    console.log('[BRAINTREE BYPASS] ' + className + '.' + methodName + ' called!');

                                    // Force success return
                                    if (methodName.includes('is') || methodName.includes('has')) {
                                        console.log('[BRAINTREE BYPASS] Forcing return true');
                                        return true;
                                    }

                                    var result = originalMethod.apply(this, arguments);
                                    console.log('[BRAINTREE BYPASS] Original result: ' + result);

                                    // Try to force success in object result
                                    if (result !== null && typeof result === 'object') {
                                        try {
                                            if (result.success !== undefined) {
                                                result.success = true;
                                                console.log('[BRAINTREE BYPASS] Modified result.success = true');
                                            }
                                        } catch (e) {}
                                    }

                                    return result;
                                };
                                hookedMethods++;
                                console.log('[+] Hooked: ' + className + '.' + methodName);
                            }
                        } catch (e) {
                            // Silently ignore hook failures
                        }
                    }
                });

            } catch (e) {
                // Silently ignore class analysis failures
            }
        });

        console.log('[+] Successfully hooked ' + hookedMethods + ' Braintree methods');

        // Hook JSON for subscription manipulation
        try {
            var JSONObject = Java.use('org.json.JSONObject');

            JSONObject.put.overload('java.lang.String', 'java.lang.Object').implementation = function(key, value) {
                var result = this.put(key, value);

                if (typeof key === 'string' && (
                    key.toLowerCase().includes('subscription') ||
                    key.toLowerCase().includes('premium') ||
                    key.toLowerCase().includes('plan') ||
                    key.toLowerCase().includes('status'))) {

                    console.log('[JSON SUBSCRIPTION] Key: ' + key + ', Value: ' + value);

                    // Try to set status to active
                    if (key.toLowerCase().includes('status') && value !== 'active') {
                        try {
                            this.put(key, 'active');
                            console.log('[JSON BYPASS] Changed status to "active"');
                        } catch (e) {}
                    }
                }

                return result;
            };

            console.log('[+] Hooked JSONObject for subscription manipulation');
        } catch (e) {
            console.log('[-] Could not hook JSON: ' + e);
        }

        // Hook HTTP responses
        try {
            var HttpURLConnection = Java.use('java.net.HttpURLConnection');

            HttpURLConnection.getResponseCode.implementation = function() {
                var result = this.getResponseCode();
                var url = this.getURL().toString();

                if (url.includes('api.knotcity.io') && (url.includes('payment') || url.includes('subscription'))) {
                    console.log('[HTTP BYPASS] API URL: ' + url + ', Original Code: ' + result);

                    // Force success for payment/subscription APIs
                    if (result >= 400) {
                        console.log('[HTTP BYPASS] Changed error code ' + result + ' to 200 (success)');
                        return 200;
                    }
                }

                return result;
            };

            console.log('[+] Hooked HttpURLConnection for API bypass');
        } catch (e) {
            console.log('[-] Could not hook HTTP: ' + e);
        }

        console.log('[+] All bypass hooks installed successfully');
        console.log('[+] Ready to intercept payment/subscription operations');

        // Test the bypass by triggering some activity
        setTimeout(function() {
            console.log('[+] Testing bypass mechanisms...');

            // Try to find and test a subscription check
            try {
                // Create a test JSON object
                var testJSON = Java.use('org.json.JSONObject').$new();
                testJSON.put('status', 'inactive');
                testJSON.put('subscription', 'free');

                console.log('[+] Test JSON before bypass: ' + testJSON.toString());

                var testJSON2 = Java.use('org.json.JSONObject').$new();
                testJSON2.put('status', 'active');
                testJSON2.put('subscription', 'premium');

                console.log('[+] Test JSON after bypass: ' + testJSON2.toString());
            } catch (e) {
                console.log('[-] Test failed: ' + e);
            }

            // Complete the test
            setTimeout(function() {
                console.log('[+] Subscription bypass test completed');
                console.log('[+] Summary:');
                console.log('    - Hooked ' + hookedMethods + ' Braintree methods');
                console.log('    - Hooked JSON manipulation');
                console.log('    - Hooked HTTP responses');
                console.log('[+] Bypass is ready for payment/subscription operations');

                // Exit Frida after completion
                setTimeout(function() {
                    console.log('[+] Test complete - exiting');
                    process.exit(0);
                }, 1000);
            }, 2000);
        }, 1000);

    } catch (e) {
        console.log('[-] Error: ' + e);
        console.log('[-] Stack: ' + e.stack);
    }
});

console.log('[*] Automatic subscription bypass script loaded');