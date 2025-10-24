console.log('[*] Starting Subscription Bypass Analysis with Timeout');

// Set a timeout to automatically exit after 30 seconds
setTimeout(function() {
    console.log('[!] Analysis timeout reached (30s) - exiting');
    Java.perform(function() {
        console.log('[+] Script completed');
    });
}, 30000);

Java.perform(function() {
    try {
        console.log('[+] Java environment loaded');

        // Quick class enumeration
        var allClasses = Java.enumerateLoadedClassesSync();
        console.log('[+] Total loaded classes: ' + allClasses.length);

        // Find Braintree payment classes (most important for bypass)
        var braintreeClasses = allClasses.filter(function(name) {
            return name.toLowerCase().includes('braintreepayments.api');
        });

        console.log('[+] Found ' + braintreeClasses.length + ' Braintree payment classes:');
        braintreeClasses.forEach(function(className, index) {
            if (index < 10) {
                console.log('    - ' + className);
            }
        });

        // Hook Braintree classes to force payment success
        braintreeClasses.forEach(function(className) {
            try {
                var cls = Java.use(className);
                console.log('[+] Analyzing Braintree class: ' + className);

                // Get all methods
                var methods = cls.class.getDeclaredMethods();
                methods.forEach(function(method) {
                    var methodName = method.getName();

                    // Hook success/complete methods
                    if (methodName.includes('success') ||
                        methodName.includes('complete') ||
                        methodName.includes('isSuccess') ||
                        methodName.includes('succeeded')) {

                        try {
                            var originalMethod = cls[methodName];
                            if (originalMethod) {
                                originalMethod.implementation = function() {
                                    console.log('[BRAINTREE BYPASS] ' + className + '.' + methodName + ' called!');
                                    console.log('[BRAINTREE BYPASS] Arguments: ' + Array.from(arguments));

                                    // Force success return value
                                    if (methodName.includes('is') || methodName.includes('has')) {
                                        return true;
                                    }

                                    var result = originalMethod.apply(this, arguments);
                                    console.log('[BRAINTREE BYPASS] Original result: ' + result);

                                    // Override to ensure success
                                    if (result !== null && typeof result === 'object') {
                                        try {
                                            if (result.success !== undefined) {
                                                result.success = true;
                                            }
                                        } catch (e) {}
                                    }

                                    return result;
                                };
                                console.log('[+] Hooked ' + className + '.' + methodName + ' for success bypass');
                            }
                        } catch (e) {
                            console.log('[-] Could not hook ' + methodName + ': ' + e);
                        }
                    }

                    // Hook payment processing methods
                    if (methodName.includes('payment') ||
                        methodName.includes('process') ||
                        methodName.includes('token') ||
                        methodName.includes('nonce')) {

                        try {
                            var originalMethod = cls[methodName];
                            if (originalMethod) {
                                originalMethod.implementation = function() {
                                    console.log('[BRAINTREE PAYMENT] ' + className + '.' + methodName + ' called!');
                                    console.log('[BRAINTREE PAYMENT] Arguments: ' + Array.from(arguments));

                                    var result = originalMethod.apply(this, arguments);
                                    console.log('[BRAINTREE PAYMENT] Result: ' + result);

                                    return result;
                                };
                                console.log('[+] Hooked ' + className + '.' + methodName + ' for payment monitoring');
                            }
                        } catch (e) {
                            console.log('[-] Could not hook payment method ' + methodName + ': ' + e);
                        }
                    }
                });

            } catch (e) {
                console.log('[-] Could not analyze Braintree class ' + className + ': ' + e);
            }
        });

        // Look for MaynDrive-specific classes
        var mayndriveClasses = allClasses.filter(function(name) {
            return name.includes('fr.mayndrive') ||
                   name.toLowerCase().includes('mayndrive');
        });

        console.log('[+] Found ' + mayndriveClasses.length + ' MaynDrive app classes:');
        mayndriveClasses.slice(0, 20).forEach(function(cls) {
            console.log('    - ' + cls);
        });

        // Hook JSON to catch subscription status changes
        try {
            var JSONObject = Java.use('org.json.JSONObject');

            JSONObject.put.overload('java.lang.String', 'java.lang.Object').implementation = function(key, value) {
                var result = this.put(key, value);

                // Log subscription-related keys
                if (typeof key === 'string' && (
                    key.toLowerCase().includes('subscription') ||
                    key.toLowerCase().includes('premium') ||
                    key.toLowerCase().includes('plan') ||
                    key.toLowerCase().includes('status') ||
                    key.toLowerCase().includes('user') ||
                    key.toLowerCase().includes('active')
                )) {
                    console.log('[JSON SUBSCRIPTION] Key: ' + key + ', Value: ' + value);

                    // Try to modify subscription status
                    if (key.toLowerCase().includes('status') && value !== 'active') {
                        console.log('[JSON BYPASS] Changing status from "' + value + '" to "active"');
                        try {
                            this.put(key, 'active');
                        } catch (e) {
                            console.log('[-] Could not modify status: ' + e);
                        }
                    }
                }

                return result;
            };

            console.log('[+] Hooked JSONObject.put() for subscription manipulation');
        } catch (e) {
            console.log('[-] Could not hook JSON: ' + e);
        }

        // Try to find and hook network calls
        try {
            var HttpURLConnection = Java.use('java.net.HttpURLConnection');

            HttpURLConnection.getResponseCode.implementation = function() {
                var result = this.getResponseCode();
                var url = this.getURL().toString();

                if (url.includes('api.knotcity.io') || url.includes('subscription') || url.includes('payment')) {
                    console.log('[HTTP BYPASS] URL: ' + url + ', Response Code: ' + result);

                    // Force success response codes for payment/subscription APIs
                    if (result >= 400 && (url.includes('payment') || url.includes('subscription'))) {
                        console.log('[HTTP BYPASS] Changing error code ' + result + ' to 200 (success)');
                        return 200;
                    }
                }

                return result;
            };

            console.log('[+] Hooked HttpURLConnection.getResponseCode()');
        } catch (e) {
            console.log('[-] Could not hook HTTP: ' + e);
        }

        console.log('[+] Bypass hooks installed. Monitoring for payment/subscription activity...');
        console.log('[+] Try making a payment or accessing subscription features now!');
        console.log('[+] Script will automatically exit in 30 seconds');

    } catch (e) {
        console.log('[-] Error: ' + e);
        console.log('[-] Stack: ' + e.stack);
    }
});

console.log('[*] Subscription bypass script with timeout loaded');