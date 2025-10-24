console.log('[*] Comprehensive MaynDrive Subscription Bypass Analysis');

Java.perform(function() {
    try {
        console.log('[+] Java environment loaded');

        // First, let's enumerate ALL loaded classes to understand the app structure
        var allClasses = Java.enumerateLoadedClassesSync();
        console.log('[+] Total loaded classes: ' + allClasses.length);

        // Look for MaynDrive-specific classes by analyzing patterns
        var mayndriveClasses = allClasses.filter(function(name) {
            return name.includes('fr.mayndrive') ||
                   name.includes('mayndrive') ||
                   name.toLowerCase().includes('subscription') ||
                   name.toLowerCase().includes('payment') ||
                   name.toLowerCase().includes('user') ||
                   name.toLowerCase().includes('premium') ||
                   name.toLowerCase().includes('plan') ||
                   name.toLowerCase().includes('ride');
        });

        console.log('[+] Found ' + mayndriveClasses.length + ' MaynDrive-related classes:');
        mayndriveClasses.slice(0, 20).forEach(function(cls) {
            console.log('    - ' + cls);
        });

        if (mayndriveClasses.length > 20) {
            console.log('    ... and ' + (mayndriveClasses.length - 20) + ' more');
        }

        // Look for any classes that might contain subscription or payment logic
        var potentialClasses = allClasses.filter(function(name) {
            // Skip Android framework classes
            if (name.startsWith('android.') || name.startsWith('com.android.') ||
                name.startsWith('java.') || name.startsWith('javax.') ||
                name.startsWith('kotlin.') || name.startsWith('kotlinx.')) {
                return false;
            }

            // Look for suspicious patterns
            var suspicious = [
                'user', 'subscription', 'payment', 'stripe', 'braintree',
                'credit', 'balance', 'wallet', 'premium', 'pro', 'paid',
                'plan', 'ride', 'rental', 'unlock', 'auth', 'token'
            ];

            return suspicious.some(function(pattern) {
                return name.toLowerCase().includes(pattern);
            });
        });

        console.log('[+] Found ' + potentialClasses.length + ' potentially relevant classes:');
        potentialClasses.slice(0, 30).forEach(function(cls) {
            console.log('    - ' + cls);
        });

        if (potentialClasses.length > 30) {
            console.log('    ... and ' + (potentialClasses.length - 30) + ' more');
        }

        // Try to hook the Braintree payment classes we found
        try {
            var braintreeClasses = allClasses.filter(function(name) {
                return name.toLowerCase().includes('braintreepayments.api');
            });

            console.log('[+] Found ' + braintreeClasses.length + ' Braintree classes');

            braintreeClasses.forEach(function(className) {
                try {
                    var cls = Java.use(className);
                    console.log('[+] Analyzing Braintree class: ' + className);

                    // Hook key methods
                    var methods = cls.class.getDeclaredMethods();
                    methods.forEach(function(method) {
                        var methodName = method.getName();
                        if (methodName.includes('success') ||
                            methodName.includes('complete') ||
                            methodName.includes('payment') ||
                            methodName.includes('token') ||
                            methodName.includes('nonce')) {

                            try {
                                Java.perform(function() {
                                    cls[methodName].implementation = function() {
                                        console.log('[BRAINTREE] ' + className + '.' + methodName + ' called with args: ' + Array.from(arguments));
                                        var result = this[methodName].apply(this, arguments);
                                        console.log('[BRAINTREE] ' + className + '.' + methodName + ' returned: ' + result);

                                        // Try to force payment success
                                        if (methodName.includes('success') || methodName.includes('complete')) {
                                            console.log('[BRAINTREE] Forcing success response!');
                                            if (typeof result === 'boolean') {
                                                return true;
                                            }
                                        }

                                        return result;
                                    };
                                });
                                console.log('[+] Hooked ' + className + '.' + methodName);
                            } catch (e) {
                                console.log('[-] Could not hook ' + methodName + ': ' + e);
                            }
                        }
                    });
                } catch (e) {
                    console.log('[-] Could not analyze Braintree class ' + className + ': ' + e);
                }
            });

        } catch (e) {
            console.log('[-] Error with Braintree analysis: ' + e);
        }

        // Look for network/API classes that might handle subscription status
        try {
            var networkClasses = allClasses.filter(function(name) {
                return name.toLowerCase().includes('network') ||
                       name.toLowerCase().includes('api') ||
                       name.toLowerCase().includes('http') ||
                       name.toLowerCase().includes('okhttp') ||
                       name.toLowerCase().includes('retrofit');
            });

            console.log('[+] Found ' + networkClasses.length + ' network-related classes:');
            networkClasses.slice(0, 10).forEach(function(cls) {
                console.log('    - ' + cls);
            });
        } catch (e) {
            console.log('[-] Error finding network classes: ' + e);
        }

        // Try to find classes related to user data or account status
        try {
            var userClasses = allClasses.filter(function(name) {
                return name.toLowerCase().includes('user') ||
                       name.toLowerCase().includes('account') ||
                       name.toLowerCase().includes('profile') ||
                       name.toLowerCase().includes('status');
            });

            console.log('[+] Found ' + userClasses.length + ' user/account classes:');
            userClasses.slice(0, 15).forEach(function(cls) {
                console.log('    - ' + cls);
            });
        } catch (e) {
            console.log('[-] Error finding user classes: ' + e);
        }

        // Try to hook JSON parsing to catch subscription data
        try {
            var JSONObject = Java.use('org.json.JSONObject');
            var JSONArray = Java.use('org.json.JSONArray');

            console.log('[+] Hooking JSON parsing to capture subscription data');

            JSONObject.put.overload('java.lang.String', 'java.lang.Object').implementation = function(key, value) {
                var result = this.put(key, value);

                if (typeof key === 'string' && (
                    key.toLowerCase().includes('subscription') ||
                    key.toLowerCase().includes('premium') ||
                    key.toLowerCase().includes('plan') ||
                    key.toLowerCase().includes('status') ||
                    key.toLowerCase().includes('user')
                )) {
                    console.log('[JSON] JSONObject.put() called with key: ' + key + ', value: ' + value);
                }

                return result;
            };

        } catch (e) {
            console.log('[-] Could not hook JSON parsing: ' + e);
        }

        console.log('[+] Comprehensive analysis complete. Script is monitoring for payment/subscription activity...');

    } catch (e) {
        console.log('[-] Error: ' + e);
        console.log('[-] Stack: ' + e.stack);
    }
});

console.log('[*] Comprehensive bypass script loaded');