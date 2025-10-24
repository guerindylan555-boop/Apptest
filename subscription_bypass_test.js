console.log('[*] Starting subscription bypass test...');

Java.perform(function() {
    try {
        console.log('[+] Java environment loaded');

        // Let's search for the specific UserSubscriptionModel class we found in decompilation
        console.log('[+] Looking for UserSubscriptionModel class...');

        try {
            var UserSubscriptionModel = Java.use('p610s4.C10458m');
            console.log('[+] Found UserSubscriptionModel: p610s4.C10458m');

            // Hook the toString method first to see if it's being called
            UserSubscriptionModel.toString.implementation = function() {
                var result = this.toString();
                console.log('[+] UserSubscriptionModel.toString() called:');
                console.log('    Result: ' + result);
                return result;
            };

            console.log('[+] UserSubscriptionModel.toString() hooked');

            // Also hook the constructor if it exists
            try {
                UserSubscriptionModel.$init.implementation = function() {
                    console.log('[+] UserSubscriptionModel constructor called');
                    var result = this.$init.apply(this, arguments);
                    console.log('[+] Constructor arguments: ' + Array.from(arguments));
                    return result;
                };
                console.log('[+] UserSubscriptionModel constructor hooked');
            } catch (e) {
                console.log('[-] Could not hook constructor: ' + e);
            }

        } catch (e) {
            console.log('[-] Could not find UserSubscriptionModel: ' + e);

            // Try to find similar classes
            try {
                var classNames = Java.enumerateLoadedClassesSync();
                var userClasses = classNames.filter(function(name) {
                    return name.includes('C10458m') ||
                           name.includes('UserSubscription') ||
                           name.toLowerCase().includes('subscription');
                });

                console.log('[+] Found ' + userClasses.length + ' subscription-related classes:');
                userClasses.slice(0, 20).forEach(function(cls) {
                    console.log('    - ' + cls);
                });

                if (userClasses.length > 20) {
                    console.log('    ... and ' + (userClasses.length - 20) + ' more');
                }
            } catch (enumError) {
                console.log('[-] Could not enumerate classes: ' + enumError);
            }
        }

        // Let's also try to find payment-related classes
        try {
            console.log('[+] Looking for payment-related classes...');
            var classNames = Java.enumerateLoadedClassesSync();
            var paymentClasses = classNames.filter(function(name) {
                return name.toLowerCase().includes('payment') ||
                       name.toLowerCase().includes('price') ||
                       name.toLowerCase().includes('stripe');
            });

            console.log('[+] Found ' + paymentClasses.length + ' payment-related classes:');
            paymentClasses.slice(0, 15).forEach(function(cls) {
                console.log('    - ' + cls);
            });

            if (paymentClasses.length > 15) {
                console.log('    ... and ' + (paymentClasses.length - 15) + ' more');
            }
        } catch (e) {
            console.log('[-] Could not search payment classes: ' + e);
        }

    } catch (e) {
        console.log('[-] Error: ' + e);
        console.log('[-] Stack: ' + e.stack);
    }
});

console.log('[*] Initial script loaded');