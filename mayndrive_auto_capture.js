/*
 * MaynDrive Automatic API Capture
 * Dynamically hooks all methods in the Vehicle API interface
 */

Java.perform(function() {
    console.log("[*] Auto MaynDrive Capture Starting...");
    console.log("[*] Dynamically hooking all API methods");

    function emitDivider() {
        console.log("\n" + "=".repeat(80));
    }

    function emitApiLog(tag, methodName, args) {
        emitDivider();
        console.log("*** " + tag + " API CALL INTERCEPTED ***");
        console.log("=".repeat(80));
        console.log("[Method] " + methodName);
        console.log("[Timestamp] " + new Date().toISOString());

        try {
            for (var i = 0; i < args.length; i++) {
                if (args[i] !== null && args[i] !== undefined) {
                    var argStr = args[i].toString();
                    console.log("[Arg " + i + "] " + argStr.substring(0, 500));

                    // Try to extract Authorization header (first arg is usually auth)
                    if (i === 0 && typeof argStr === 'string' && argStr.indexOf('Bearer') >= 0) {
                        console.log("[Authorization] " + argStr);
                    }
                }
            }
        } catch (err) {
            console.log("[Error dumping args] " + err);
        }

        console.log("=".repeat(80) + "\n");
    }

    try {
        var VehicleAPI = Java.use('T3.I');
        console.log("[+] Found Vehicle API interface: T3.I");

        var methods = VehicleAPI.class.getDeclaredMethods();
        console.log("[+] Found " + methods.length + " methods in interface");

        // Hook all methods
        for (var i = 0; i < methods.length; i++) {
            var method = methods[i];
            var methodName = method.getName();
            var paramTypes = method.getParameterTypes();

            console.log("[*] Hooking method: " + methodName + " with " + paramTypes.length + " parameters");

            // Create closure to capture method name
            (function(mName) {
                try {
                    var methodRef = VehicleAPI[mName];
                    if (methodRef && methodRef.implementation) {
                        methodRef.implementation = function() {
                            var args = Array.prototype.slice.call(arguments);
                            emitApiLog("VEHICLE_API", mName, args);
                            return methodRef.apply(this, arguments);
                        };
                        console.log("  [✓] Hooked: " + mName);
                    }
                } catch (hookErr) {
                    console.log("  [✗] Failed to hook " + mName + ": " + hookErr);
                }
            })(methodName);
        }

        console.log("\n[*] Waiting for API calls...\n");

    } catch (interfaceErr) {
        console.log('[!] Vehicle API interface not available: ' + interfaceErr);
    }
});
