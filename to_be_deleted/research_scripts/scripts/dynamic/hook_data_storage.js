// MyMaynDrive APK - Data Storage and Privacy Hook
// This script monitors data storage, SharedPreferences, and database operations

console.log("[*] MyMaynDrive Data Storage Monitoring Hook Started");

Java.perform(function() {
    console.log("[+] Java environment initialized for data storage monitoring");

    // Hook SharedPreferences operations
    try {
        var SharedPreferences = Java.use("android.content.SharedPreferences");
        var Editor = Java.use("android.content.SharedPreferences$Editor");

        // Monitor data reads
        SharedPreferences.getString.implementation = function(key, defValue) {
            var result = this.getString(key, defValue);

            // Check for sensitive data access
            var sensitiveKeys = [
                'api_key', 'token', 'password', 'email', 'phone', 'user_id',
                'payment', 'card', 'bank', 'stripe', 'braintree', 'paypal',
                'location', 'address', 'coordinate', 'gps', 'firebase',
                'analytics', 'tracking', 'session', 'auth', 'credential'
            ];

            for (var i = 0; i < sensitiveKeys.length; i++) {
                if (key.toLowerCase().includes(sensitiveKeys[i])) {
                    console.log("[!] SENSITIVE DATA READ FROM SHARED PREFERENCES:");
                    console.log("    Key: " + key);
                    console.log("    Value length: " + (result ? result.length : 0));
                    console.log("    Sensitive type: " + sensitiveKeys[i]);
                    console.log("    Timestamp: " + new Date().toISOString());
                    break;
                }
            }

            return result;
        };

        // Monitor data writes
        Editor.putString.implementation = function(key, value) {
            var sensitiveKeys = [
                'api_key', 'token', 'password', 'email', 'phone', 'user_id',
                'payment', 'card', 'bank', 'stripe', 'braintree', 'paypal',
                'location', 'address', 'coordinate', 'gps', 'firebase',
                'analytics', 'tracking', 'session', 'auth', 'credential'
            ];

            for (var i = 0; i < sensitiveKeys.length; i++) {
                if (key.toLowerCase().includes(sensitiveKeys[i])) {
                    console.log("[!] SENSITIVE DATA WRITTEN TO SHARED PREFERENCES:");
                    console.log("    Key: " + key);
                    console.log("    Value length: " + (value ? value.length : 0));
                    console.log("    Sensitive type: " + sensitiveKeys[i]);

                    // Check for potential security issues
                    if (value && value.includes("AIzaSy")) {
                        console.log("    🚨 GOOGLE API KEY STORED IN PLAINTEXT!");
                    }
                    if (value && value.length > 100) {
                        console.log("    ⚠️  LONG VALUE STORED (potential sensitive data)");
                    }

                    console.log("    Timestamp: " + new Date().toISOString());
                    break;
                }
            }

            return this.putString(key, value);
        };

        // Monitor boolean values
        Editor.putBoolean.implementation = function(key, value) {
            var configKeys = ['debug', 'test', 'production', 'logging', 'analytics_enabled'];
            for (var i = 0; i < configKeys.length; i++) {
                if (key.toLowerCase().includes(configKeys[i])) {
                    console.log("[!] CONFIGURATION VALUE STORED:");
                    console.log("    Key: " + key);
                    console.log("    Value: " + value);
                    console.log("    Type: " + configKeys[i]);
                    console.log("    Timestamp: " + new Date().toISOString());
                    break;
                }
            }

            return this.putBoolean(key, value);
        };

        console.log("[+] SharedPreferences operations hooked");
    } catch (e) {
        console.log("[-] Failed to hook SharedPreferences: " + e);
    }

    // Hook SQLite database operations
    try {
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
        var SQLiteQuery = Java.use("android.database.sqlite.SQLiteQuery");

        // Monitor database queries
        SQLiteDatabase.rawQuery.implementation = function(sql, selectionArgs) {
            var sqlStr = sql.toString().toLowerCase();

            // Check for sensitive data queries
            var sensitiveTables = [
                'user', 'payment', 'card', 'transaction', 'location',
                'token', 'session', 'credential', 'personal', 'private'
            ];

            for (var i = 0; i < sensitiveTables.length; i++) {
                if (sqlStr.includes(sensitiveTables[i])) {
                    console.log("[!] SENSITIVE DATABASE QUERY:");
                    console.log("    SQL: " + sql);
                    if (selectionArgs) {
                        console.log("    Args: " + selectionArgs.toString());
                    }
                    console.log("    Sensitive table: " + sensitiveTables[i]);
                    console.log("    Timestamp: " + new Date().toISOString());
                    break;
                }
            }

            return this.rawQuery(sql, selectionArgs);
        };

        // Monitor database inserts
        SQLiteDatabase.insert.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues').implementation = function(table, nullColumnHack, values) {
            var tableStr = table.toLowerCase();

            var sensitiveTables = [
                'user', 'payment', 'card', 'transaction', 'location',
                'token', 'session', 'credential', 'personal', 'private'
            ];

            for (var i = 0; i < sensitiveTables.length; i++) {
                if (tableStr.includes(sensitiveTables[i])) {
                    console.log("[!] SENSITIVE DATA INSERTED:");
                    console.log("    Table: " + table);
                    console.log("    Columns: " + (values ? values.keySet().toString() : "null"));
                    console.log("    Sensitive table: " + sensitiveTables[i]);
                    console.log("    Timestamp: " + new Date().toISOString());
                    break;
                }
            }

            return this.insert(table, nullColumnHack, values);
        };

        console.log("[+] SQLite database operations hooked");
    } catch (e) {
        console.log("[-] Failed to hook SQLite operations: " + e);
    }

    // Hook file operations
    try {
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        var FileInputStream = Java.use("java.io.FileInputStream");

        // Monitor file writes
        FileOutputStream.write.overload('[B').implementation = function(buffer) {
            var filePath = this.getFD().toString();

            // Check for sensitive file operations
            var sensitivePatterns = [
                'key', 'token', 'password', 'credential', 'private',
                'config', 'cache', 'temp', 'backup', 'log'
            ];

            for (var i = 0; i < sensitivePatterns.length; i++) {
                if (filePath.toLowerCase().includes(sensitivePatterns[i])) {
                    console.log("[!] SENSITIVE FILE WRITE:");
                    console.log("    File: " + filePath);
                    console.log("    Data size: " + buffer.length + " bytes");
                    console.log("    Pattern: " + sensitivePatterns[i]);

                    // Check for potential keys or secrets in the data
                    var dataStr = Java.use("java.lang.String").$new(buffer);
                    if (dataStr.includes("AIzaSy")) {
                        console.log("    🚨 GOOGLE API KEY WRITTEN TO FILE!");
                    }

                    console.log("    Timestamp: " + new Date().toISOString());
                    break;
                }
            }

            return this.write(buffer);
        };

        console.log("[+] File operations hooked");
    } catch (e) {
        console.log("[-] Failed to hook file operations: " + e);
    }

    // Hook Room database operations if available
    try {
        var RoomDatabase = Java.use("androidx.room.RoomDatabase");
        RoomDatabase.beginTransaction.implementation = function() {
            console.log("[!] ROOM DATABASE TRANSACTION STARTED:");
            console.log("    Database: " + this.getClass().getSimpleName());
            console.log("    Timestamp: " + new Date().toISOString());
            return this.beginTransaction();
        };

        RoomDatabase.setTransactionSuccessful.implementation = function() {
            console.log("[!] ROOM DATABASE TRANSACTION COMMITTED:");
            console.log("    Database: " + this.getClass().getSimpleName());
            console.log("    Timestamp: " + new Date().toISOString());
            return this.setTransactionSuccessful();
        };

        console.log("[+] Room database operations hooked");
    } catch (e) {
        console.log("[-] Room database not available: " + e);
    }

    // Hook encryption operations
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.implementation = function() {
            var algorithm = this.getAlgorithm();
            var operation = this.getOpMode();

            console.log("[!] ENCRYPTION OPERATION:");
            console.log("    Algorithm: " + algorithm);
            console.log("    Operation: " + operation);

            if (operation === 1) { // ENCRYPT_MODE
                console.log("    Type: ENCRYPTION");
            } else if (operation === 2) { // DECRYPT_MODE
                console.log("    Type: DECRYPTION");
            }

            console.log("    Timestamp: " + new Date().toISOString());

            var result = this.doFinal();
            console.log("    Result size: " + result.length + " bytes");

            return result;
        };

        console.log("[+] Encryption operations hooked");
    } catch (e) {
        console.log("[-] Failed to hook encryption operations: " + e);
    }

    // Hook Android Keystore operations
    try {
        var KeyStore = Java.use("java.security.KeyStore");
        KeyStore.getKey.implementation = function(alias, password) {
            console.log("[!] KEYSTORE KEY ACCESS:");
            console.log("    Alias: " + alias);
            console.log("    Keystore: " + this.getType());
            console.log("    Timestamp: " + new Date().toISOString());

            return this.getKey(alias, password);
        };

        KeyStore.setKeyEntry.implementation = function(alias, key, password, chain) {
            console.log("[!] KEYSTORE KEY STORAGE:");
            console.log("    Alias: " + alias);
            console.log("    Key type: " + key.getAlgorithm());
            console.log("    Keystore: " + this.getType());
            console.log("    Timestamp: " + new Date().toISOString());

            return this.setKeyEntry(alias, key, password, chain);
        };

        console.log("[+] Android Keystore operations hooked");
    } catch (e) {
        console.log("[-] Failed to hook Keystore operations: " + e);
    }

    // Monitor Firebase Realtime Database operations
    try {
        var DatabaseReference = Java.use("com.google.firebase.database.DatabaseReference");
        DatabaseReference.setValue.implementation = function(value) {
            console.log("[!] FIREBASE DATABASE WRITE:");
            console.log("    Reference: " + this.toString());
            console.log("    Value type: " + value.getClass().getSimpleName());
            console.log("    Timestamp: " + new Date().toISOString());
            return this.setValue(value);
        };

        console.log("[+] Firebase database operations hooked");
    } catch (e) {
        console.log("[-] Firebase database not available: " + e);
    }

    console.log("[*] Data Storage Monitoring Hook Setup Complete");
    console.log("[*] Monitoring SharedPreferences, SQLite, Files, Encryption, and Keystore operations");
});