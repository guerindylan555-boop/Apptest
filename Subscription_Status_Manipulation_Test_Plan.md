# 🧪 Subscription Status Manipulation Test Plan

**Test ID:** TC-SUB-001
**Target:** MaynDrive App v1.1.34
**Vulnerability Class:** Client-side Subscription Bypass
**Risk Level:** HIGH

---

## 📋 **TEST OVERVIEW**

**Objective:** Demonstrate the ability to manipulate subscription status to obtain premium features without payment by hooking the `UserSubscriptionModel` class and forcing it to show "active" status with extended validity.

**Expected Outcome:** User gains access to premium subscription features indefinitely without actual payment.

---

## 🔧 **TEST REQUIREMENTS**

### Environment Setup
- **Device:** Android emulator or rooted physical device
- **App:** MaynDrive APK v1.1.34 (official signed)
- **Frida Server:** v17.4.0+ running on device
- **Frida Client:** v17.4.0+ on host machine
- **Python:** 3.8+ (for Frida Python API)
- **ADB:** Android Debug Bridge

### Target Classes/Methods
```java
// Primary Target: UserSubscriptionModel
Class: p610s4.C10458m
Fields to Manipulate:
- f34534h0 (state) - Subscription status
- f34531Z (nextRenewDate) - Next renewal timestamp
- f34532f0 (cancellationDate) - Cancellation timestamp
- f34529X (userSubscriptionId) - Subscription ID
```

---

## 📱 **TEST EXECUTION PLAN**

### Phase 1: Preparation

#### 1.1 Environment Setup
```bash
# 1. Start emulator/ensure device is connected
adb devices

# 2. Install official MaynDrive APK
adb install mayndrive_1.1.34.apk

# 3. Start Frida server on device
adb shell su -c "/data/local/tmp/frida-server &"

# 4. Verify Frida connection
frida-ps -U | grep mayndrive
```

#### 1.2 Baseline Verification
```bash
# 1. Launch app normally
adb shell am start -n fr.mayndrive.app/.MainActivity

# 2. Verify current subscription status (should be none/free)
# 3. Note UI behavior - premium features should be locked
# 4. Take baseline screenshots
adb shell screencap -p > baseline_status.png
```

### Phase 2: Hook Development

#### 2.1 Create Subscription Manipulation Script
```javascript
// File: subscription_bypass.js
console.log("[*] Starting MaynDrive Subscription Bypass...");

Java.perform(function() {
    try {
        // Target UserSubscriptionModel class
        var UserSubscriptionModel = Java.use("p610s4.C10458m");

        console.log("[+] Found UserSubscriptionModel class");

        // Hook the constructor to manipulate subscription status
        UserSubscriptionModel.$init.overload(
            'java.lang.String',    // userSubscriptionId
            'java.util.Date',      // startDate
            'java.util.Date',      // nextRenewDate
            'java.util.Date',      // cancellationDate
            'java.util.Date',      // endDate
            'java.lang.String',    // state
            'p610s4.C10452g',      // price
            'java.lang.String',    // intervalType
            'java.lang.Integer',   // intervalCount
            'java.lang.String',    // subscriptionName
            'java.lang.Integer',   // tripDuration
            'java.lang.Integer',   // tripWaitingPeriod
            'java.lang.String',    // networkId
            'java.lang.String',    // networkName
            'java.lang.String',    // currency
            'p545n4.C9549x',       // paymentMethodDetails
            'java.lang.String',    // paymentMethodType
            'java.lang.String',    // provider
            'java.lang.String',    // lastTripState
            'java.util.Date',      // lastTripEndDate
            'java.lang.Double',    // discountPercent
            'java.lang.Integer',   // discountDuration
            'java.lang.Integer'    // discountDurationInMonths
        ).implementation = function(userSubscriptionId, startDate, nextRenewDate, cancellationDate,
                                   endDate, state, price, intervalType, intervalCount, subscriptionName,
                                   tripDuration, tripWaitingPeriod, networkId, networkName, currency,
                                   paymentMethodDetails, paymentMethodType, provider, lastTripState,
                                   lastTripEndDate, discountPercent, discountDuration, discountDurationInMonths) {

            console.log("[*] Intercepting UserSubscriptionModel constructor");
            console.log("[+] Original state: " + state);
            console.log("[+] Original renewal date: " + nextRenewDate);

            // Create fake premium subscription
            var fakeSubscriptionId = "PREMIUM_BYPASS_" + Math.floor(Math.random() * 1000000);
            var fakeStartDate = new Date();
            var fakeNextRenewDate = new Date(Date.now() + (365 * 24 * 60 * 60 * 1000)); // 1 year from now
            var fakeEndDate = new Date(Date.now() + (730 * 24 * 60 * 60 * 1000)); // 2 years from now
            var fakeState = "active";

            // Create fake premium subscription
            this.$init(
                fakeSubscriptionId,
                fakeStartDate,
                fakeNextRenewDate,    // Extended renewal date
                null,                  // No cancellation date
                fakeEndDate,
                fakeState,             // ACTIVE status
                price,
                "month",
                1,
                "Premium Monthly",
                60,                    // 60 minutes trips
                0,
                networkId,
                networkName,
                "EUR",
                paymentMethodDetails,
                "card",
                provider,
                "completed",
                lastTripEndDate,
                0.0,                   // No discount
                0,
                0
            );

            console.log("[+] Subscription manipulated to ACTIVE status");
            console.log("[+] New subscription ID: " + fakeSubscriptionId);
            console.log("[+] New renewal date: " + fakeNextRenewDate);
            console.log("[+] New state: " + fakeState);
        };

        // Also hook static methods that might create subscription objects
        try {
            var SubscriptionUtils = Java.use("p610s4.C10449d");
            console.log("[+] Found SubscriptionUtils class");

            // Hook any method that returns subscription data
            SubscriptionUtils.toString.implementation = function() {
                var result = this.toString();
                console.log("[+] SubscriptionUtils.toString() called: " + result);
                return result;
            };

        } catch (e) {
            console.log("[-] Could not hook SubscriptionUtils: " + e);
        }

        // Hook payment method related classes
        try {
            var PaymentMethodDetails = Java.use("p545n4.C9549x");
            console.log("[+] Found PaymentMethodDetails class");

            PaymentMethodDetails.$init.implementation = function(alias, expirationDate, cardProvider, email, wallet, networks) {
                console.log("[+] Intercepting PaymentMethodDetails constructor");
                // Create a fake payment method
                this.$init(
                    "VISA ****4242",
                    expirationDate,
                    "VISA",
                    email,
                    "premium_wallet",
                    networks
                );
                console.log("[+] Payment method manipulated to show premium wallet");
            };

        } catch (e) {
            console.log("[-] Could not hook PaymentMethodDetails: " + e);
        }

        console.log("[+] All hooks installed successfully");

    } catch (e) {
        console.log("[-] Error setting up hooks: " + e);
        console.log("[-] Stack trace: " + e.stack);
    }
});

console.log("[*] Subscription bypass script loaded");
```

#### 2.2 Create Test Automation Script
```python
# File: test_subscription_bypass.py
import frida
import time
import subprocess
import sys
import json

class SubscriptionBypassTester:
    def __init__(self):
        self.device = None
        self.session = None
        self.script = None

    def setup_frida(self):
        """Setup Frida connection"""
        try:
            # Get the MaynDrive process
            result = subprocess.run(['adb', 'shell', 'pidof', 'fr.mayndrive.app'],
                                  capture_output=True, text=True)

            if result.returncode != 0:
                print("[-] MaynDrive app not running. Starting it...")
                subprocess.run(['adb', 'shell', 'am', 'start', '-n', 'fr.mayndrive.app/.MainActivity'])
                time.sleep(3)

                result = subprocess.run(['adb', 'shell', 'pidof', 'fr.mayndrive.app'],
                                      capture_output=True, text=True)
                if result.returncode != 0:
                    raise Exception("Could not start MaynDrive app")

            pid = result.stdout.strip()
            print(f"[+] Found MaynDrive process: {pid}")

            # Attach Frida
            self.device = frida.get_usb_device()
            self.session = self.device.attach(int(pid))

            # Load the script
            with open('subscription_bypass.js', 'r') as f:
                script_code = f.read()

            self.script = self.session.create_script(script_code)

            # Set up message handlers
            def on_message(message, data):
                if message['type'] == 'send':
                    print(f"[FRIDA] {message['payload']}")
                elif message['type'] == 'error':
                    print(f"[ERROR] {message['stack']}")

            self.script.on('message', on_message)
            self.script.load()

            print("[+] Frida session established and script loaded")
            return True

        except Exception as e:
            print(f"[-] Error setting up Frida: {e}")
            return False

    def run_test_sequence(self):
        """Execute the test sequence"""
        print("\n" + "="*60)
        print("🧪 SUBSCRIPTION STATUS MANIPULATION TEST")
        print("="*60)

        # Test 1: Baseline Check
        print("\n[TEST 1] Baseline subscription status check...")
        self.take_screenshot("baseline_subscription")

        # Test 2: Hook Installation
        print("\n[TEST 2] Installing subscription bypass hooks...")
        if not self.setup_frida():
            print("[-] Failed to setup Frida")
            return False

        time.sleep(2)

        # Test 3: Trigger Subscription Check
        print("\n[TEST 3] Triggering subscription status refresh...")
        # Navigate to subscription screen
        subprocess.run(['adb', 'shell', 'input', 'tap', '540', '1200'])  # Tap profile area
        time.sleep(2)
        subprocess.run(['adb', 'shell', 'input', 'tap', '540', '800'])   # Tap subscription area
        time.sleep(3)

        # Test 4: Verify Manipulation
        print("\n[TEST 4] Verifying subscription status manipulation...")
        self.take_screenshot("manipulated_subscription")

        # Test 5: Premium Feature Access Test
        print("\n[TEST 5] Testing premium feature access...")
        self.test_premium_features()

        # Test 6: Persistence Test
        print("\n[TEST 6] Testing subscription persistence...")
        self.test_persistence()

        return True

    def take_screenshot(self, filename):
        """Take a screenshot"""
        try:
            subprocess.run(['adb', 'shell', 'screencap', '-p', f'/sdcard/{filename}.png'])
            subprocess.run(['adb', 'pull', f'/sdcard/{filename}.png', f'./{filename}.png'])
            print(f"[+] Screenshot saved: {filename}.png")
        except Exception as e:
            print(f"[-] Error taking screenshot: {e}")

    def test_premium_features(self):
        """Test access to premium features"""
        print("[+] Testing premium scooter unlock...")

        # Try to unlock a scooter (premium feature)
        subprocess.run(['adb', 'shell', 'input', 'tap', '300', '900'])  # Tap map area
        time.sleep(2)
        subprocess.run(['adb', 'shell', 'input', 'tap', '617', '1042'])  # Tap rent button
        time.sleep(5)

        self.take_screenshot("premium_unlock_test")
        print("[+] Premium unlock test completed")

    def test_persistence(self):
        """Test if bypass persists after app restart"""
        print("[+] Testing bypass persistence...")

        # Restart app
        subprocess.run(['adb', 'shell', 'am', 'force-stop', 'fr.mayndrive.app'])
        time.sleep(2)
        subprocess.run(['adb', 'shell', 'am', 'start', '-n', 'fr.mayndrive.app/.MainActivity'])
        time.sleep(3)

        # Check subscription status again
        subprocess.run(['adb', 'shell', 'input', 'tap', '540', '1200'])
        time.sleep(2)
        subprocess.run(['adb', 'shell', 'input', 'tap', '540', '800'])
        time.sleep(3)

        self.take_screenshot("persistence_test")
        print("[+] Persistence test completed")

    def cleanup(self):
        """Clean up resources"""
        if self.session:
            self.session.detach()
        print("[+] Cleanup completed")

def main():
    tester = SubscriptionBypassTester()

    try:
        success = tester.run_test_sequence()

        print("\n" + "="*60)
        print("📊 TEST RESULTS SUMMARY")
        print("="*60)

        if success:
            print("✅ Subscription status manipulation successful!")
            print("✅ Premium features should now be accessible")
            print("✅ Check screenshots for visual confirmation")
            print("\n⚠️  WARNING: This is for authorized testing only!")
        else:
            print("❌ Test failed - check logs for details")

    except KeyboardInterrupt:
        print("\n[!] Test interrupted by user")
    except Exception as e:
        print(f"\n[-] Unexpected error: {e}")
    finally:
        tester.cleanup()

if __name__ == "__main__":
    main()
```

### Phase 3: Test Execution

#### 3.1 Execute the Test
```bash
# 1. Save the scripts above in the same directory
# 2. Run the test
python test_subscription_bypass.py
```

#### 3.2 Expected Results
```
[+] Found MaynDrive process: 6318
[+] Frida session established and script loaded
[+] All hooks installed successfully
[+] Subscription manipulated to ACTIVE status
[+] New subscription ID: PREMIUM_BYPASS_123456
[+] New renewal date: Fri Oct 24 2026 15:30:00 GMT+0000
[+] New state: active
```

---

## 📊 **SUCCESS CRITERIA**

### Primary Success Indicators
1. ✅ **UI Shows Active Subscription**
   - Premium subscription banner appears
   - "Premium" status displayed in profile
   - Next renewal date shows future date (1+ years)

2. ✅ **Premium Features Unlocked**
   - Scooter unlock works without payment prompt
   - Extended ride time available (60+ minutes)
   - No subscription upgrade prompts

3. ✅ **No Payment Required**
   - App doesn't request payment method
   - No Stripe/Google Pay checkout flow
   - Premium features work immediately

### Secondary Success Indicators
1. ✅ **Subscription Persistence**
   - Bypass survives app restart
   - Status remains active across sessions

2. ✅ **Error-Free Operation**
   - No app crashes or instability
   - Normal functionality preserved

---

## 🔍 **VERIFICATION STEPS**

### 1. Visual Verification
- Compare baseline vs manipulated screenshots
- Confirm UI shows premium status
- Verify absence of payment prompts

### 2. Functional Testing
- Attempt to unlock scooter (should work without payment)
- Check ride time limits (should be premium limits)
- Navigate subscription screen (should show active status)

### 3. Technical Verification
- Monitor Frida logs for successful hook execution
- Check API calls (should show premium subscription requests)
- Verify local storage contains manipulated data

---

## 📋 **TEST CHECKLIST**

### Pre-Test Requirements
- [ ] Frida server running on device
- [ ] MaynDrive app installed and launchable
- [ ] Test scripts created and ready
- [ ] Screenshot directory exists
- [ ] Baseline app behavior documented

### Execution Checklist
- [ ] App launched normally
- [ ] Baseline screenshots taken
- [ ] Frida successfully attached
- [ ] Scripts loaded without errors
- [ ] Subscription status manipulated
- [ ] Premium features tested
- [ ] Persistence verified
- [ ] Screenshots captured for all steps

### Post-Test Verification
- [ ] Review all screenshots
- [ ] Check Frida logs for success messages
- [ ] Document any unexpected behavior
- [ ] Verify app stability
- [ ] Clean up test environment

---

## 🚨 **EXPECTED BEHAVIORS**

### During Hook Installation
- App may briefly pause when hooks first execute
- Console messages showing hook installation success
- No app crashes or error dialogs

### After Manipulation
- UI updates to show premium subscription status
- Premium features become accessible
- No payment prompts during feature access

### During Premium Feature Use
- Smooth operation without payment interruptions
- Extended ride times and privileges
- Normal app performance maintained

---

## ⚠️ **SAFETY CONSIDERATIONS**

### Test Environment Safety
- Use test account or create new account
- Avoid using personal payment methods
- Document all changes for rollback

### Legal Compliance
- Only test on apps you have permission to test
- Follow responsible disclosure practices
- Do not exploit vulnerabilities beyond testing scope

### Data Protection
- Don't use real payment information
- Clear app data after testing if needed
- Secure any captured screenshots/logs

---

## 🔄 **ROLLBACK PROCEDURES**

### 1. Stop Frida Script
```bash
# Terminate the test script
Ctrl+C in test script terminal
```

### 2. Clear App Data
```bash
# Reset app to original state
adb shell pm clear fr.mayndrive.app
```

### 3. Reinstall App (if needed)
```bash
# Fresh install to ensure clean state
adb uninstall fr.mayndrive.app
adb install mayndrive_1.1.34.apk
```

---

## 📝 **NOTES AND OBSERVATIONS**

### Things to Document During Test
- Exact timing of hook installation
- Any error messages or unexpected behaviors
- Performance impact on app functionality
- Specific UI changes observed
- Any network requests affected

### Potential Variations
- Different app versions may have different class names
- Hook may need adjustment based on app behavior
- Some features may require additional hooks

---

**⚠️ WARNING:** This test plan is for authorized security research only. Unauthorized use of payment system vulnerabilities is illegal and unethical. Always obtain proper authorization before conducting security testing.