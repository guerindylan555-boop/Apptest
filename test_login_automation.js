#!/usr/bin/env node

/**
 * Test Login Automation using Updated MaynDrive Framework
 * Tests the complete login flow with discovered coordinates and working credentials
 */

const MaynDriveAutomation = require('./mayndrive_automation_framework');

async function testLoginAutomation() {
    console.log('🚀 Starting MaynDrive Login Automation Test');
    console.log('Using discovered coordinates and working credentials');

    // Initialize the automation framework
    const app = new MaynDriveAutomation({
        screenshotDir: './login_test_screenshots',
        logFile: './login_test.log',
        device: 'emulator-5556'
    });

    try {
        // Step 1: Ensure the app is started
        console.log('\n1️⃣ Ensuring app is started...');
        const appStarted = await app.ensureAppStarted();
        if (!appStarted) {
            console.log('❌ Failed to start the app');
            return false;
        }
        console.log('✅ App started successfully');

        // Step 2: Get current status
        console.log('\n2️⃣ Getting current status...');
        const status = await app.getStatus();
        console.log(`Current screen: ${status.currentScreen}`);
        console.log(`Available actions: ${status.availableActions.join(', ')}`);

        // Step 3: Take initial screenshot
        await app.takeScreenshot('initial_state');

        // Step 4: Handle login flow based on current screen
        if (status.currentScreen === 'LOGIN') {
            console.log('\n3️⃣ Already on login screen - proceeding with login...');
            await app.performLogin('blhackapple@gmail.com', 'Yolo01610');
        } else if (status.currentScreen === 'MAIN_MAP') {
            // Check if we have "Login to rent" button (not logged in)
            if (status.availableActions.includes('openMenu')) {
                console.log('\n3️⃣ On main map but need to login...');

                // Open login bottom sheet by tapping bottom area
                console.log('Opening login sheet...');
                await app.tap(540, 1689, 'Login to rent button');
                await app.delay(2000);

                // Select login from sheet
                console.log('Selecting login option...');
                await app.tap(540, 1348, 'Login button in sheet');
                await app.delay(2000);

                // Perform login with credentials
                console.log('Performing login with credentials...');
                const loginSuccess = await app.performLogin('blhackapple@gmail.com', 'Yolo01610');

                if (loginSuccess) {
                    console.log('✅ Login completed successfully!');
                } else {
                    console.log('❌ Login failed');
                    return false;
                }
            } else {
                console.log('\n3️⃣ Already logged in - taking final screenshot');
                await app.takeScreenshot('already_logged_in');
                return true;
            }
        } else {
            console.log(`\n3️⃣ On unexpected screen: ${status.currentScreen}`);
            console.log('Taking screenshot and attempting to navigate...');
            await app.takeScreenshot('unexpected_screen');

            // Try to get back to a known state
            await app.back();
            await app.delay(2000);
        }

        // Step 5: Verify final state
        console.log('\n4️⃣ Verifying final login state...');
        const finalStatus = await app.getStatus();
        console.log(`Final screen: ${finalStatus.currentScreen}`);
        console.log(`Final actions: ${finalStatus.availableActions.join(', ')}`);

        // Take final screenshot
        await app.takeScreenshot('final_state');

        // Step 6: Validate login success
        const isLoggedIn = finalStatus.currentScreen === 'MAIN_MAP' &&
                         finalStatus.availableActions.includes('buyPass') &&
                         finalStatus.availableActions.includes('scanRide');

        if (isLoggedIn) {
            console.log('\n✅ LOGIN AUTOMATION TEST SUCCESSFUL!');
            console.log('✅ User is now logged in with full access to app features');
            console.log('✅ Available actions:', finalStatus.availableActions.join(', '));
            return true;
        } else {
            console.log('\n❌ LOGIN AUTOMATION TEST FAILED');
            console.log(`❌ Current screen: ${finalStatus.currentScreen}`);
            console.log(`❌ Expected: MAIN_MAP with buyPass and scanRide actions`);
            return false;
        }

    } catch (error) {
        console.error('\n❌ Login automation failed with error:', error.message);
        await app.takeScreenshot('error_state');
        return false;
    }
}

// Alternative step-by-step login implementation for testing
async function testStepByStepLogin() {
    console.log('\n🔧 Testing step-by-step login implementation...');

    const app = new MaynDriveAutomation({
        screenshotDir: './step_by_step_screenshots',
        logFile: './step_by_step.log',
        device: 'emulator-5556'
    });

    try {
        // Start app
        await app.ensureAppStarted();
        await app.takeScreenshot('step_start');

        // Handle consent if present
        console.log('Checking for consent screen...');
        const currentStatus = await app.getStatus();

        if (currentStatus.currentScreen === 'UNKNOWN') {
            // Try to dismiss consent/error dialogs
            console.log('Attempting to handle consent flow...');

            // Tap "Let's go!" if present
            await app.tap(540, 1667, "Let's go button");
            await app.delay(2000);

            // Dismiss any error dialogs
            await app.tap(779, 1053, "Error dialog OK");
            await app.delay(2000);

            // Try to open login sheet
            await app.tap(540, 1689, "Login to rent");
            await app.delay(2000);

            // Select login
            await app.tap(540, 1348, "Login option");
            await app.delay(2000);
        }

        // Enter credentials step by step
        console.log('Entering email...');
        await app.tap(540, 407, "Email field");
        await app.delay(500);
        await app.adb('shell input text "blhackapple@gmail.com"');
        await app.delay(1000);

        console.log('Entering password...');
        await app.tap(540, 638, "Password field");
        await app.delay(500);
        await app.adb('shell input text "Yolo01610"');
        await app.delay(1000);

        console.log('Submitting login...');
        await app.tap(540, 1067, "Login button");
        await app.delay(5000);

        // Handle post-login error
        console.log('Checking for post-login dialogs...');
        await app.tap(779, 1053, "Post-login OK");
        await app.delay(3000);

        // Verify success
        const finalStatus = await app.getStatus();
        await app.takeScreenshot('step_final');

        const success = finalStatus.availableActions.includes('buyPass') &&
                      finalStatus.availableActions.includes('scanRide');

        console.log(`Step-by-step login ${success ? 'SUCCESSFUL' : 'FAILED'}`);
        return success;

    } catch (error) {
        console.error('Step-by-step login failed:', error.message);
        return false;
    }
}

// Main execution
async function main() {
    console.log('🧪 MaynDrive Login Automation Test Suite');
    console.log('=====================================');

    let testsPassed = 0;
    let testsTotal = 2;

    // Test 1: Framework login method
    console.log('\n📋 Test 1: Framework Login Method');
    console.log('-----------------------------------');
    const test1Result = await testLoginAutomation();
    if (test1Result) {
        testsPassed++;
        console.log('✅ Test 1 PASSED');
    } else {
        console.log('❌ Test 1 FAILED');
    }

    // Test 2: Step-by-step method
    console.log('\n📋 Test 2: Step-by-Step Login Method');
    console.log('-------------------------------------');
    const test2Result = await testStepByStepLogin();
    if (test2Result) {
        testsPassed++;
        console.log('✅ Test 2 PASSED');
    } else {
        console.log('❌ Test 2 FAILED');
    }

    // Summary
    console.log('\n📊 Test Results Summary');
    console.log('=======================');
    console.log(`Tests passed: ${testsPassed}/${testsTotal}`);
    console.log(`Success rate: ${Math.round((testsPassed / testsTotal) * 100)}%`);

    if (testsPassed === testsTotal) {
        console.log('\n🎉 ALL TESTS PASSED! Login automation is working correctly.');
        process.exit(0);
    } else {
        console.log('\n⚠️ Some tests failed. Please check the logs and screenshots.');
        process.exit(1);
    }
}

// Run if executed directly
if (require.main === module) {
    main().catch(error => {
        console.error('Test suite failed:', error);
        process.exit(1);
    });
}

module.exports = { testLoginAutomation, testStepByStepLogin };