/**
 * MaynDrive Login Automation Example
 * Demonstrates how to use the updated framework with login functionality
 */

const MaynDriveAutomation = require('./mayndrive_automation_framework');

async function exampleLoginAutomation() {
    console.log('🚀 Starting MaynDrive Login Automation Example');
    console.log('This demonstrates the complete login process using the updated framework');

    // Initialize the automation framework
    const app = new MaynDriveAutomation({
        screenshotDir: './login_automation_screenshots',
        logFile: './login_automation.log',
        device: 'emulator-5556' // Use the correct device ID
    });

    try {
        // Step 1: Ensure the app is running and check current state
        console.log('\n1️⃣ Ensuring app is started...');
        const appStarted = await app.ensureAppStarted();
        if (!appStarted) {
            console.log('❌ Failed to start the app');
            return;
        }

        // Step 2: Get current status
        console.log('\n2️⃣ Getting current status...');
        const status = await app.getStatus();
        console.log(`Current screen: ${status.currentScreen}`);
        console.log(`Available actions: ${status.availableActions.join(', ')}`);

        // Step 3: If on main map, logout to show login process
        if (status.currentScreen === 'MAIN_MAP') {
            console.log('\n3️⃣ Already logged in - performing logout to demonstrate login flow...');
            await app.openMenu();
            await app.delay(2000);

            // Try to find and click logout option
            await app.tap(540, 950, 'Logout option');
            await app.delay(3000);

            const newStatus = await app.getStatus();
            if (newStatus.currentScreen !== 'LOGIN') {
                console.log('⚠️ Could not logout - proceeding with current state');
            }
        }

        // Step 4: Check if we're on login screen
        const currentStatus = await app.getStatus();
        if (currentStatus.currentScreen !== 'LOGIN') {
            console.log(`⚠️ Not on login screen. Current: ${currentStatus.currentScreen}`);
            console.log('Please ensure the app data is cleared to see the login screen');
            return;
        }

        console.log('\n4️⃣ On login screen - demonstrating login interaction methods...');

        // Example 1: Individual login steps
        console.log('\n📧 Testing individual login field interactions...');
        await app.enterEmail('test@example.com');
        await app.delay(1000);

        console.log('\n🔐 Testing password field interaction...');
        await app.enterPassword('password123');
        await app.delay(1000);

        console.log('\n🔑 Testing login button interaction...');
        await app.clickLoginButton();
        await app.delay(3000);

        // Check result
        const finalStatus = await app.getStatus();
        if (finalStatus.currentScreen === 'MAIN_MAP') {
            console.log('✅ Individual login steps completed successfully!');
        } else {
            console.log(`⚠️ Login attempt result: ${finalStatus.currentScreen}`);
        }

        // Step 5: Demonstrate complete login method (if still on login screen)
        if (finalStatus.currentScreen === 'LOGIN') {
            console.log('\n🔄 Testing complete login method...');
            const loginSuccess = await app.performLogin('test@example.com', 'password123');

            if (loginSuccess) {
                console.log('✅ Complete login method worked!');
            } else {
                console.log('❌ Complete login method failed');
            }
        }

        console.log('\n🎉 Login automation example completed!');
        console.log('Available login methods in the framework:');
        console.log('- enterEmail(email)');
        console.log('- enterPassword(password)');
        console.log('- clickLoginButton()');
        console.log('- clickForgotPassword()');
        console.log('- performLogin(email, password)');

    } catch (error) {
        console.error('❌ Login automation failed:', error.message);
    }
}

// Run the example
if (require.main === module) {
    exampleLoginAutomation().then(() => {
        console.log('\nExample finished');
        process.exit(0);
    }).catch(error => {
        console.error('Example failed:', error);
        process.exit(1);
    });
}

module.exports = exampleLoginAutomation;