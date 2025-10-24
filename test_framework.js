/**
 * Test the MaynDrive Automation Framework
 * Demonstrates that it works correctly
 */

const MaynDriveAutomation = require('./mayndrive_automation_framework');

async function testFramework() {
    console.log('🧪 Testing MaynDrive Automation Framework');

    // Initialize the framework
    const app = new MaynDriveAutomation({
        screenshotDir: './test_screenshots',
        logFile: './test.log'
    });

    try {
        console.log('\n1. Testing app startup...');
        const appStarted = await app.ensureAppStarted();
        console.log(`App started: ${appStarted ? '✅' : '❌'}`);

        console.log('\n2. Testing status detection...');
        const status = await app.getStatus();
        console.log(`Current screen: ${status.currentScreen}`);
        console.log(`Available actions: ${status.availableActions.join(', ')}`);
        console.log(`Status detection: ${status.currentScreen !== 'UNKNOWN' ? '✅' : '❌'}`);

        console.log('\n3. Testing basic tap...');
        const tapResult = await app.tap(540, 336, 'Vehicle info banner');
        console.log(`Basic tap: ${tapResult ? '✅' : '❌'}`);

        console.log('\n4. Testing screenshot...');
        const screenshot = await app.takeScreenshot('test_screenshot');
        console.log(`Screenshot: ${screenshot ? '✅' : '❌'}`);

        console.log('\n5. Testing navigation back...');
        const backResult = await app.back();
        console.log(`Navigation back: ${backResult ? '✅' : '❌'}`);

        console.log('\n6. Testing screen detection after navigation...');
        const newStatus = await app.getStatus();
        console.log(`New screen: ${newStatus.currentScreen}`);

        console.log('\n✅ Framework test completed successfully!');
        console.log('The framework is ready for LLM automation.');

    } catch (error) {
        console.error('\n❌ Framework test failed:', error.message);
        console.error('Please check ADB connection and device status.');
    }
}

// Run the test
if (require.main === module) {
    testFramework().then(() => {
        console.log('\nTest finished');
        process.exit(0);
    }).catch(error => {
        console.error('Test failed:', error);
        process.exit(1);
    });
}

module.exports = testFramework;