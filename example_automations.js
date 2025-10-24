/**
 * Example MaynDrive Automation Scripts
 * Demonstrates how LLMs can easily create automation using the framework
 */

const MaynDriveAutomation = require('./mayndrive_automation_framework');

// Initialize the automation framework
const app = new MaynDriveAutomation({
    screenshotDir: './example_screenshots',
    logFile: './example_automation.log'
});

async function example1_BasicVehicleUnlock() {
    console.log('🚀 Example 1: Basic Vehicle Unlock Flow');

    try {
        // Ensure app is running
        await app.ensureAppStarted();

        // Get current status
        const status = await app.getStatus();
        console.log('Current status:', status);

        // Complete vehicle unlock flow
        const success = await app.completeVehicleUnlockFlow();

        if (success) {
            console.log('✅ Vehicle unlocked successfully!');
        } else {
            console.log('❌ Vehicle unlock failed');
        }

    } catch (error) {
        console.error('❌ Example failed:', error.message);
    }
}

async function example2_CompleteRideFlow() {
    console.log('🏁 Example 2: Complete Ride Flow');

    try {
        // Start the app
        await app.ensureAppStarted();

        // Try to start a ride (either QR scanner or vehicle unlock)
        const rideStarted = await app.startRideFlow();

        if (rideStarted) {
            console.log('✅ Ride started successfully!');

            // Take a screenshot to document the start
            await app.takeScreenshot('ride_started');
        } else {
            console.log('❌ Failed to start ride');
        }

    } catch (error) {
        console.error('❌ Example failed:', error.message);
    }
}

async function example3_NavigationAndExploration() {
    console.log('🗺️ Example 3: Navigation and Exploration');

    try {
        await app.ensureAppStarted();

        // Go to my location
        await app.goToMyLocation();

        // Toggle between vehicles and spots
        await app.toggleVehicles();

        // Open and explore menu
        await app.openMenu();
        await app.takeScreenshot('menu_opened');

        // Open payment methods
        await app.openPaymentMethods();
        await app.takeScreenshot('payment_methods');

        // Go back to main map
        await app.back();
        await app.closeMenu();

        console.log('✅ Navigation and exploration completed!');

    } catch (error) {
        console.error('❌ Example failed:', error.message);
    }
}

async function example4_SmartErrorRecovery() {
    console.log('🛡️ Example 4: Smart Error Recovery');

    try {
        await app.ensureAppStarted();

        // Try to unlock vehicle even if we're not on the right screen
        // The framework will automatically navigate to the correct screen
        const success = await app.unlockVehicle();

        if (success) {
            console.log('✅ Vehicle unlocked (framework handled navigation)');
        } else {
            console.log('❌ Still failed after recovery attempts');
        }

    } catch (error) {
        console.error('❌ Example failed:', error.message);
    }
}

async function example5_StatusAwareAutomation() {
    console.log('📊 Example 5: Status-Aware Automation');

    try {
        // Get current status
        const status = await app.getStatus();
        console.log('Available actions:', status.availableActions);

        // Perform actions based on current screen
        if (status.currentScreen === 'MAIN_MAP') {
            console.log('On main map - starting ride flow');
            await app.startRideFlow();
        } else if (status.currentScreen === 'NAVIGATION_MENU') {
            console.log('In menu - exploring payment methods');
            await app.openPaymentMethods();
        } else if (status.currentScreen === 'VEHICLE_PANEL') {
            console.log('Vehicle panel open - unlocking vehicle');
            await app.unlockVehicle();
        } else {
            console.log('Unknown screen - going back to main map');
            await app.ensureScreen('MAIN_MAP');
        }

        console.log('✅ Status-aware automation completed!');

    } catch (error) {
        console.error('❌ Example failed:', error.message);
    }
}

async function example6_CustomCoordinationFlow() {
    console.log('🎯 Example 6: Custom Coordination Flow');

    try {
        await app.ensureAppStarted();

        // Custom sequence using individual coordinates
        await app.tap(540, 1557, 'Buy a Pass'); // Buy Pass button
        await app.delay(3000);

        await app.takeScreenshot('after_buy_pass');

        // Go back and try something else
        await app.back();

        await app.tap(540, 1689, 'Scan & Ride'); // Scan & Ride button
        await app.delay(3000);

        await app.takeScreenshot('after_scan_ride');

        // Return to main map
        await app.back();

        console.log('✅ Custom coordination flow completed!');

    } catch (error) {
        console.error('❌ Example failed:', error.message);
    }
}

// LLM-friendly template function
async function createCustomAutomation(description, steps) {
    console.log(`🤖 Custom Automation: ${description}`);

    try {
        await app.ensureAppStarted();

        for (let i = 0; i < steps.length; i++) {
            const step = steps[i];
            console.log(`Step ${i + 1}: ${step.description}`);

            // Execute the step
            if (typeof step.action === 'function') {
                await step.action();
            } else if (typeof step.action === 'string') {
                // Call method by name
                if (app[step.action]) {
                    await app[step.action](...step.args || []);
                } else {
                    console.log(`❌ Unknown action: ${step.action}`);
                }
            }

            // Take screenshot if requested
            if (step.screenshot) {
                await app.takeScreenshot(step.screenshot);
            }

            // Wait if specified
            if (step.wait) {
                await app.delay(step.wait);
            }
        }

        console.log('✅ Custom automation completed!');

    } catch (error) {
        console.error('❌ Custom automation failed:', error.message);
    }
}

// Example of LLM creating a custom automation
async function example7_LLMGeneratedAutomation() {
    const customSteps = [
        {
            description: 'Open the menu to access navigation options',
            action: 'openMenu',
            screenshot: 'menu_opened',
            wait: 2000
        },
        {
            description: 'Navigate to payment methods',
            action: 'openPaymentMethods',
            screenshot: 'payment_methods_opened',
            wait: 2000
        },
        {
            description: 'Go back to main menu',
            action: 'back',
            wait: 1000
        },
        {
            description: 'Close menu and return to main map',
            action: 'closeMenu',
            screenshot: 'back_to_main_map',
            wait: 2000
        },
        {
            description: 'Start ride flow',
            action: 'startRideFlow',
            screenshot: 'ride_started'
        }
    ];

    await createCustomAutomation(
        'LLM-Generated Payment and Ride Flow',
        customSteps
    );
}

// Export all examples for easy testing
module.exports = {
    example1_BasicVehicleUnlock,
    example2_CompleteRideFlow,
    example3_NavigationAndExploration,
    example4_SmartErrorRecovery,
    example5_StatusAwareAutomation,
    example6_CustomCoordinationFlow,
    example7_LLMGeneratedAutomation,
    createCustomAutomation
};

// If running directly, let user choose which example to run
if (require.main === module) {
    const args = process.argv.slice(2);
    const exampleNumber = args[0] || '1';

    const examples = {
        '1': example1_BasicVehicleUnlock,
        '2': example2_CompleteRideFlow,
        '3': example3_NavigationAndExploration,
        '4': example4_SmartErrorRecovery,
        '5': example5_StatusAwareAutomation,
        '6': example6_CustomCoordinationFlow,
        '7': example7_LLMGeneratedAutomation
    };

    if (examples[exampleNumber]) {
        examples[exampleNumber]().then(() => {
            console.log('Example completed');
            process.exit(0);
        }).catch(error => {
            console.error('Example failed:', error);
            process.exit(1);
        });
    } else {
        console.log('Available examples:');
        Object.keys(examples).forEach(key => {
            console.log(`  ${key}: example${key}_${examples[key].name}`);
        });
        console.log('Usage: node example_automations.js [example_number]');
        process.exit(1);
    }
}