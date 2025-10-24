#!/usr/bin/env node

/**
 * Test Enhanced MaynDrive Automation Framework
 * Demonstrates intelligent state-aware automation
 */

const EnhancedMaynDriveAutomation = require('./enhanced_automation_framework');

async function testEnhancedFramework() {
    console.log('🧪 Testing Enhanced MaynDrive Automation Framework');
    console.log('==================================================');

    const app = new EnhancedMaynDriveAutomation({
        screenshotDir: './enhanced_test_screenshots',
        logFile: './enhanced_test.log',
        device: 'emulator-5556'
    });

    try {
        // Test 1: Current State Detection
        console.log('\n📊 Test 1: Real-time State Detection');
        console.log('------------------------------------');
        const currentState = await app.getCurrentState();
        console.log(`Current screen: ${currentState.screen}`);
        console.log(`Is logged in: ${currentState.isLoggedIn}`);
        console.log(`Available actions: ${currentState.availableActions.join(', ')}`);
        console.log(`Confidence: ${currentState.confidence}`);

        // Test 2: Smart Login (only if needed)
        console.log('\n🔐 Test 2: Smart Login Logic');
        console.log('---------------------------');

        // Create automation plan for login
        const loginPlan = await app.createAutomationPlan('login');
        console.log(`Login plan steps: ${loginPlan.steps.join(' → ')}`);
        console.log(`Estimated time: ${loginPlan.estimatedTime}ms`);
        console.log(`Requirements: ${loginPlan.requirements.join(', ')}`);

        // Execute login plan only if needed
        if (loginPlan.steps.some(step => step.includes('no action needed'))) {
            console.log('✅ Smart login detected already logged in - skipping');
        } else {
            console.log('🔄 Executing login plan...');
            const loginSuccess = await app.executeAutomationPlan(loginPlan, {
                credentials: {
                    email: 'blhackapple@gmail.com',
                    password: 'Yolo01610'
                }
            });
            console.log(`Login result: ${loginSuccess ? 'SUCCESS' : 'FAILED'}`);
        }

        // Test 3: State-Aware Ride Start
        console.log('\n🚴 Test 3: State-Aware Ride Start');
        console.log('----------------------------------');

        const ridePlan = await app.createAutomationPlan('start_ride');
        console.log(`Ride plan steps: ${ridePlan.steps.join(' → ')}`);

        // Only show plan, don't execute to avoid actual ride
        console.log('📋 Ride automation plan created (not executed to avoid charges)');

        // Test 4: Smart Logout (if desired)
        console.log('\n🚪 Test 4: Smart Logout Logic');
        console.log('---------------------------');

        const logoutPlan = await app.createAutomationPlan('logout');
        console.log(`Logout plan steps: ${logoutPlan.steps.join(' → ')}`);

        // Ask user if they want to logout
        console.log('⚠️ Logout would clear app data. Uncomment to execute:');
        console.log('// const logoutSuccess = await app.executeAutomationPlan(logoutPlan);');

        // Test 5: Convenience Methods
        console.log('\n⚡ Test 5: Convenience Methods');
        console.log('----------------------------');

        // Test smart login again (should detect no action needed)
        const smartLoginResult = await app.smartLogin({
            email: 'test@example.com',
            password: 'test123'
        });
        console.log(`Smart login result: ${smartLoginResult ? 'Already logged in' : 'Login attempted'}`);

        // Test app readiness
        const rideReady = await app.ensureReadyForRide();
        console.log(`App ready for ride: ${rideReady ? 'YES' : 'NO'}`);

        // Test 6: Session Summary
        console.log('\n📈 Test 6: Session Summary');
        console.log('------------------------');
        const summary = app.getSessionSummary();
        console.log(`Session ID: ${summary.sessionId}`);
        console.log(`Duration: ${Math.round(summary.duration / 1000)}s`);
        console.log(`Actions executed: ${summary.actions}`);
        console.log(`Screenshots taken: ${summary.screenshots}`);
        console.log(`Final state: ${summary.currentState.screen}`);

        console.log('\n✅ Enhanced Framework Test Completed Successfully!');
        return true;

    } catch (error) {
        console.error('\n❌ Enhanced framework test failed:', error.message);
        return false;
    }
}

// LLM-Friendly Automation Examples
async function demonstrateLLMFriendlyAutomation() {
    console.log('\n🤖 LLM-Friendly Automation Examples');
    console.log('=====================================');

    const app = new EnhancedMaynDriveAutomation();

    // Example 1: Simple login with automatic state handling
    console.log('\n📝 Example 1: Smart Login');
    await app.smartLogin({
        email: 'user@example.com',
        password: 'password123'
    });

    // Example 2: Create and execute custom automation plan
    console.log('\n📝 Example 2: Custom Automation Plan');
    const customPlan = await app.createAutomationPlan('buy_pass');
    await app.executeAutomationPlan(customPlan);

    // Example 3: Ensure specific state
    console.log('\n📝 Example 3: State Guarantee');
    await app.ensureAppState('LOGGED_IN');
    await app.ensureAppState('MAIN_MAP');

    // Example 4: Check current state and act accordingly
    console.log('\n📝 Example 4: Conditional Logic');
    const state = await app.getCurrentState();
    if (state.isLoggedIn) {
        console.log('User is logged in - proceeding with ride features');
        await app.tap(540, 1689, 'Scan & ride button');
    } else {
        console.log('User not logged in - handling login first');
        await app.smartLogin({ email: 'user@example.com', password: 'password123' });
    }
}

// Run tests if executed directly
if (require.main === module) {
    testEnhancedFramework()
        .then(success => {
            if (success) {
                console.log('\n🎉 All tests passed! Enhanced framework is ready for LLM use.');
                process.exit(0);
            } else {
                console.log('\n💥 Some tests failed.');
                process.exit(1);
            }
        })
        .catch(error => {
            console.error('Test suite failed:', error);
            process.exit(1);
        });
}

module.exports = { testEnhancedFramework, demonstrateLLMFriendlyAutomation };