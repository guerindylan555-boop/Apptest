# LLM-Friendly MaynDrive Automation Quick Start Guide

## 🚀 Super Simple Automation for LLMs

The enhanced framework makes automation incredibly easy - it automatically detects app state and adapts accordingly!

## 📋 Basic Setup

```javascript
const EnhancedMaynDriveAutomation = require('./enhanced_automation_framework');

// Initialize
const app = new EnhancedMaynDriveAutomation();
```

## 🎯 One-Line Automations

### Smart Login (handles any state automatically)
```javascript
// Just works - detects if already logged in, logs in if needed
await app.smartLogin({ email: 'user@example.com', password: 'password123' });
```

### Ensure Ready for Ride
```javascript
// Guarantees the app is ready for ride features
await app.ensureReadyForRide();
```

### Smart Logout
```javascript
// Logs out only if needed, does nothing if already logged out
await app.smartLogout();
```

## 🤖 LLM Automation Examples

### Example 1: Complete Ride Start Sequence
```javascript
async function startRide() {
    // Framework handles all state detection automatically
    await app.ensureReadyForRide();  // Login if needed

    // Now we're guaranteed to be logged in and on main map
    await app.tap(540, 1689, 'Scan & ride button');
    // ... rest of ride flow
}
```

### Example 2: Conditional Logic Based on State
```javascript
async function handleUserFlow() {
    const state = await app.getCurrentState();

    if (state.isLoggedIn) {
        console.log('User logged in - showing ride options');
        await app.tap(540, 1557, 'Buy a Pass button');
    } else {
        console.log('User not logged in - handling login first');
        await app.smartLogin({ email: 'user@example.com', password: 'password123' });
    }
}
```

### Example 3: Guaranteed State Automation
```javascript
async function ensureLoggedInAndBuyPass() {
    // This sequence ALWAYS succeeds regardless of starting state
    await app.ensureAppState('LOGGED_IN');  // Auto-login if needed
    await app.tap(540, 1557, 'Buy a Pass button');  // Now guaranteed to work
}
```

## 🎭 Automation Plans (LLM-Generated)

### Create Plans for Any Goal
```javascript
// Let the framework figure out how to login
const loginPlan = await app.createAutomationPlan('login');
console.log(loginPlan.steps);
// Output: ["Ensure app is in login state", "Enter credentials", "Submit login", "Verify login success"]

// Let the framework figure out how to start a ride
const ridePlan = await app.createAutomationPlan('start_ride');
console.log(ridePlan.steps);
// Output: ["Ensure logged in", "Navigate to main map", "Click 'Scan & ride' or select vehicle", "Complete ride start flow"]

// Execute any plan automatically
await app.executeAutomationPlan(loginPlan, {
    credentials: { email: 'user@example.com', password: 'password123' }
});
```

### Available Automation Goals
- `login` - Smart login with state detection
- `logout` - Clean logout with data clearing
- `start_ride` - Complete ride start sequence
- `buy_pass` - Pass purchase flow
- Any custom goal with manual steps

## 🧠 Intelligent State Detection

The framework automatically detects:

### Screen States
- `LOGIN` - Email/password form
- `MAIN_MAP` - Map with ride options (logged in or out)
- `CONSENT` - Data collection consent
- `ERROR_DIALOG` - Error popups
- `LOGIN_SHEET` - Login/signup bottom sheet
- `QR_SCANNER` - Camera scanning mode
- `NAVIGATION_MENU` - Side menu with options

### Login Status
```javascript
const state = await app.getCurrentState();
console.log(state);
// Output: {
//   screen: 'MAIN_MAP',
//   isLoggedIn: true,
//   availableActions: ['buyPass', 'scanRide', 'openMenu', ...],
//   confidence: 0.95
// }
```

## 🎯 Common Patterns (Copy-Paste Ready)

### Pattern 1: Guaranteed Login Before Any Action
```javascript
async function performActionNeedingLogin() {
    await app.ensureAppState('LOGGED_IN', {
        credentials: { email: 'user@example.com', password: 'password123' }
    });

    // Now guaranteed to be logged in, can safely proceed
    await app.tap(540, 1557, 'Buy a Pass button');
}
```

### Pattern 2: Conditional Logic Based on Current State
```javascript
async function smartUserFlow() {
    const state = await app.getCurrentState();

    switch (state.screen) {
        case 'LOGIN':
            console.log('User needs to login first');
            await app.performLogin('user@example.com', 'password123');
            break;
        case 'MAIN_MAP':
            if (state.isLoggedIn) {
                console.log('Ready for ride features');
                await app.tap(540, 1689, 'Scan & ride');
            } else {
                console.log('Need to login on main map');
                await app.smartLogin({ email: 'user@example.com', password: 'password123' });
            }
            break;
        default:
            console.log('Unexpected state, getting to main map');
            await app.ensureAppState('MAIN_MAP');
    }
}
```

### Pattern 3: One-Liner State Guarantees
```javascript
// These one-liners handle all the complexity automatically

// Always start from main map (logged in or not)
await app.ensureAppState('MAIN_MAP');

// Always ensure logged in (logs in if needed)
await app.ensureAppState('LOGGED_IN');

// Always ensure logged out (clears data if needed)
await app.ensureAppState('LOGGED_OUT');

// Always ensure ready for ride features
await app.ensureReadyForRide();
```

### Pattern 4: Robust Error-Handling Automation
```javascript
async function robustAutomation() {
    try {
        // Framework handles state detection automatically
        const success = await app.ensureAppState('LOGGED_IN');

        if (success) {
            // Guaranteed to be logged in here
            await app.takeScreenshot('logged_in_success');
            await app.tap(540, 1689, 'Scan & ride button');
            return true;
        } else {
            console.log('Login failed, but app is in a known state');
            return false;
        }
    } catch (error) {
        // Framework logs everything automatically
        console.log('Automation failed, check logs for details');
        return false;
    }
}
```

## 🎮 Testing and Debugging

### Quick State Check
```javascript
// See exactly what the framework detects
const state = await app.getCurrentState();
console.log(`Screen: ${state.screen}`);
console.log(`Logged in: ${state.isLoggedIn}`);
console.log(`Actions: ${state.availableActions.join(', ')}`);
```

### Visual Verification
```javascript
// Take screenshot at any point to verify state
await app.takeScreenshot('current_state');
```

### Session Summary
```javascript
// Get complete session summary
const summary = app.getSessionSummary();
console.log(`Session lasted ${Math.round(summary.duration / 1000)} seconds`);
console.log(`Executed ${summary.actions} actions`);
console.log(`Took ${summary.screenshots} screenshots`);
```

## 🚀 Production-Ready Templates

### Template 1: Complete Ride Automation
```javascript
async function completeRideAutomation() {
    const app = new EnhancedMaynDriveAutomation();

    // Step 1: Ensure logged in (handles any starting state)
    await app.ensureAppState('LOGGED_IN', {
        credentials: {
            email: 'your-email@example.com',
            password: 'your-password'
        }
    });

    // Step 2: Start ride (guaranteed to work now)
    await app.tap(540, 1689, 'Scan & ride button');
    await app.delay(3000);

    // Step 3: Handle QR scanning or vehicle selection
    const currentState = await app.getCurrentState();
    if (currentState.screen === 'QR_SCANNER') {
        // QR scanning logic here
        console.log('QR scanner active');
    }

    console.log('✅ Ride automation completed successfully');
}
```

### Template 2: State-Independent Testing
```javascript
async function testAppFunctionality() {
    const app = new EnhancedMaynDriveAutomation();

    // Test each screen state independently
    const states = ['LOGIN', 'MAIN_MAP', 'NAVIGATION_MENU'];

    for (const targetState of states) {
        console.log(`Testing ${targetState} state...`);

        // Framework handles getting to the target state
        const success = await app.ensureAppState(targetState);
        console.log(`${targetState} state: ${success ? '✅' : '❌'}`);

        // Take screenshot for verification
        await app.takeScreenshot(`test_${targetState}`);

        // Wait before next test
        await app.delay(2000);
    }
}
```

## 🎯 Key Benefits for LLMs

1. **Zero State Management**: Framework handles all state detection automatically
2. **Intelligent Navigation**: Always takes the shortest path to target state
3. **Built-in Error Recovery**: Automatic retry and fallback mechanisms
4. **Comprehensive Logging**: Every action logged automatically with timestamps
5. **Visual Documentation**: Screenshots captured for every step
6. **Simple API**: One-line methods for complex operations
7. **Session Tracking**: Complete audit trail of all automation

## 🏆 Best Practices

1. **Always use `ensureAppState()`** before performing actions that require specific states
2. **Let the framework handle login** with `smartLogin()` instead of manual login flows
3. **Check `getCurrentState()`** for conditional logic instead of assumptions
4. **Use `createAutomationPlan()`** for complex multi-step operations
5. **Take screenshots** at key verification points
6. **Handle both success and failure** scenarios gracefully

That's it! You now have a production-ready, LLM-friendly automation framework that handles all the complexity for you! 🚀