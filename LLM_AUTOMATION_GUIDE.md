# MaynDrive LLM Automation Guide

This guide makes it incredibly easy for LLMs to create and execute MaynDrive app automation. The framework provides high-level, intuitive methods that handle all the complexity of screen detection, navigation, and error recovery.

## 🚀 Quick Start for LLMs

### 1. Basic Setup
```javascript
const MaynDriveAutomation = require('./mayndrive_automation_framework');

// Initialize the automation
const app = new MaynDriveAutomation({
    screenshotDir: './my_screenshots',
    logFile: './automation.log'
});
```

### 2. Essential Methods

#### App Management
- `await app.ensureAppStarted()` - Start the MaynDrive app
- `await app.getStatus()` - Get current screen and available actions

#### Login Actions (from LOGIN screen)
- `await app.enterEmail(email)` - Enter email in login field
- `await app.enterPassword(password)` - Enter password in login field
- `await app.clickLoginButton()` - Click "Se connecter" (Sign in) button
- `await app.clickForgotPassword()` - Click "Mot de passe oublié?" link
- `await app.performLogin(email, password)` - Complete login flow with validation

#### Main Actions (from MAIN_MAP screen)
- `await app.buyPass()` - Click "Buy a Pass" button
- `await app.scanRide()` - Open QR scanner for ride
- `await app.openMenu()` - Open navigation menu
- `await app.goToMyLocation()` - Go to current location on map
- `await app.toggleVehicles()` - Switch between vehicles/spots view
- `await app.selectVehicle()` - Select vehicle on map

#### Vehicle Actions
- `await app.unlockVehicle()` - Unlock vehicle (from vehicle panel)
- `await app.completeVehicleUnlockFlow()` - Full unlock sequence

#### Menu Actions
- `await app.closeMenu()` - Close navigation menu
- `await app.openPaymentMethods()` - Open payment methods screen
- `await app.openProfile()` - Open user profile

#### Compound Actions
- `await app.startRideFlow()` - Smart ride start (QR or vehicle)
- `await app.completeVehicleUnlockFlow()` - Full vehicle unlock

#### Navigation
- `await app.back()` - Go back to previous screen
- `await app.ensureScreen('SCREEN_NAME')` - Navigate to specific screen

## 🎯 Example Patterns for LLMs

### Pattern 1: Simple Action Sequence
```javascript
// Start app and perform basic actions
await app.ensureAppStarted();
await app.goToMyLocation();
await app.toggleVehicles();
await app.openMenu();
await app.openPaymentMethods();
```

### Pattern 2: Status-Aware Automation
```javascript
// Get current status and act accordingly
const status = await app.getStatus();
console.log('Current screen:', status.currentScreen);
console.log('Available actions:', status.availableActions);

if (status.currentScreen === 'MAIN_MAP') {
    await app.startRideFlow();
} else if (status.currentScreen === 'NAVIGATION_MENU') {
    await app.openPaymentMethods();
}
```

### Pattern 3: Error-Resistant Flow
```javascript
// The framework automatically handles screen navigation
await app.ensureAppStarted();

// This works regardless of current screen
const success = await app.unlockVehicle();

if (success) {
    console.log('Vehicle unlocked!');
} else {
    console.log('Unlock failed - trying alternative method');
    await app.scanRide();
}
```

### Pattern 4: Custom Step-by-Step
```javascript
// Custom automation with screenshots
await app.ensureAppStarted();
await app.takeScreenshot('start');

await app.openMenu();
await app.takeScreenshot('menu_opened');

await app.openPaymentMethods();
await app.takeScreenshot('payment_methods');

await app.back();
await app.closeMenu();
await app.takeScreenshot('back_to_map');
```

## 📱 Screen States

The framework automatically detects these screens:

- **LOGIN** - Login screen with email/password fields (French UI)
- **MAIN_MAP** - Main map with vehicle/pass buttons
- **VEHICLE_PANEL** - Vehicle details with unlock button
- **QR_SCANNER** - Camera view for QR code scanning
- **NAVIGATION_MENU** - Side menu with profile/payment options
- **PAYMENT_METHODS** - Payment method management screen

## 🔧 Advanced Features

### Custom Coordinates
```javascript
// Direct coordinate access
await app.tap(540, 1557, 'Buy a Pass button');
await app.tap(540, 1689, 'Scan & ride button');
await app.tap(77, 154, 'Menu button');
```

### Screenshot Documentation
```javascript
// Automatic screenshot with timestamp
const filepath = await app.takeScreenshot('my_action');
console.log('Screenshot saved:', filepath);
```

### Delay Management
```javascript
// Custom delays
await app.delay(5000); // Wait 5 seconds
```

### Error Handling
```javascript
try {
    await app.completeVehicleUnlockFlow();
    console.log('✅ Success!');
} catch (error) {
    console.log('❌ Error:', error.message);
    // Framework already attempted recovery
}
```

## 🤖 LLM Integration Template

```javascript
/**
 * Template for LLM-generated automation
 * Just replace the steps array with your desired actions
 */
async function createCustomAutomation(description, steps) {
    console.log(`🤖 Running: ${description}`);

    try {
        await app.ensureAppStarted();

        for (const step of steps) {
            console.log(`Step: ${step.description}`);

            // Execute action
            await app[step.action](...step.args || []);

            // Screenshot if requested
            if (step.screenshot) {
                await app.takeScreenshot(step.screenshot);
            }

            // Wait if specified
            if (step.wait) {
                await app.delay(step.wait);
            }
        }

        console.log('✅ Automation completed!');

    } catch (error) {
        console.error('❌ Failed:', error.message);
    }
}

// Example usage
const mySteps = [
    {
        description: 'Open the main menu',
        action: 'openMenu',
        screenshot: 'menu_opened',
        wait: 2000
    },
    {
        description: 'Navigate to payment methods',
        action: 'openPaymentMethods',
        screenshot: 'payment_methods'
    },
    {
        description: 'Return to main map',
        action: 'back',
        wait: 1000
    },
    {
        description: 'Close menu',
        action: 'closeMenu'
    },
    {
        description: 'Start a ride',
        action: 'startRideFlow',
        screenshot: 'ride_started'
    }
];

await createCustomAutomation('My Custom Automation', mySteps);
```

## 🎯 Common Use Cases

### 1. Login Flow
```javascript
await app.ensureAppStarted();
const status = await app.getStatus();

if (status.currentScreen === 'LOGIN') {
    await app.performLogin('user@example.com', 'password123');
    console.log('✅ Logged in successfully!');
}
```

### 2. Quick Ride Start (after login)
```javascript
await app.ensureAppStarted();
await app.performLogin('user@example.com', 'password123');
await app.startRideFlow();
```

### 3. Payment Method Check
```javascript
await app.ensureAppStarted();
await app.openMenu();
await app.openPaymentMethods();
await app.takeScreenshot('payment_status');
```

### 4. Vehicle Exploration
```javascript
await app.ensureAppStarted();
await app.goToMyLocation();
await app.toggleVehicles(); // Show vehicles
await app.selectVehicle(); // Open vehicle panel
await app.back(); // Return to map
```

### 5. App Navigation Test
```javascript
await app.ensureAppStarted();
const screens = ['MAIN_MAP', 'NAVIGATION_MENU', 'PAYMENT_METHODS'];

for (const screen of screens) {
    await app.ensureScreen(screen);
    await app.takeScreenshot(`screen_${screen.toLowerCase()}`);
    await app.delay(2000);
}
```

## 📊 Available Actions by Screen

The `getStatus()` method returns available actions for current screen:

- **LOGIN**: enterEmail(), enterPassword(), clickLoginButton(), clickForgotPassword(), performLogin()
- **MAIN_MAP**: buyPass(), scanRide(), openMenu(), goToMyLocation(), toggleVehicles(), selectVehicle()
- **VEHICLE_PANEL**: unlockVehicle(), back()
- **QR_SCANNER**: back()
- **NAVIGATION_MENU**: closeMenu(), openPaymentMethods(), openProfile()
- **PAYMENT_METHODS**: back()

## 🛡️ Safety Features

- **Automatic screen detection** - Knows where you are
- **Smart navigation** - Gets to required screen automatically
- **Error recovery** - Tries multiple approaches on failure
- **Logging** - Detailed action logs for debugging
- **Screenshots** - Visual documentation of every step

## 🚀 Getting Started

1. **Include the framework**: `const app = new MaynDriveAutomation();`
2. **Start the app**: `await app.ensureAppStarted();`
3. **Check status**: `const status = await app.getStatus();`
4. **Perform actions**: Use the high-level methods
5. **Document**: Take screenshots for verification

That's it! The framework handles all the complexity so you can focus on what you want to automate.