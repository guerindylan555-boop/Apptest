/**
 * Enhanced MaynDrive Automation Framework
 * Real-time state-aware automation with LLM-friendly interface
 */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

class EnhancedMaynDriveAutomation {
    constructor(options = {}) {
        this.config = {
            device: options.device || "emulator-5556",
            packageName: "fr.mayndrive.app",
            screenshotDir: options.screenshotDir || "./screenshots",
            logFile: options.logFile || "./automation.log",
            delays: {
                tap: options.tapDelay || 900,
                screenLoad: options.screenLoadDelay || 2000,
                api: options.apiDelay || 3000,
                input: options.inputDelay || 500
            }
        };

        // Current app state tracking
        this.currentState = {
            screen: 'UNKNOWN',
            isLoggedIn: false,
            availableActions: [],
            uiElements: {},
            lastUpdated: null
        };

        // Automation session tracking
        this.session = {
            id: Date.now(),
            startTime: new Date(),
            actions: [],
            screenshots: [],
            xmlDumps: [],
            errors: []
        };

        // Ensure screenshot directory exists
        if (!fs.existsSync(this.config.screenshotDir)) {
            fs.mkdirSync(this.config.screenshotDir, { recursive: true });
        }

        this.initializeLogging();
    }

    initializeLogging() {
        const timestamp = new Date().toISOString();
        const logHeader = `\n=== Enhanced MaynDrive Automation Session ===\nSession ID: ${this.session.id}\nStarted: ${timestamp}\nDevice: ${this.config.device}\n\n`;

        if (fs.existsSync(this.config.logFile)) {
            fs.appendFileSync(this.config.logFile, logHeader);
        } else {
            fs.writeFileSync(this.config.logFile, logHeader);
        }
    }

    log(message, level = 'INFO') {
        const timestamp = new Date().toISOString();
        const logEntry = `[${timestamp}] [${level}] ${message}\n`;
        fs.appendFileSync(this.config.logFile, logEntry);

        if (level === 'ERROR') {
            console.error(`❌ ${message}`);
        } else if (level === 'WARN') {
            console.warn(`⚠️ ${message}`);
        } else {
            console.log(`${message}`);
        }
    }

    async adb(command) {
        try {
            const fullCommand = `adb -s ${this.config.device} ${command}`;
            this.log(`Executing: ${fullCommand}`);
            const result = execSync(fullCommand, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
            return result.trim();
        } catch (error) {
            this.log(`ADB command failed: ${command} - ${error.message}`, 'ERROR');
            throw error;
        }
    }

    async getCurrentState() {
        try {
            // Get UI dump
            await this.adb('shell uiautomator dump');
            const xmlContent = await this.adb('shell cat /sdcard/window_dump.xml');

            // Analyze current state
            const state = this.analyzeUIState(xmlContent);

            // Update internal state
            this.currentState = {
                ...this.currentState,
                ...state,
                lastUpdated: new Date()
            };

            return this.currentState;
        } catch (error) {
            this.log(`Failed to get current state: ${error.message}`, 'ERROR');
            return this.currentState;
        }
    }

    analyzeUIState(xmlContent) {
        const state = {
            screen: 'UNKNOWN',
            isLoggedIn: false,
            availableActions: [],
            uiElements: {},
            confidence: 0
        };

        // Check for LOGIN screen patterns
        if (xmlContent.includes('Email') && xmlContent.includes('Password') && xmlContent.includes('Login')) {
            state.screen = 'LOGIN';
            state.isLoggedIn = false;
            state.availableActions = ['enterEmail', 'enterPassword', 'clickLoginButton', 'clickForgotPassword', 'performLogin'];
            state.confidence = 0.9;
        }
        // Check for MAIN_MAP with login required
        else if (xmlContent.includes('Login to rent') && xmlContent.includes('Buy a Pass')) {
            state.screen = 'MAIN_MAP';
            state.isLoggedIn = false;
            state.availableActions = ['openLoginSheet', 'enterLoginFlow'];
            state.confidence = 0.9;
        }
        // Check for authenticated MAIN_MAP
        else if (xmlContent.includes('Buy a Pass') && xmlContent.includes('Scan & ride') && !xmlContent.includes('Login to rent')) {
            state.screen = 'MAIN_MAP';
            state.isLoggedIn = true;
            state.availableActions = ['buyPass', 'scanRide', 'openMenu', 'goToMyLocation', 'toggleVehicles', 'selectVehicle'];
            state.confidence = 0.95;
        }
        // Check for consent screen
        else if (xmlContent.includes('Let\'s go') && xmlContent.includes('collect for improving')) {
            state.screen = 'CONSENT';
            state.isLoggedIn = false;
            state.availableActions = ['acceptConsent'];
            state.confidence = 0.9;
        }
        // Check for error dialogs
        else if (xmlContent.includes('An error occurred') && xmlContent.includes('It was reported')) {
            state.screen = 'ERROR_DIALOG';
            state.availableActions = ['dismissError'];
            state.confidence = 0.95;
        }
        // Check for login sheet
        else if (xmlContent.includes('Login') && xmlContent.includes('Signup') && xmlContent.includes('Cancel')) {
            state.screen = 'LOGIN_SHEET';
            state.isLoggedIn = false;
            state.availableActions = ['selectLogin', 'selectSignup', 'cancel'];
            state.confidence = 0.9;
        }
        // Check for QR scanner state (minimal UI with close and keyboard buttons)
        else if ((xmlContent.includes('Keyboard') || xmlContent.includes('Close')) &&
                 (xmlContent.includes('fr.mayndrive.app') && xmlContent.includes('Y1.r'))) {
            state.screen = 'QR_SCANNER';
            state.isLoggedIn = true; // Usually logged in when accessing QR scanner
            state.availableActions = ['closeScanner', 'openKeyboard', 'scanQR', 'goBack'];
            state.confidence = 0.85;
        }
        // Check for minimal UI state (likely QR scanner or camera view)
        else if (xmlContent.includes('fr.mayndrive.app') &&
                 xmlContent.includes('android.widget.FrameLayout') &&
                 !xmlContent.includes('Login') && !xmlContent.includes('Buy') &&
                 xmlContent.includes('Keyboard') && xmlContent.includes('Close')) {
            state.screen = 'QR_SCANNER';
            state.isLoggedIn = true;
            state.availableActions = ['closeScanner', 'openKeyboard', 'scanQR'];
            state.confidence = 0.8;
        }
        // Check for QR scanner
        else if (xmlContent.includes('camera') || xmlContent.includes('Scan QR')) {
            state.screen = 'QR_SCANNER';
            state.isLoggedIn = true;
            state.availableActions = ['back', 'scanQRCode'];
            state.confidence = 0.8;
        }
        // Check for navigation menu
        else if (xmlContent.includes('Profile') || xmlContent.includes('Payment methods')) {
            state.screen = 'NAVIGATION_MENU';
            state.isLoggedIn = true;
            state.availableActions = ['closeMenu', 'openPaymentMethods', 'openProfile'];
            state.confidence = 0.85;
        }

        return state;
    }

    async ensureAppState(targetState, options = {}) {
        this.log(`🎯 Ensuring app state: ${targetState}`);
        const currentState = await this.getCurrentState();

        this.log(`Current state: ${currentState.screen} (logged in: ${currentState.isLoggedIn})`);

        // If already in target state, return success
        if (this.isInTargetState(currentState, targetState)) {
            this.log(`✅ Already in target state: ${targetState}`);
            return true;
        }

        // Navigate to target state
        const navigationPath = this.getNavigationPath(currentState, targetState);
        this.log(`Navigation path: ${navigationPath.join(' → ')}`);

        for (const step of navigationPath) {
            const success = await this.executeNavigationStep(step, options);
            if (!success) {
                this.log(`❌ Failed to execute step: ${step}`, 'ERROR');
                return false;
            }
            await this.delay(this.config.delays.screenLoad);
        }

        // Verify final state
        const finalState = await this.getCurrentState();
        const success = this.isInTargetState(finalState, targetState);

        if (success) {
            this.log(`✅ Successfully reached target state: ${targetState}`);
        } else {
            this.log(`❌ Failed to reach target state. Current: ${finalState.screen}`, 'ERROR');
        }

        return success;
    }

    isInTargetState(currentState, targetState) {
        switch (targetState) {
            case 'LOGGED_IN':
                return currentState.isLoggedIn && currentState.screen === 'MAIN_MAP';
            case 'LOGGED_OUT':
                return !currentState.isLoggedIn || currentState.screen === 'LOGIN';
            case 'LOGIN_SCREEN':
                return currentState.screen === 'LOGIN';
            case 'MAIN_MAP':
                return currentState.screen === 'MAIN_MAP';
            case 'ANY':
                return true;
            default:
                return currentState.screen === targetState;
        }
    }

    getNavigationPath(currentState, targetState) {
        const path = [];

        // Handle special cases first
        if (targetState === 'LOGGED_IN' && !currentState.isLoggedIn) {
            // Need to login
            if (currentState.screen === 'ERROR_DIALOG') {
                path.push('dismissError');
            }
            if (currentState.screen === 'CONSENT') {
                path.push('acceptConsent');
            }
            if (currentState.screen !== 'LOGIN' && currentState.screen !== 'LOGIN_SHEET') {
                path.push('openLoginSheet');
            }
            if (currentState.screen !== 'LOGIN') {
                path.push('selectLogin');
            }
            path.push('performLogin');
            return path;
        }

        if (targetState === 'LOGGED_OUT' && currentState.isLoggedIn) {
            // For logout, we'll need to clear app data or navigate to logout
            path.push('logout');
            return path;
        }

        // Default navigation logic
        if (currentState.screen === 'ERROR_DIALOG') {
            path.push('dismissError');
        }

        if (currentState.screen === 'CONSENT') {
            path.push('acceptConsent');
        }

        if (targetState === 'LOGIN_SCREEN' && currentState.screen !== 'LOGIN') {
            path.push('openLoginSheet', 'selectLogin');
        }

        if (targetState === 'MAIN_MAP' && currentState.screen !== 'MAIN_MAP') {
            if (currentState.screen === 'LOGIN' || currentState.screen === 'LOGIN_SHEET') {
                // Need to complete login first
                path.push('performLogin');
            } else if (currentState.screen === 'QR_SCANNER' || currentState.screen === 'NAVIGATION_MENU') {
                path.push('back');
            }
        }

        return path;
    }

    async executeNavigationStep(step, options) {
        this.log(`🔄 Executing step: ${step}`);

        // Get state before action
        const beforeState = await this.getCurrentState();
        this.log(`📊 State before step: ${beforeState.screen} (logged in: ${beforeState.isLoggedIn})`);

        try {
            switch (step) {
                case 'acceptConsent':
                    await this.tap(540, 1667, "Let's go button");
                    break;
                case 'dismissError':
                    await this.tap(779, 1053, "Error dialog OK");
                    break;
                case 'openLoginSheet':
                    await this.tap(540, 1689, "Login to rent button");
                    break;
                case 'selectLogin':
                    await this.tap(540, 1348, "Login option");
                    break;
                case 'selectSignup':
                    await this.tap(540, 1502, "Signup option");
                    break;
                case 'cancel':
                    await this.tap(540, 1656, "Cancel button");
                    break;
                case 'performLogin':
                    if (options.credentials) {
                        await this.performLogin(options.credentials.email, options.credentials.password);
                    } else {
                        await this.performLogin('blhackapple@gmail.com', 'Yolo01610');
                    }
                    break;
                case 'logout':
                    await this.logout();
                    break;
                case 'back':
                    await this.back();
                    break;
                default:
                    this.log(`Unknown navigation step: ${step}`, 'WARN');
                    return false;
            }

            // Comprehensive state review after action
            await this.reviewStateAfterAction(step, beforeState);

            return true;
        } catch (error) {
            this.log(`Navigation step failed: ${step} - ${error.message}`, 'ERROR');
            await this.reviewStateAfterAction(step, beforeState, true);
            return false;
        }
    }

    async reviewStateAfterAction(step, beforeState, hadError = false) {
        this.log(`🔍 Reviewing state after step: ${step}`);

        // Take screenshot for visual verification
        const screenshotName = `step_${step.replace(/[^a-zA-Z0-9]/g, '_')}_review`;
        await this.takeScreenshot(screenshotName);

        // Wait for UI to settle
        await this.delay(this.config.delays.screenLoad);

        // Dump UI XML for detailed review
        const xmlDumpName = `step_${step.replace(/[^a-zA-Z0-9]/g, '_')}_review.xml`;
        await this.dumpUIXML(xmlDumpName);

        // Get updated state
        const afterState = await this.getCurrentState();
        this.log(`📊 State after step: ${afterState.screen} (logged in: ${afterState.isLoggedIn})`);
        this.log(`📊 Available actions: ${afterState.availableActions.join(', ')}`);
        this.log(`📊 Confidence: ${afterState.confidence}`);

        // Log UI dump location for manual review
        this.log(`📁 UI XML saved: ${xmlDumpName}`);
        this.log(`📁 Screenshot saved: ${screenshotName}.png`);

        // Analyze state changes
        const stateAnalysis = this.analyzeStateChange(beforeState, afterState, step);
        this.log(stateAnalysis.summary);

        // Validate expected transitions
        const validation = this.validateStateTransition(step, beforeState, afterState);
        if (!validation.success) {
            this.log(`⚠️ State transition validation: ${validation.message}`, 'WARN');
        } else {
            this.log(`✅ State transition validation: ${validation.message}`);
        }

        // Check for unexpected states or errors
        if (afterState.screen === 'ERROR_DIALOG') {
            this.log(`🚨 Error dialog detected after step: ${step}`, 'WARN');
            await this.takeScreenshot(`${screenshotName}_error_dialog`);
        }

        // Log detailed state comparison if significant change
        if (stateAnalysis.significantChange) {
            this.log(`🔄 State changed significantly:`);
            this.log(`   Screen: ${beforeState.screen} → ${afterState.screen}`);
            this.log(`   Login: ${beforeState.isLoggedIn} → ${afterState.isLoggedIn}`);
            this.log(`   Actions: ${beforeState.availableActions.length} → ${afterState.availableActions.length}`);
        }

        // Return state analysis for potential adaptive behavior
        return {
            beforeState,
            afterState,
            analysis: stateAnalysis,
            validation,
            hadError
        };
    }

    analyzeStateChange(beforeState, afterState, step) {
        const analysis = {
            screenChanged: beforeState.screen !== afterState.screen,
            loginChanged: beforeState.isLoggedIn !== afterState.isLoggedIn,
            actionsChanged: beforeState.availableActions.length !== afterState.availableActions.length,
            confidenceChanged: Math.abs(beforeState.confidence - afterState.confidence) > 0.1,
            significantChange: false
        };

        analysis.significantChange = analysis.screenChanged || analysis.loginChanged;

        let summary = `State analysis after "${step}": `;
        const changes = [];

        if (analysis.screenChanged) {
            changes.push(`screen ${beforeState.screen} → ${afterState.screen}`);
        }
        if (analysis.loginChanged) {
            changes.push(`login ${beforeState.isLoggedIn} → ${afterState.isLoggedIn}`);
        }
        if (analysis.actionsChanged) {
            changes.push(`actions ${beforeState.availableActions.length} → ${afterState.availableActions.length}`);
        }

        summary += changes.length > 0 ? changes.join(', ') : 'no significant changes';

        return analysis;
    }

    validateStateTransition(step, beforeState, afterState) {
        const validation = {
            success: true,
            message: 'Transition valid'
        };

        // Define expected transitions for each step
        const expectedTransitions = {
            'acceptConsent': {
                from: ['CONSENT', 'ERROR_DIALOG'],
                to: ['MAIN_MAP', 'UNKNOWN']
            },
            'dismissError': {
                from: ['ERROR_DIALOG'],
                to: ['MAIN_MAP', 'LOGIN', 'CONSENT', 'UNKNOWN']
            },
            'openLoginSheet': {
                from: ['MAIN_MAP'],
                to: ['LOGIN_SHEET', 'LOGIN', 'UNKNOWN']
            },
            'selectLogin': {
                from: ['LOGIN_SHEET'],
                to: ['LOGIN', 'UNKNOWN']
            },
            'selectSignup': {
                from: ['LOGIN_SHEET'],
                to: ['SIGNUP', 'UNKNOWN']
            },
            'cancel': {
                from: ['LOGIN_SHEET'],
                to: ['MAIN_MAP', 'UNKNOWN']
            },
            'performLogin': {
                from: ['LOGIN'],
                to: ['MAIN_MAP', 'ERROR_DIALOG', 'UNKNOWN']
            },
            'logout': {
                from: ['MAIN_MAP', 'NAVIGATION_MENU', 'QR_SCANNER'],
                to: ['LOGIN', 'CONSENT', 'UNKNOWN']
            },
            'back': {
                from: ['QR_SCANNER', 'NAVIGATION_MENU', 'PAYMENT_METHODS'],
                to: ['MAIN_MAP', 'UNKNOWN']
            }
        };

        const expected = expectedTransitions[step];
        if (expected) {
            const fromValid = expected.from.includes(beforeState.screen) || expected.from.includes('UNKNOWN');
            const toValid = expected.to.includes(afterState.screen) || expected.to.includes('UNKNOWN');

            if (!fromValid) {
                validation.success = false;
                validation.message = `Unexpected "from" state: ${beforeState.screen} (expected: ${expected.from.join(' or ')})`;
            } else if (!toValid) {
                validation.success = false;
                validation.message = `Unexpected "to" state: ${afterState.screen} (expected: ${expected.to.join(' or ')})`;
            } else {
                validation.message = `Valid transition: ${beforeState.screen} → ${afterState.screen}`;
            }
        } else {
            validation.message = `No validation rules for step: ${step}`;
        }

        return validation;
    }

    async performLogin(email, password) {
        this.log(`🔐 Performing login for: ${email}`);

        try {
            // Enter email
            await this.tap(540, 407, "Email field");
            await this.delay(this.config.delays.input);
            await this.adb(`shell input text "${email}"`);
            await this.delay(this.config.delays.input);

            // Enter password
            await this.tap(540, 638, "Password field");
            await this.delay(this.config.delays.input);
            await this.adb(`shell input text "${password}"`);
            await this.delay(this.config.delays.input);

            // Submit login
            await this.tap(540, 1067, "Login button");
            await this.delay(this.config.delays.api);

            // Handle post-login error if present
            await this.delay(2000);
            const state = await this.getCurrentState();
            if (state.screen === 'ERROR_DIALOG') {
                await this.tap(779, 1053, "Post-login error dialog");
                await this.delay(this.config.delays.screenLoad);
            }

            // Verify login success
            const finalState = await this.getCurrentState();
            return finalState.isLoggedIn;

        } catch (error) {
            this.log(`Login failed: ${error.message}`, 'ERROR');
            return false;
        }
    }

    async logout() {
        this.log('🚪 Logging out...');

        try {
            // Clear app data to logout
            await this.adb(`shell pm clear ${this.config.packageName}`);
            await this.delay(this.config.delays.screenLoad * 2);

            // Update state
            await this.getCurrentState();
            return true;
        } catch (error) {
            this.log(`Logout failed: ${error.message}`, 'ERROR');
            return false;
        }
    }

    async tap(x, y, description) {
        this.log(`👆 Tap at (${x}, ${y}) - ${description}`);
        try {
            await this.adb(`shell input tap ${x} ${y}`);
            await this.delay(this.config.delays.tap);

            // Track action
            this.session.actions.push({
                type: 'tap',
                coordinates: { x, y },
                description,
                timestamp: new Date()
            });

            return true;
        } catch (error) {
            this.log(`Tap failed at (${x}, ${y}) - ${error.message}`, 'ERROR');
            return false;
        }
    }

    async back() {
        this.log('⬅️ Pressing back button');
        try {
            await this.adb('shell input keyevent KEYCODE_BACK');
            await this.delay(this.config.delays.screenLoad);
            return true;
        } catch (error) {
            this.log(`Back button failed: ${error.message}`, 'ERROR');
            return false;
        }
    }

    async delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async takeScreenshot(name) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `${name}_${timestamp}.png`;
        const devicePath = `/sdcard/${filename}`;
        const localPath = path.join(this.config.screenshotDir, filename);

        try {
            await this.adb(`shell screencap -p ${devicePath}`);
            await this.adb(`pull ${devicePath} "${localPath}"`);
            await this.adb(`shell rm ${devicePath}`);

            this.log(`📸 Screenshot saved: ${localPath}`);

            // Track screenshot
            this.session.screenshots.push({
                name,
                filename,
                path: localPath,
                timestamp: new Date(),
                state: { ...this.currentState }
            });

            return localPath;
        } catch (error) {
            this.log(`Screenshot failed: ${error.message}`, 'ERROR');
            return null;
        }
    }

    async dumpUIXML(name) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `${name}_${timestamp}.xml`;
        const devicePath = `/sdcard/${filename}`;
        const localPath = path.join(this.config.screenshotDir, filename);

        try {
            await this.adb(`shell uiautomator dump`);
            await this.adb(`pull /sdcard/window_dump.xml "${localPath}"`);

            this.log(`📄 UI XML saved: ${localPath}`);

            // Track XML dump
            this.session.xmlDumps = this.session.xmlDumps || [];
            this.session.xmlDumps.push({
                name,
                filename,
                path: localPath,
                timestamp: new Date(),
                state: { ...this.currentState }
            });

            return localPath;
        } catch (error) {
            this.log(`UI XML dump failed: ${error.message}`, 'ERROR');
            return null;
        }
    }

    // LLM-friendly automation methods
    async createAutomationPlan(goal, options = {}) {
        this.log(`🎯 Creating automation plan for: ${goal}`);

        const plan = {
            goal,
            steps: [],
            currentState: await this.getCurrentState(),
            estimatedTime: 0,
            requirements: []
        };

        switch (goal.toLowerCase()) {
            case 'login':
                if (plan.currentState.isLoggedIn) {
                    plan.steps.push('Already logged in - no action needed');
                } else {
                    plan.steps.push('Ensure app is in login state');
                    plan.steps.push('Enter credentials');
                    plan.steps.push('Submit login');
                    plan.steps.push('Verify login success');
                }
                plan.requirements = ['Credentials: email and password'];
                plan.estimatedTime = 10000;
                break;

            case 'logout':
                if (!plan.currentState.isLoggedIn) {
                    plan.steps.push('Already logged out - no action needed');
                } else {
                    plan.steps.push('Clear app data to logout');
                    plan.steps.push('Verify logout success');
                }
                plan.estimatedTime = 5000;
                break;

            case 'start_ride':
                plan.steps.push('Ensure logged in');
                plan.steps.push('Navigate to main map');
                plan.steps.push('Click "Scan & ride" or select vehicle');
                plan.steps.push('Complete ride start flow');
                plan.requirements = ['Logged in state'];
                plan.estimatedTime = 15000;
                break;

            case 'buy_pass':
                plan.steps.push('Ensure logged in');
                plan.steps.push('Navigate to main map');
                plan.steps.push('Click "Buy a Pass" button');
                plan.steps.push('Complete purchase flow');
                plan.requirements = ['Logged in state', 'Payment method'];
                plan.estimatedTime = 20000;
                break;

            default:
                plan.steps.push(`Unknown goal: ${goal}`);
                plan.estimatedTime = 0;
        }

        return plan;
    }

    async executeAutomationPlan(plan, options = {}) {
        this.log(`🚀 Executing automation plan: ${plan.goal}`);
        this.log(`📋 Plan has ${plan.steps.length} steps, estimated time: ${plan.estimatedTime}ms`);

        const results = {
            totalSteps: plan.steps.length,
            completedSteps: 0,
            successfulSteps: 0,
            failedSteps: 0,
            stepResults: []
        };

        for (let i = 0; i < plan.steps.length; i++) {
            const step = plan.steps[i];
            this.log(`\n📍 Step ${i + 1}/${plan.steps.length}: ${step}`);

            // Get state before step
            const beforeState = await this.getCurrentState();
            this.log(`📊 State before step ${i + 1}: ${beforeState.screen} (logged in: ${beforeState.isLoggedIn})`);

            // Skip descriptive steps
            if (step.includes('no action needed')) {
                this.log(`✅ Step ${i + 1} skipped: ${step}`);
                results.completedSteps++;
                results.successfulSteps++;
                results.stepResults.push({
                    stepNumber: i + 1,
                    step,
                    skipped: true,
                    reason: 'No action needed'
                });
                continue;
            }

            let success = false;
            let error = null;

            try {
                // Execute step based on description
                if (step.includes('Ensure logged in')) {
                    success = await this.ensureAppState('LOGGED_IN', options);
                } else if (step.includes('Ensure app is in login state')) {
                    success = await this.ensureAppState('LOGIN_SCREEN', options);
                } else if (step.includes('Navigate to main map')) {
                    success = await this.ensureAppState('MAIN_MAP', options);
                } else if (step.includes('Click "Buy a Pass"')) {
                    success = await this.tap(540, 1557, "Buy a Pass button");
                    // Review state after tap
                    await this.reviewStateAfterAction(`plan_step_${i + 1}_buy_pass`, beforeState);
                } else if (step.includes('Click "Scan & ride"')) {
                    success = await this.tap(540, 1689, "Scan & ride button");
                    // Review state after tap
                    await this.reviewStateAfterAction(`plan_step_${i + 1}_scan_ride`, beforeState);
                } else if (step.includes('Clear app data')) {
                    success = await this.logout();
                } else if (step.includes('Verify')) {
                    const state = await this.getCurrentState();
                    success = step.includes('login') ? state.isLoggedIn : !state.isLoggedIn;

                    // Review verification result
                    this.log(`🔍 Verification result: ${success ? '✅ PASSED' : '❌ FAILED'}`);
                    this.log(`📊 State during verification: ${state.screen} (logged in: ${state.isLoggedIn})`);
                } else {
                    this.log(`⚠️ Unknown step format: ${step}`, 'WARN');
                    success = true; // Don't fail for unknown steps
                }

                results.completedSteps++;
                if (success) {
                    results.successfulSteps++;
                } else {
                    results.failedSteps++;
                }

            } catch (err) {
                error = err;
                results.completedSteps++;
                results.failedSteps++;
                this.log(`❌ Step ${i + 1} failed with error: ${err.message}`, 'ERROR');
            }

            // Record step result
            results.stepResults.push({
                stepNumber: i + 1,
                step,
                success,
                error: error ? error.message : null,
                beforeState,
                afterState: await this.getCurrentState()
            });

            // Take final screenshot for step
            await this.takeScreenshot(`plan_step_${i + 1}_${step.replace(/[^a-zA-Z0-9]/g, '_')}_final`);

            // Report step completion
            const status = success ? '✅ COMPLETED' : '❌ FAILED';
            this.log(`${status} Step ${i + 1}: ${step}`);

            // Stop execution if critical step failed
            if (!success && this.isCriticalStep(step)) {
                this.log(`🛑 Critical step failed, stopping automation plan execution`, 'ERROR');
                break;
            }
        }

        // Final plan completion summary
        this.log(`\n📊 Automation Plan Execution Summary`);
        this.log(`====================================`);
        this.log(`Goal: ${plan.goal}`);
        this.log(`Total steps: ${results.totalSteps}`);
        this.log(`Completed: ${results.completedSteps}`);
        this.log(`Successful: ${results.successfulSteps}`);
        this.log(`Failed: ${results.failedSteps}`);
        this.log(`Success rate: ${Math.round((results.successfulSteps / results.completedSteps) * 100)}%`);

        // Get final state
        const finalState = await this.getCurrentState();
        this.log(`Final state: ${finalState.screen} (logged in: ${finalState.isLoggedIn})`);

        const overallSuccess = results.failedSteps === 0 ||
                             (!this.isGoalCritical(plan.goal) && results.successfulSteps > 0);

        if (overallSuccess) {
            this.log(`\n✅ Automation plan completed successfully: ${plan.goal}`);
        } else {
            this.log(`\n❌ Automation plan failed: ${plan.goal}`);
        }

        return overallSuccess;
    }

    isCriticalStep(step) {
        const criticalPatterns = [
            'Ensure logged in',
            'Enter credentials',
            'Submit login',
            'Clear app data'
        ];
        return criticalPatterns.some(pattern => step.includes(pattern));
    }

    isGoalCritical(goal) {
        const criticalGoals = ['login', 'logout'];
        return criticalGoals.includes(goal.toLowerCase());
    }

    // Convenience methods for common automation tasks
    async smartLogin(credentials) {
        const currentState = await this.getCurrentState();

        if (currentState.isLoggedIn) {
            this.log('✅ Already logged in');
            return true;
        }

        return await this.ensureAppState('LOGGED_IN', { credentials });
    }

    async smartLogout() {
        const currentState = await this.getCurrentState();

        if (!currentState.isLoggedIn) {
            this.log('✅ Already logged out');
            return true;
        }

        return await this.ensureAppState('LOGGED_OUT');
    }

    async ensureReadyForRide() {
        return await this.ensureAppState('LOGGED_IN');
    }

    getStatus() {
        return this.currentState;
    }

    getSessionSummary() {
        return {
            sessionId: this.session.id,
            startTime: this.session.startTime,
            duration: Date.now() - this.session.startTime,
            actions: this.session.actions.length,
            screenshots: this.session.screenshots.length,
            xmlDumps: this.session.xmlDumps ? this.session.xmlDumps.length : 0,
            errors: this.session.errors.length,
            currentState: this.currentState
        };
    }
}

module.exports = EnhancedMaynDriveAutomation;