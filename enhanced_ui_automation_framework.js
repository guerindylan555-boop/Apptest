#!/usr/bin/env node

/**
 * Enhanced UI Automation Framework for MaynDrive
 *
 * This framework combines UI element discovery with intelligent targeting
 * to create robust, maintainable automation that adapts to UI changes.
 *
 * Features:
 * - Dynamic element detection using multiple strategies
 * - State-based navigation and validation
 * - Intelligent timing and error recovery
 * - Comprehensive logging and debugging
 * - Configuration-driven approach
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Configuration
const CONFIG = {
    device: {
        serial: process.env.EMULATOR_SERIAL || process.env.ADB_SERIAL || 'emulator-5554',
        timeout: 10000,
        retryAttempts: 3,
        retryDelay: 1000
    },
    app: {
        package: 'fr.mayndrive.app',
        mainActivity: 'city.knot.knotapp.ui.MainActivity'
    },
    timing: {
        fast: { delay: 500, timeout: 5000 },
        normal: { delay: 1000, timeout: 10000 },
        slow: { delay: 2000, timeout: 15000 }
    },
    credentials: {
        email: process.env.MAYNDRIVE_EMAIL || 'blhackapple@gmail.com',
        password: process.env.MAYNDRIVE_PASSWORD || 'Yolo01610'
    }
};

class EnhancedUIAutomation {
    constructor(speed = 'normal') {
        this.speed = CONFIG.timing[speed];
        this.uiElements = new Map();
        this.currentState = null;
        this.elementCache = new Map();
        this.debugMode = process.env.DEBUG_MODE === 'true';
        this.logBuffer = [];

        // Known UI patterns from discovery analysis
        this.knownElements = {
            // Login flow elements
            consentButton: { text: 'Let\\'s go!', fallback: { x: 540, y: 2200 } },
            loginSheet: { text: 'Login', fallback: { x: 540, y: 1910 } },
            emailField: { class: 'EditText', fallback: { x: 540, y: 450 } },
            passwordField: { class: 'EditText', fallback: { x: 540, y: 675 } },
            loginButton: { text: 'Login', fallback: { x: 540, y: 1085 } },

            // Vehicle control elements
            vehiclePanel: { text: 'TUF055', fallback: { x: 1002, y: 386 } },
            startRideButton: { text: 'Start to ride', fallback: { x: 631, y: 730 } },
            resumeButton: { text: 'Resume my rent', fallback: { x: 540, y: 2085 } },
            lockButton: { text: 'Lock my vehicle', fallback: { x: 540, y: 2085 } },
            endTripButton: { text: 'End your trip', fallback: { x: 540, y: 970 } },

            // Common navigation
            bottomDrawer: { fallback: { x: 540, y: 2240 } },
            dismissDialog: { fallback: { x: 768, y: 1353 } },

            // Success/error dialogs
            dismissSuccess: { fallback: { x: 540, y: 1459 } },
            appLogo: { contentDesc: 'App logo', fallback: { x: 540, y: 154 } }
        };
    }

    /**
     * Logging utilities
     */
    log(level, message, data = null) {
        const timestamp = new Date().toISOString();
        const logEntry = { timestamp, level, message, data };
        this.logBuffer.push(logEntry);

        const logLine = `[${timestamp}] [${level}] ${message}`;
        if (this.debugMode && data) {
            console.log(logLine, data);
        } else {
            console.log(logLine);
        }
    }

    debug(message, data = null) {
        if (this.debugMode) {
            this.log('DEBUG', message, data);
        }
    }

    info(message, data = null) {
        this.log('INFO', message, data);
    }

    warn(message, data = null) {
        this.log('WARN', message, data);
    }

    error(message, error = null) {
        this.log('ERROR', message, error ? { error: error.message, stack: error.stack } : null);
    }

    /**
     * Core ADB operations
     */
    async adb(args, options = {}) {
        const command = `adb -s ${CONFIG.device.serial} ${args}`;
        this.debug(`Executing ADB: ${command}`);

        try {
            if (options.capture) {
                return execSync(command, { encoding: 'utf8', ...options });
            } else {
                execSync(command, { stdio: 'inherit', ...options });
                return '';
            }
        } catch (error) {
            this.error(`ADB command failed: ${command}`, error);
            throw error;
        }
    }

    async tap(x, y, label = '') {
        if (label) {
            this.info(`Tapping at (${x}, ${y}): ${label}`);
        } else {
            this.debug(`Tapping at (${x}, ${y})`);
        }

        await this.adb(`shell input tap ${x} ${y}`);
        await this.sleep(this.speed.delay);
    }

    async tapByCoordinates(coords, label) {
        await this.tap(coords.x, coords.y, label);
    }

    async sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * UI state detection and element finding
     */
    async dumpUI(tag = 'current') {
        const devicePath = `/sdcard/${tag}.xml`;
        const localPath = path.resolve(`${tag}.xml`);

        try {
            await this.adb(`exec-out uiautomator dump ${devicePath}`);
            await this.adb(`pull ${devicePath} ${JSON.stringify(localPath)}`);

            const xml = fs.readFileSync(localPath, 'utf8');
            this.debug(`UI dump captured: ${tag}`, { elements: xml.split('<node').length - 1 });

            return xml;
        } catch (error) {
            this.warn(`Failed to capture UI dump: ${tag}`, error);
            return null;
        }
    }

    async findElement(strategy, timeout = this.speed.timeout) {
        const startTime = Date.now();

        while (Date.now() - startTime < timeout) {
            const xml = await this.dumpUI();
            if (!xml) continue;

            const element = this.searchElement(xml, strategy);
            if (element) {
                this.debug(`Element found using strategy: ${strategy.type}`, { strategy, element });
                return element;
            }

            await this.sleep(500);
        }

        this.warn(`Element not found using strategy: ${strategy.type}`, { strategy });
        return null;
    }

    searchElement(xml, strategy) {
        switch (strategy.type) {
            case 'text':
                return this.findByText(xml, strategy.value, strategy.exact);
            case 'contentDesc':
                return this.findByContentDesc(xml, strategy.value, strategy.exact);
            case 'resourceId':
                return this.findByResourceId(xml, strategy.value);
            case 'class':
                return this.findByClass(xml, strategy.value, strategy.index);
            case 'xpath':
                return this.findByXPath(xml, strategy.expression);
            default:
                return null;
        }
    }

    findByText(xml, text, exact = true) {
        const regex = exact ?
            new RegExp(`text="${text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"`, 'g') :
            new RegExp(`text="[^"]*${text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[^"]*"`, 'g');

        const match = regex.exec(xml);
        if (match) {
            const nodeMatch = match[0].match(/bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/);
            if (nodeMatch) {
                return {
                    bounds: {
                        left: parseInt(nodeMatch[1]),
                        top: parseInt(nodeMatch[2]),
                        right: parseInt(nodeMatch[3]),
                        bottom: parseInt(nodeMatch[4])
                    },
                    center: {
                        x: Math.floor((parseInt(nodeMatch[1]) + parseInt(nodeMatch[3])) / 2),
                        y: Math.floor((parseInt(nodeMatch[2]) + parseInt(nodeMatch[4])) / 2)
                    }
                };
            }
        }
        return null;
    }

    findByContentDesc(xml, contentDesc, exact = true) {
        const regex = exact ?
            new RegExp(`content-desc="${contentDesc.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"`, 'g') :
            new RegExp(`content-desc="[^"]*${contentDesc.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[^"]*"`, 'g');

        const match = regex.exec(xml);
        if (match) {
            const nodeMatch = match[0].match(/bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/);
            if (nodeMatch) {
                return {
                    bounds: {
                        left: parseInt(nodeMatch[1]),
                        top: parseInt(nodeMatch[2]),
                        right: parseInt(nodeMatch[3]),
                        bottom: parseInt(nodeMatch[4])
                    },
                    center: {
                        x: Math.floor((parseInt(nodeMatch[1]) + parseInt(nodeMatch[3])) / 2),
                        y: Math.floor((parseInt(nodeMatch[2]) + parseInt(nodeMatch[4])) / 2)
                    }
                };
            }
        }
        return null;
    }

    findByResourceId(xml, resourceId) {
        const regex = new RegExp(`resource-id="${resourceId}"`, 'g');
        const match = regex.exec(xml);
        if (match) {
            // Find the bounds in the same node
            const nodeStart = xml.lastIndexOf('<node', match.index);
            const nodeEnd = xml.indexOf('/>', match.index) + 2;
            const nodeXml = xml.substring(nodeStart, nodeEnd);

            const boundsMatch = nodeXml.match(/bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/);
            if (boundsMatch) {
                return {
                    bounds: {
                        left: parseInt(boundsMatch[1]),
                        top: parseInt(boundsMatch[2]),
                        right: parseInt(boundsMatch[3]),
                        bottom: parseInt(boundsMatch[4])
                    },
                    center: {
                        x: Math.floor((parseInt(boundsMatch[1]) + parseInt(boundsMatch[3])) / 2),
                        y: Math.floor((parseInt(boundsMatch[2]) + parseInt(boundsMatch[4])) / 2)
                    }
                };
            }
        }
        return null;
    }

    findByClass(xml, className, index = 0) {
        const regex = new RegExp(`class="${className}"`, 'g');
        let matchCount = 0;
        let match;

        while ((match = regex.exec(xml)) !== null) {
            if (matchCount === index) {
                // Find bounds in same node
                const nodeStart = xml.lastIndexOf('<node', match.index);
                const nodeEnd = xml.indexOf('/>', match.index) + 2;
                const nodeXml = xml.substring(nodeStart, nodeEnd);

                const boundsMatch = nodeXml.match(/bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/);
                if (boundsMatch) {
                    return {
                        bounds: {
                            left: parseInt(boundsMatch[1]),
                            top: parseInt(boundsMatch[2]),
                            right: parseInt(boundsMatch[3]),
                            bottom: parseInt(boundsMatch[4])
                        },
                        center: {
                            x: Math.floor((parseInt(boundsMatch[1]) + parseInt(boundsMatch[3])) / 2),
                            y: Math.floor((parseInt(boundsMatch[2]) + parseInt(boundsMatch[4])) / 2)
                        }
                    };
                }
            }
            matchCount++;
        }
        return null;
    }

    /**
     * Smart element interaction with fallback strategies
     */
    async smartTap(elementKey, timeout = this.speed.timeout) {
        const elementConfig = this.knownElements[elementKey];
        if (!elementConfig) {
            throw new Error(`Unknown element: ${elementKey}`);
        }

        // Try primary strategy first
        let strategies = [];

        if (elementConfig.text) {
            strategies.push({ type: 'text', value: elementConfig.text, exact: true });
            strategies.push({ type: 'text', value: elementConfig.text, exact: false });
        }

        if (elementConfig.contentDesc) {
            strategies.push({ type: 'contentDesc', value: elementConfig.contentDesc, exact: true });
        }

        if (elementConfig.class) {
            strategies.push({ type: 'class', value: elementConfig.class, index: 0 });
        }

        if (elementConfig.resourceId) {
            strategies.push({ type: 'resourceId', value: elementConfig.resourceId });
        }

        // Try each strategy
        for (const strategy of strategies) {
            const element = await this.findElement(strategy, timeout);
            if (element) {
                await this.tap(element.center.x, element.center.y, elementKey);
                return true;
            }
        }

        // Fallback to coordinates if available
        if (elementConfig.fallback) {
            this.warn(`Using fallback coordinates for ${elementKey}`);
            await this.tapByCoordinates(elementConfig.fallback, elementKey);
            return true;
        }

        throw new Error(`Could not find element: ${elementKey}`);
    }

    /**
     * State detection and validation
     */
    async detectCurrentState() {
        const xml = await this.dumpUI();
        if (!xml) return 'UNKNOWN';

        // Check for various known states
        if (xml.includes('Login') && xml.includes('Signup')) {
            return 'LOGIN_SHEET';
        }

        if (xml.includes('Email') && xml.includes('Password')) {
            return 'LOGIN_FORM';
        }

        if (xml.includes('Scan & ride') || xml.includes('Buy a Pass')) {
            return 'HOME_SCREEN';
        }

        if (xml.includes('TUF055') && xml.includes('Start to ride')) {
            return 'VEHICLE_UNLOCKED';
        }

        if (xml.includes('Unlocking a vehicle')) {
            return 'UNLOCKING';
        }

        if (xml.includes('Vehicle unlocked')) {
            return 'UNLOCK_SUCCESS';
        }

        if (xml.includes('Vehicle locked')) {
            return 'LOCK_SUCCESS';
        }

        if (xml.includes('End your trip')) {
            return 'VEHICLE_UNLOCKED';
        }

        return 'UNKNOWN';
    }

    async waitForState(expectedState, timeout = this.speed.timeout) {
        const startTime = Date.now();

        while (Date.now() - startTime < timeout) {
            const currentState = await this.detectCurrentState();
            if (currentState === expectedState) {
                this.info(`State confirmed: ${expectedState}`);
                return true;
            }

            this.debug(`Current state: ${currentState}, waiting for: ${expectedState}`);
            await this.sleep(500);
        }

        throw new Error(`Timeout waiting for state: ${expectedState}`);
    }

    async handleCommonDialogs() {
        // Handle common dialogs that may appear
        const xml = await this.dumpUI();
        if (!xml) return;

        // Dismiss error dialogs
        if (xml.includes('An error occurred') && xml.includes('Ok')) {
            const okButton = await this.findElement({ type: 'text', value: 'Ok' }, 2000);
            if (okButton) {
                await this.tap(okButton.center.x, okButton.center.y, 'Dismiss error dialog');
                await this.sleep(1500);
            }
        }

        // Dismiss crash dialogs
        if (xml.includes('isn\'t responding')) {
            const waitButton = await this.findElement({ type: 'text', value: 'Wait' }, 2000);
            if (waitButton) {
                await this.tap(waitButton.center.x, waitButton.center.y, 'Dismiss crash dialog');
                await this.sleep(4000);
            }
        }
    }

    /**
     * High-level automation flows
     */
    async login(credentials = CONFIG.credentials) {
        this.info('Starting login flow');

        try {
            // Wait for login sheet
            await this.waitForState('LOGIN_SHEET');

            // Open login form
            await this.smartTap('loginSheet');
            await this.sleep(2000);

            // Fill in credentials
            await this.smartTap('emailField');
            await this.sleep(500);
            await this.adb(`shell input text '${credentials.email}'`);
            await this.sleep(800);

            await this.smartTap('passwordField');
            await this.sleep(500);
            await this.adb(`shell input text '${credentials.password}'`);
            await this.sleep(1000);

            // Submit login
            await this.smartTap('loginButton');
            await this.sleep(4000);

            // Handle any post-login dialogs
            await this.handleCommonDialogs();

            // Wait for home screen
            await this.waitForState('HOME_SCREEN');

            this.info('Login completed successfully');
            return true;

        } catch (error) {
            this.error('Login failed', error);
            throw error;
        }
    }

    async unlockVehicle(vehicleId = 'TUF055') {
        this.info(`Starting vehicle unlock flow for ${vehicleId}`);

        try {
            // Open vehicle panel
            await this.smartTap('bottomDrawer');
            await this.sleep(1500);

            await this.smartTap('vehiclePanel');
            await this.sleep(2000);

            // Start ride
            await this.smartTap('startRideButton');
            await this.sleep(3000);

            // Confirm resume
            await this.smartTap('resumeButton');
            await this.sleep(5000);

            // Handle success dialog
            await this.handleCommonDialogs();

            // Verify unlock success
            await this.waitForState('VEHICLE_UNLOCKED');

            this.info('Vehicle unlocked successfully');
            return true;

        } catch (error) {
            this.error('Vehicle unlock failed', error);
            throw error;
        }
    }

    async lockVehicle() {
        this.info('Starting vehicle lock flow');

        try {
            // Open vehicle panel
            await this.smartTap('bottomDrawer');
            await this.sleep(1500);

            await this.smartTap('vehiclePanel');
            await this.sleep(2000);

            // End trip
            await this.smartTap('endTripButton');
            await this.sleep(2000);

            // Confirm lock
            await this.smartTap('lockButton');
            await this.sleep(5000);

            // Handle success dialog
            await this.handleCommonDialogs();

            // Verify lock success
            await this.waitForState('HOME_SCREEN');

            this.info('Vehicle locked successfully');
            return true;

        } catch (error) {
            this.error('Vehicle lock failed', error);
            throw error;
        }
    }

    async completeUnlockFlow(credentials = CONFIG.credentials) {
        this.info('Starting complete unlock flow (login + unlock)');

        try {
            // Detect current state and start from appropriate point
            const initialState = await this.detectCurrentState();
            this.info(`Initial state: ${initialState}`);

            if (initialState === 'LOGIN_SHEET' || initialState === 'LOGIN_FORM') {
                // Need to login first
                await this.login(credentials);
            } else if (initialState === 'UNKNOWN') {
                // Try to navigate to home screen
                await this.handleCommonDialogs();
                await this.sleep(2000);

                const newState = await this.detectCurrentState();
                if (newState === 'LOGIN_SHEET' || newState === 'LOGIN_FORM') {
                    await this.login(credentials);
                }
            }

            // Now unlock vehicle
            await this.unlockVehicle();

            this.info('Complete unlock flow finished successfully');
            return true;

        } catch (error) {
            this.error('Complete unlock flow failed', error);
            throw error;
        }
    }

    /**
     * Utility methods
     */
    async resetApp() {
        this.info('Resetting application state');

        await this.adb(`shell am force-stop ${CONFIG.app.package}`);
        await this.adb(`shell pm clear ${CONFIG.app.package}`);
        await this.adb(`shell am start -n ${CONFIG.app.package}/${CONFIG.app.mainActivity}`);
        await this.sleep(6000);
    }

    saveLogs(filename) {
        const logPath = path.resolve(filename);
        fs.writeFileSync(logPath, JSON.stringify(this.logBuffer, null, 2));
        this.info(`Logs saved to ${logPath}`);
    }

    generateReport() {
        const report = {
            timestamp: new Date().toISOString(),
            device: CONFIG.device.serial,
            app: CONFIG.app.package,
            currentState: this.currentState,
            knownElements: Object.keys(this.knownElements),
            totalLogs: this.logBuffer.length,
            lastLogs: this.logBuffer.slice(-20)
        };

        return report;
    }
}

// CLI interface
if (require.main === module) {
    const args = process.argv.slice(2);
    const command = args[0];

    const automation = new EnhancedUIAutomation('normal');

    async function runCommand() {
        try {
            switch (command) {
                case 'login':
                    await automation.login();
                    break;

                case 'unlock':
                    await automation.unlockVehicle();
                    break;

                case 'lock':
                    await automation.lockVehicle();
                    break;

                case 'complete':
                    await automation.completeUnlockFlow();
                    break;

                case 'reset':
                    await automation.resetApp();
                    break;

                case 'state':
                    const state = await automation.detectCurrentState();
                    console.log(`Current state: ${state}`);
                    break;

                default:
                    console.log('Available commands:');
                    console.log('  login     - Perform login flow');
                    console.log('  unlock    - Unlock vehicle');
                    console.log('  lock      - Lock vehicle');
                    console.log('  complete  - Complete login + unlock flow');
                    console.log('  reset     - Reset app state');
                    console.log('  state     - Detect current state');
                    break;
            }

            // Save logs
            automation.saveLogs(`automation_logs_${Date.now()}.json`);

        } catch (error) {
            automation.error('Command failed', error);
            process.exit(1);
        }
    }

    runCommand();
}

module.exports = EnhancedUIAutomation;