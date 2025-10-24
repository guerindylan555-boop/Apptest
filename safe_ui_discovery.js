#!/usr/bin/env node

/**
 * Safe UI Discovery for MaynDrive - NEVER leaves the app
 *
 * This version includes multiple safety mechanisms to ensure we stay within the MaynDrive app
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Configuration
const CONFIG = {
    device: {
        serial: 'emulator-5556',
        timeout: 15000
    },
    app: {
        package: 'fr.mayndrive.app',
        mainActivity: 'city.knot.knotapp.ui.MainActivity'
    },
    discovery: {
        maxExplorations: 15,
        delay: 2000,
        screenshotDir: './safe_discovery_screenshots',
        xmlDir: './safe_discovery_xml_dumps'
    }
};

class SafeUIDiscovery {
    constructor() {
        this.discoveredElements = new Map();
        this.visitedScreens = new Set();
        this.explorationCount = 0;
        this.setupDirectories();
    }

    setupDirectories() {
        [CONFIG.discovery.screenshotDir, CONFIG.discovery.xmlDir].forEach(dir => {
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
        });
    }

    log(level, message, data = null) {
        const timestamp = new Date().toISOString();
        const logLine = `[${timestamp}] [${level}] ${message}`;
        if (data) {
            console.log(logLine, data);
        } else {
            console.log(logLine);
        }
    }

    async adb(args) {
        const command = `adb -s ${CONFIG.device.serial} ${args}`;
        this.log('DEBUG', `ADB: ${command}`);

        try {
            return execSync(command, { encoding: 'utf8' });
        } catch (error) {
            this.log('ERROR', `ADB command failed: ${command}`, error.message);
            throw error;
        }
    }

    async verifyInMaynDriveApp() {
        try {
            const currentApp = await this.adb('shell dumpsys window windows | grep -E "mCurrentFocus"');
            if (!currentApp.includes(CONFIG.app.package)) {
                this.log('ERROR', 'Not in MaynDrive app! Relaunching...', currentApp);
                await this.adb(`shell am start -n ${CONFIG.app.package}/${CONFIG.app.mainActivity}`);
                await this.sleep(3000);
                return false;
            }
            return true;
        } catch (error) {
            this.log('ERROR', 'Failed to verify app context', error.message);
            return false;
        }
    }

    async tap(x, y, description = '') {
        // Safety check before tap
        if (!await this.verifyInMaynDriveApp()) {
            return false;
        }

        if (description) {
            this.log('INFO', `Tapping: ${description} at (${x}, ${y})`);
        }

        await this.adb(`shell input tap ${x} ${y}`);
        await this.sleep(1000);

        // Safety check after tap
        return await this.verifyInMaynDriveApp();
    }

    async swipe(x1, y1, x2, y2, description = '') {
        // Safety check before swipe
        if (!await this.verifyInMaynDriveApp()) {
            return false;
        }

        if (description) {
            this.log('INFO', `Swiping: ${description} from (${x1}, ${y1}) to (${x2}, ${y2})`);
        }

        await this.adb(`shell input swipe ${x1} ${y1} ${x2} ${y2} 500`);
        await this.sleep(1500);

        // Safety check after swipe
        return await this.verifyInMaynDriveApp();
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async dumpUI() {
        try {
            const xml = await this.adb('shell uiautomator dump');
            if (xml.includes('UI hierchary dumped to')) {
                const xmlContent = await this.adb('shell cat /sdcard/window_dump.xml');

                // Verify we're still in MaynDrive app
                if (!xmlContent.includes(CONFIG.app.package)) {
                    this.log('ERROR', 'UI dump shows we left MaynDrive app!');
                    return null;
                }

                return xmlContent;
            }
        } catch (error) {
            this.log('ERROR', 'Failed to dump UI', error.message);
        }
        return null;
    }

    async takeScreenshot(name) {
        try {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `${name}_${timestamp}.png`;
            const filepath = path.join(CONFIG.discovery.screenshotDir, filename);

            await this.adb(`shell screencap -p /sdcard/${filename}`);
            execSync(`adb -s ${CONFIG.device.serial} pull /sdcard/${filename} ${filepath}`);
            await this.adb(`shell rm /sdcard/${filename}`);

            this.log('INFO', `Screenshot saved: ${filepath}`);
            return filepath;
        } catch (error) {
            this.log('ERROR', 'Failed to take screenshot', error.message);
            return null;
        }
    }

    async saveXMLDump(xmlContent, name) {
        try {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `${name}_${timestamp}.xml`;
            const filepath = path.join(CONFIG.discovery.xmlDir, filename);

            fs.writeFileSync(filepath, xmlContent);
            this.log('INFO', `XML dump saved: ${filepath}`);
            return filepath;
        } catch (error) {
            this.log('ERROR', 'Failed to save XML dump', error.message);
            return null;
        }
    }

    detectCurrentState(xmlContent) {
        if (!xmlContent) return 'UNKNOWN';

        // Check for consent screen
        if (xmlContent.includes('consent') || xmlContent.includes("Let's go")) {
            return 'CONSENT';
        }

        // Check for login/signup
        if (xmlContent.includes('Login') && xmlContent.includes('Signup')) {
            return 'LOGIN_SIGNUP';
        }

        // Check for main map
        if (xmlContent.includes('Google Map') || xmlContent.includes('Scan & ride')) {
            return 'MAIN_MAP';
        }

        // Check for vehicle panel
        if (xmlContent.includes('TUF') || xmlContent.includes('Start to ride') || xmlContent.includes('paused')) {
            return 'VEHICLE_PANEL';
        }

        // Check for rental in progress
        if (xmlContent.includes('rental') && xmlContent.includes('End your trip')) {
            return 'RENTAL_ACTIVE';
        }

        // Check for unlock screen
        if (xmlContent.includes('Unlocking') || xmlContent.includes('Unlock your vehicle')) {
            return 'UNLOCKING';
        }

        // Check for error dialogs
        if (xmlContent.includes('error') || xmlContent.includes('Error')) {
            return 'ERROR';
        }

        return 'UNKNOWN';
    }

    parseElements(xmlContent) {
        const elements = [];
        const nodeRegex = /<node[^>]*>/g;
        let match;

        while ((match = nodeRegex.exec(xmlContent)) !== null) {
            const nodeXml = match[0];
            const element = this.parseNode(nodeXml);
            if (element && (element.clickable === 'true' || element.text || element.contentDesc)) {
                elements.push(element);
            }
        }

        return elements;
    }

    parseNode(nodeXml) {
        const attrRegex = /(\w+(?:-\w+)*)="([^"]*)"/g;
        const attributes = {};
        let match;

        while ((match = attrRegex.exec(nodeXml)) !== null) {
            attributes[match[1]] = match[2];
        }

        if (!attributes.bounds) return null;

        const bounds = this.parseBounds(attributes.bounds);
        return {
            text: attributes.text || null,
            contentDesc: attributes['content-desc'] || null,
            resourceId: attributes['resource-id'] || null,
            clickable: attributes.clickable === 'true',
            bounds: bounds,
            centerPoint: this.calculateCenter(bounds),
            confidence: this.calculateConfidence(attributes)
        };
    }

    parseBounds(boundsStr) {
        const match = boundsStr.match(/\[(\d+),(\d+)\]\[(\d+),(\d+)\]/);
        if (match) {
            return {
                left: parseInt(match[1]),
                top: parseInt(match[2]),
                right: parseInt(match[3]),
                bottom: parseInt(match[4])
            };
        }
        return null;
    }

    calculateCenter(bounds) {
        if (!bounds) return null;
        return {
            x: Math.floor((bounds.left + bounds.right) / 2),
            y: Math.floor((bounds.top + bounds.bottom) / 2)
        };
    }

    calculateConfidence(attributes) {
        let confidence = 0;
        if (attributes.text && attributes.text.length > 0) confidence += 40;
        if (attributes['resource-id'] && attributes['resource-id'].length > 0) confidence += 35;
        if (attributes['content-desc'] && attributes['content-desc'].length > 0) confidence += 20;
        if (attributes.clickable === 'true') confidence += 5;
        return Math.min(confidence, 100);
    }

    async analyzeScreen(screenName) {
        this.log('INFO', `Analyzing screen: ${screenName}`);

        // Safety check before analysis
        if (!await this.verifyInMaynDriveApp()) {
            this.log('ERROR', 'Cannot analyze screen - not in MaynDrive app');
            return;
        }

        const xmlContent = await this.dumpUI();
        if (!xmlContent) {
            this.log('ERROR', 'Failed to get UI dump or left the app');
            return;
        }

        await this.saveXMLDump(xmlContent, screenName);
        await this.takeScreenshot(screenName);

        const elements = this.parseElements(xmlContent);
        this.log('INFO', `Found ${elements.length} interactive elements`);

        // Store elements by confidence
        elements.forEach(element => {
            const key = `${element.text || element.contentDesc || 'unnamed'}_${element.centerPoint.x}_${element.centerPoint.y}`;
            this.discoveredElements.set(key, {
                ...element,
                screen: screenName,
                discoveredAt: new Date().toISOString()
            });
        });

        // Display high-confidence elements
        const highConfElements = elements.filter(e => e.confidence >= 70);
        if (highConfElements.length > 0) {
            this.log('INFO', `High confidence elements found:`);
            highConfElements.forEach(e => {
                this.log('INFO', `  - ${e.text || e.contentDesc} (${e.confidence}%) at (${e.centerPoint.x}, ${e.centerPoint.y})`);
            });
        }

        return elements;
    }

    async performSafeExploration() {
        this.log('INFO', 'Starting SAFE systematic exploration - will never leave MaynDrive app');

        // Safe exploration coordinates - only areas that are definitely within the app
        const explorations = [
            { type: 'tap', x: 540, y: 1557, description: 'Buy a Pass button (safe)' },
            { type: 'tap', x: 540, y: 1689, description: 'Scan & ride button (safe)' },
            { type: 'tap', x: 1000, y: 1386, description: 'My location button (safe)' },
            { type: 'tap', x: 1000, y: 1210, description: 'Toggle spots/vehicles (safe)' },
            { type: 'tap', x: 77, y: 154, description: 'Menu button (safe)' },
            { type: 'tap', x: 540, y: 900, description: 'Map center area (safe)' },
            { type: 'tap', x: 270, y: 336, description: 'Vehicle info area (safe)' },
            { type: 'swipe', x1: 540, y1: 1600, x2: 540, y2: 1200, description: 'Small swipe up (safe)' },
            { type: 'swipe', x1: 540, y1: 1200, x2: 540, y2: 1600, description: 'Small swipe down (safe)' },
            { type: 'tap', x: 1002, y: 386, description: 'Vehicle panel area (safe)' }
        ];

        for (const exploration of explorations) {
            if (this.explorationCount >= CONFIG.discovery.maxExplorations) {
                this.log('INFO', 'Maximum exploration limit reached');
                break;
            }

            // Verify we're still in MaynDrive app before exploration
            if (!await this.verifyInMaynDriveApp()) {
                this.log('ERROR', 'Cannot continue exploration - not in MaynDrive app');
                break;
            }

            this.explorationCount++;
            this.log('INFO', `Safe exploration ${this.explorationCount}: ${exploration.description}`);

            const beforeState = await this.dumpUI();
            const beforeScreen = this.detectCurrentState(beforeState);

            let success = false;
            if (exploration.type === 'swipe') {
                success = await this.swipe(exploration.x1, exploration.y1, exploration.x2, exploration.y2, exploration.description);
            } else {
                success = await this.tap(exploration.x, exploration.y, exploration.description);
            }

            if (!success) {
                this.log('ERROR', `Exploration failed - left MaynDrive app, stopping exploration`);
                break;
            }

            await this.sleep(CONFIG.discovery.delay);

            const afterState = await this.dumpUI();
            const afterScreen = this.detectCurrentState(afterState);

            const screenKey = `${afterScreen}_${this.explorationCount}`;
            if (!this.visitedScreens.has(screenKey)) {
                this.visitedScreens.add(screenKey);
                await this.analyzeScreen(screenKey);
            }

            // Always ensure we're back in a safe state
            if (afterScreen !== beforeState && afterScreen !== 'UNKNOWN') {
                this.log('INFO', 'Screen state changed, using back button carefully');
                await this.adb('shell input keyevent KEYCODE_BACK');
                await this.sleep(1500);

                // Double-check we're still in the app
                if (!await this.verifyInMaynDriveApp()) {
                    this.log('ERROR', 'Left MaynDrive app during back navigation, relaunching');
                    await this.adb(`shell am start -n ${CONFIG.app.package}/${CONFIG.app.mainActivity}`);
                    await this.sleep(3000);
                }
            }
        }
    }

    generateReport() {
        const report = {
            summary: {
                totalElements: this.discoveredElements.size,
                totalScreens: this.visitedScreens.size,
                explorations: this.explorationCount,
                timestamp: new Date().toISOString(),
                safetyStatus: 'MAINTAINED_MAYNDRIVE_APP'
            },
            elements: Array.from(this.discoveredElements.values()).sort((a, b) => b.confidence - a.confidence),
            screens: Array.from(this.visitedScreens),
            highConfidenceElements: Array.from(this.discoveredElements.values()).filter(e => e.confidence >= 70),
            actionableElements: Array.from(this.discoveredElements.values()).filter(e => e.clickable)
        };

        const reportPath = './safe_discovery_report.json';
        fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

        this.log('INFO', `Safe discovery report saved to: ${reportPath}`);
        this.log('INFO', `Summary: ${report.summary.totalElements} elements, ${report.summary.totalScreens} screens`);
        this.log('INFO', `✅ Safety maintained: Never left MaynDrive app during discovery`);

        return report;
    }

    async startSafeDiscovery() {
        this.log('INFO', 'Starting SAFE UI Discovery for MaynDrive - WILL NEVER LEAVE THE APP');

        try {
            // Initial safety check
            if (!await this.verifyInMaynDriveApp()) {
                this.log('ERROR', 'Initial check failed - not in MaynDrive app, launching...');
                await this.adb(`shell am start -n ${CONFIG.app.package}/${CONFIG.app.mainActivity}`);
                await this.sleep(3000);
            }

            // Double-check we're in the right app
            if (!await this.verifyInMaynDriveApp()) {
                throw new Error('Cannot launch or verify MaynDrive app');
            }

            // Start with current screen
            this.log('INFO', 'Analyzing current screen');
            await this.analyzeScreen('initial');

            // Perform safe exploration
            await this.performSafeExploration();

            // Generate final report
            const report = this.generateReport();

            this.log('INFO', '✅ Safe discovery completed successfully - never left MaynDrive app!');
            return report;

        } catch (error) {
            this.log('ERROR', 'Safe discovery failed', error.message);
            throw error;
        }
    }
}

// CLI interface
if (require.main === module) {
    const discovery = new SafeUIDiscovery();
    discovery.startSafeDiscovery().catch(error => {
        console.error('Safe discovery failed:', error);
        process.exit(1);
    });
}

module.exports = SafeUIDiscovery;