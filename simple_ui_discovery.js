#!/usr/bin/env node

/**
 * Simple Automatic UI Discovery for MaynDrive
 *
 * A streamlined version that automatically explores the app and discovers UI elements
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
        package: 'fr.mayndrive.app'
    },
    discovery: {
        maxExplorations: 20,
        delay: 2000,
        screenshotDir: './discovery_screenshots',
        xmlDir: './discovery_xml_dumps'
    }
};

class SimpleUIDiscovery {
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

    async tap(x, y, description = '') {
        if (description) {
            this.log('INFO', `Tapping: ${description} at (${x}, ${y})`);
        }
        await this.adb(`shell input tap ${x} ${y}`);
        await this.sleep(1000);
    }

    async swipe(x1, y1, x2, y2, description = '') {
        if (description) {
            this.log('INFO', `Swiping: ${description} from (${x1}, ${y1}) to (${x2}, ${y2})`);
        }
        await this.adb(`shell input swipe ${x1} ${y1} ${x2} ${y2} 500`);
        await this.sleep(1500);
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async dumpUI() {
        try {
            const xml = await this.adb('shell uiautomator dump');
            if (xml.includes('UI hierchary dumped to')) {
                const xmlContent = await this.adb('shell cat /sdcard/window_dump.xml');
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
        if (xmlContent.includes('TUF') || xmlContent.includes('Start to ride')) {
            return 'VEHICLE_PANEL';
        }

        // Check for rental in progress
        if (xmlContent.includes('paused') && xmlContent.includes('rental')) {
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

        const xmlContent = await this.dumpUI();
        if (!xmlContent) {
            this.log('ERROR', 'Failed to get UI dump');
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

    async performExploration() {
        this.log('INFO', 'Starting systematic exploration');

        const explorations = [
            { type: 'tap', x: 540, y: 2200, description: 'Bottom center' },
            { type: 'tap', x: 540, y: 1800, description: 'Lower middle' },
            { type: 'tap', x: 540, y: 1400, description: 'Middle center' },
            { type: 'tap', x: 100, y: 154, description: 'Menu button' },
            { type: 'tap', x: 1000, y: 1386, description: 'Location button' },
            { type: 'tap', x: 1000, y: 1210, description: 'Map toggle button' },
            { type: 'swipe', x1: 100, y1: 1000, x2: 100, y2: 500, description: 'Swipe up' },
            { type: 'swipe', x1: 100, y1: 500, x2: 100, y2: 1000, description: 'Swipe down' },
            { type: 'tap', x: 540, y: 900, description: 'Upper middle' },
            { type: 'tap', x: 200, y: 1000, description: 'Left side' },
            { type: 'tap', x: 880, y: 1000, description: 'Right side' }
        ];

        for (const exploration of explorations) {
            if (this.explorationCount >= CONFIG.discovery.maxExplorations) {
                this.log('INFO', 'Maximum exploration limit reached');
                break;
            }

            this.explorationCount++;
            this.log('INFO', `Exploration ${this.explorationCount}: ${exploration.description}`);

            const beforeState = await this.dumpUI();
            const beforeScreen = this.detectCurrentState(beforeState);

            if (exploration.type === 'swipe') {
                await this.swipe(exploration.x1, exploration.y1, exploration.x2, exploration.y2, exploration.description);
            } else {
                await this.tap(exploration.x, exploration.y, exploration.description);
            }

            await this.sleep(CONFIG.discovery.delay);

            const afterState = await this.dumpUI();
            const afterScreen = this.detectCurrentState(afterState);

            const screenKey = `${afterScreen}_${this.explorationCount}`;
            if (!this.visitedScreens.has(screenKey)) {
                this.visitedScreens.add(screenKey);
                await this.analyzeScreen(screenKey);
            }

            // Go back to try to return to a known state
            if (afterScreen !== beforeState) {
                this.log('INFO', 'Screen state changed, going back');
                await this.adb('shell input keyevent KEYCODE_BACK');
                await this.sleep(1500);
            }
        }
    }

    generateReport() {
        const report = {
            summary: {
                totalElements: this.discoveredElements.size,
                totalScreens: this.visitedScreens.size,
                explorations: this.explorationCount,
                timestamp: new Date().toISOString()
            },
            elements: Array.from(this.discoveredElements.values()).sort((a, b) => b.confidence - a.confidence),
            screens: Array.from(this.visitedScreens),
            highConfidenceElements: Array.from(this.discoveredElements.values()).filter(e => e.confidence >= 70),
            actionableElements: Array.from(this.discoveredElements.values()).filter(e => e.clickable)
        };

        const reportPath = './simple_discovery_report.json';
        fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

        this.log('INFO', `Discovery report saved to: ${reportPath}`);
        this.log('INFO', `Summary: ${report.summary.totalElements} elements, ${report.summary.totalScreens} screens`);

        return report;
    }

    async startDiscovery() {
        this.log('INFO', 'Starting Simple UI Discovery for MaynDrive');

        try {
            // Check if device is available
            const devices = await this.adb('devices');
            if (!devices.includes(CONFIG.device.serial)) {
                throw new Error(`Device ${CONFIG.device.serial} not found`);
            }

            // Start with current screen
            this.log('INFO', 'Analyzing current screen');
            await this.analyzeScreen('initial');

            // Perform systematic exploration
            await this.performExploration();

            // Generate final report
            const report = this.generateReport();

            this.log('INFO', 'Discovery completed successfully!');
            return report;

        } catch (error) {
            this.log('ERROR', 'Discovery failed', error.message);
            throw error;
        }
    }
}

// CLI interface
if (require.main === module) {
    const discovery = new SimpleUIDiscovery();
    discovery.startDiscovery().catch(error => {
        console.error('Discovery failed:', error);
        process.exit(1);
    });
}

module.exports = SimpleUIDiscovery;