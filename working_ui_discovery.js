#!/usr/bin/env node

/**
 * Working Safe UI Discovery for MaynDrive
 * Simple and effective - stays within the app
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const CONFIG = {
    device: 'emulator-5556',
    app: {
        package: 'fr.mayndrive.app',
        mainActivity: 'city.knot.knotapp.ui.MainActivity'
    },
    discovery: {
        maxExplorations: 10,
        delay: 2000,
        screenshotDir: './working_discovery_screenshots',
        xmlDir: './working_discovery_xml_dumps'
    }
};

class WorkingUIDiscovery {
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

    log(level, message) {
        const timestamp = new Date().toISOString();
        console.log(`[${timestamp}] [${level}] ${message}`);
    }

    async adb(args) {
        try {
            return execSync(`adb -s ${CONFIG.device} ${args}`, { encoding: 'utf8' });
        } catch (error) {
            this.log('ERROR', `ADB failed: ${args}`);
            return '';
        }
    }

    async ensureInMaynDriveApp() {
        // Simple check: if UI dump contains MaynDrive package, we're good
        const xml = await this.adb('shell uiautomator dump && cat /sdcard/window_dump.xml');
        if (xml && xml.includes(CONFIG.app.package)) {
            return true;
        }

        // If not, launch MaynDrive
        this.log('WARN', 'Not in MaynDrive app, relaunching...');
        await this.adb(`shell am start -n ${CONFIG.app.package}/${CONFIG.app.mainActivity}`);
        await this.sleep(3000);

        // Check again
        const retryXml = await this.adb('shell uiautomator dump && cat /sdcard/window_dump.xml');
        return retryXml && retryXml.includes(CONFIG.app.package);
    }

    async safeTap(x, y, description) {
        this.log('INFO', `Tapping: ${description} at (${x}, ${y})`);
        await this.adb(`shell input tap ${x} ${y}`);
        await this.sleep(1500);
        return await this.ensureInMaynDriveApp();
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async dumpUI() {
        try {
            const result = await this.adb('shell uiautomator dump');
            if (result.includes('UI hierchary dumped to')) {
                const xml = await this.adb('shell cat /sdcard/window_dump.xml');
                if (xml && xml.includes(CONFIG.app.package)) {
                    return xml;
                } else {
                    this.log('ERROR', 'UI dump shows we left MaynDrive app');
                    return null;
                }
            }
        } catch (error) {
            this.log('ERROR', 'Failed to dump UI');
        }
        return null;
    }

    async saveScreenshot(name) {
        try {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `${name}_${timestamp}.png`;
            const filepath = path.join(CONFIG.discovery.screenshotDir, filename);

            await this.adb(`shell screencap -p /sdcard/${filename}`);
            execSync(`adb -s ${CONFIG.device} pull /sdcard/${filename} ${filepath}`);
            await this.adb(`shell rm /sdcard/${filename}`);

            this.log('INFO', `Screenshot saved: ${filepath}`);
            return filepath;
        } catch (error) {
            this.log('ERROR', 'Failed to take screenshot');
            return null;
        }
    }

    async saveXMLDump(xmlContent, name) {
        try {
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `${name}_${timestamp}.xml`;
            const filepath = path.join(CONFIG.discovery.xmlDir, filename);

            fs.writeFileSync(filepath, xmlContent);
            this.log('INFO', `XML saved: ${filepath}`);
            return filepath;
        } catch (error) {
            this.log('ERROR', 'Failed to save XML');
            return null;
        }
    }

    detectScreenState(xmlContent) {
        if (!xmlContent) return 'UNKNOWN';

        if (xmlContent.includes('Google Map') || xmlContent.includes('Scan & ride')) {
            return 'MAIN_MAP';
        }
        if (xmlContent.includes('TUF') || xmlContent.includes('Start to ride') || xmlContent.includes('paused')) {
            return 'VEHICLE_PANEL';
        }
        if (xmlContent.includes('Login') && xmlContent.includes('Signup')) {
            return 'LOGIN';
        }
        if (xmlContent.includes('Unlocking') || xmlContent.includes('Unlock')) {
            return 'UNLOCKING';
        }
        if (xmlContent.includes('error') || xmlContent.includes('Error')) {
            return 'ERROR';
        }

        return 'UNKNOWN';
    }

    parseElements(xmlContent) {
        const elements = [];
        const nodeRegex = /<node[^>]*clickable="true"[^>]*>/g;
        let match;

        while ((match = nodeRegex.exec(xmlContent)) !== null) {
            const nodeXml = match[0];
            const element = this.parseElement(nodeXml);
            if (element) {
                elements.push(element);
            }
        }

        return elements;
    }

    parseElement(nodeXml) {
        const textMatch = nodeXml.match(/text="([^"]*)"/);
        const descMatch = nodeXml.match(/content-desc="([^"]*)"/);
        const boundsMatch = nodeXml.match(/bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"/);

        if (!boundsMatch) return null;

        const text = textMatch ? textMatch[1] : null;
        const contentDesc = descMatch ? descMatch[1] : null;
        const x = Math.floor((parseInt(boundsMatch[1]) + parseInt(boundsMatch[3])) / 2);
        const y = Math.floor((parseInt(boundsMatch[2]) + parseInt(boundsMatch[4])) / 2);

        let confidence = 0;
        if (text && text.length > 0) confidence += 40;
        if (contentDesc && contentDesc.length > 0) confidence += 30;

        return {
            text,
            contentDesc,
            x,
            y,
            confidence,
            nodeXml
        };
    }

    async analyzeScreen(screenName) {
        this.log('INFO', `Analyzing screen: ${screenName}`);

        const xmlContent = await this.dumpUI();
        if (!xmlContent) {
            this.log('ERROR', 'Cannot get UI dump');
            return;
        }

        await this.saveXMLDump(xmlContent, screenName);
        await this.saveScreenshot(screenName);

        const elements = this.parseElements(xmlContent);
        this.log('INFO', `Found ${elements.length} clickable elements`);

        // Store elements
        elements.forEach(element => {
            const key = `${element.text || element.contentDesc || 'unnamed'}_${element.x}_${element.y}`;
            this.discoveredElements.set(key, {
                ...element,
                screen: screenName,
                discoveredAt: new Date().toISOString()
            });
        });

        // Show high confidence elements
        const highConf = elements.filter(e => e.confidence >= 40);
        if (highConf.length > 0) {
            this.log('INFO', 'High confidence elements:');
            highConf.forEach(e => {
                this.log('INFO', `  - "${e.text || e.contentDesc}" (${e.confidence}%) at (${e.x}, ${e.y})`);
            });
        }

        return elements;
    }

    async performSafeExploration() {
        this.log('INFO', 'Starting safe exploration within MaynDrive app');

        // Safe tap coordinates based on our earlier successful discoveries
        const explorations = [
            { x: 540, y: 1557, desc: 'Buy a Pass button' },
            { x: 540, y: 1689, desc: 'Scan & ride button' },
            { x: 1000, y: 1386, desc: 'My location button' },
            { x: 1000, y: 1210, desc: 'Toggle vehicles button' },
            { x: 77, y: 154, desc: 'Menu button' },
            { x: 270, y: 336, desc: 'Vehicle info area' },
            { x: 540, y: 700, desc: 'Map middle area' },
            { x: 540, y: 400, desc: 'Map upper area' }
        ];

        for (const exploration of explorations) {
            if (this.explorationCount >= CONFIG.discovery.maxExplorations) {
                this.log('INFO', 'Max explorations reached');
                break;
            }

            // Ensure we're in MaynDrive before each exploration
            if (!await this.ensureInMaynDriveApp()) {
                this.log('ERROR', 'Cannot continue - not in MaynDrive app');
                break;
            }

            this.explorationCount++;
            this.log('INFO', `Exploration ${this.explorationCount}: ${exploration.desc}`);

            const beforeXml = await this.dumpUI();
            const beforeState = this.detectScreenState(beforeXml);

            const success = await this.safeTap(exploration.x, exploration.y, exploration.desc);
            if (!success) {
                this.log('ERROR', 'Exploration failed - left MaynDrive app, stopping');
                break;
            }

            const afterXml = await this.dumpUI();
            const afterState = this.detectScreenState(afterXml);

            const screenKey = `${afterState}_${this.explorationCount}`;
            if (!this.visitedScreens.has(screenKey)) {
                this.visitedScreens.add(screenKey);
                await this.analyzeScreen(screenKey);
            }

            // Use back button if state changed significantly
            if (afterState !== beforeState && afterState !== 'UNKNOWN') {
                this.log('INFO', 'State changed, using back button');
                await this.adb('shell input keyevent KEYCODE_BACK');
                await this.sleep(1500);
                await this.ensureInMaynDriveApp();
            }

            await this.sleep(1000);
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
            elements: Array.from(this.discoveredElements.values()),
            screens: Array.from(this.visitedScreens),
            highConfidenceElements: Array.from(this.discoveredElements.values()).filter(e => e.confidence >= 40)
        };

        const reportPath = './working_discovery_report.json';
        fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

        this.log('INFO', `Report saved: ${reportPath}`);
        this.log('INFO', `Summary: ${report.summary.totalElements} elements, ${report.summary.totalScreens} screens`);
        this.log('INFO', '✅ Discovery completed safely within MaynDrive app');

        return report;
    }

    async start() {
        this.log('INFO', 'Starting Working UI Discovery for MaynDrive');

        try {
            if (!await this.ensureInMaynDriveApp()) {
                throw new Error('Cannot access MaynDrive app');
            }

            await this.analyzeScreen('initial');
            await this.performSafeExploration();
            const report = this.generateReport();

            return report;

        } catch (error) {
            this.log('ERROR', 'Discovery failed', error.message);
            throw error;
        }
    }
}

// CLI interface
if (require.main === module) {
    const discovery = new WorkingUIDiscovery();
    discovery.start().catch(error => {
        console.error('Discovery failed:', error);
        process.exit(1);
    });
}

module.exports = WorkingUIDiscovery;