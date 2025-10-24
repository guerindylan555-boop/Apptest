#!/usr/bin/env node

/**
 * Step-by-Step UI Discovery for MaynDrive
 *
 * Usage: node step_by_step_discovery.js <action> [x] [y]
 *
 * Actions:
 *   analyze          - Analyze current screen
 *   tap <x> <y>      - Tap at coordinates
 *   back             - Go back
 *   report           - Generate final report
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
        outputDir: './step_discovery',
        stateFile: './step_discovery/discovery_state.json'
    }
};

class StepByStepDiscovery {
    constructor() {
        this.step = 0;
        this.setupOutputDirectory();
        this.loadState();
    }

    setupOutputDirectory() {
        if (!fs.existsSync(CONFIG.discovery.outputDir)) {
            fs.mkdirSync(CONFIG.discovery.outputDir, { recursive: true });
        }
    }

    loadState() {
        if (fs.existsSync(CONFIG.discovery.stateFile)) {
            const state = JSON.parse(fs.readFileSync(CONFIG.discovery.stateFile, 'utf8'));
            this.step = state.step || 0;
            this.discoveredElements = state.elements || [];
        } else {
            this.discoveredElements = [];
        }
    }

    saveState() {
        const state = {
            step: this.step,
            elements: this.discoveredElements,
            lastUpdated: new Date().toISOString()
        };
        fs.writeFileSync(CONFIG.discovery.stateFile, JSON.stringify(state, null, 2));
    }

    log(level, message, data = null) {
        const timestamp = new Date().toISOString();
        const logLine = `[${timestamp}] [STEP ${this.step}] [${level}] ${message}`;
        if (data) {
            console.log(logLine, data);
        } else {
            console.log(logLine);
        }
    }

    async adb(args) {
        try {
            return execSync(`adb -s ${CONFIG.device} ${args}`, { encoding: 'utf8' });
        } catch (error) {
            this.log('ERROR', `ADB failed: ${args}`);
            return '';
        }
    }

    async checkMaynDriveApp() {
        const xml = await this.adb('shell uiautomator dump');
        if (!xml.includes('UI hierchary dumped to')) {
            this.log('ERROR', 'Failed to dump UI');
            return false;
        }

        const xmlContent = await this.adb('shell cat /sdcard/window_dump.xml');
        if (xmlContent && xmlContent.includes(CONFIG.app.package)) {
            return true;
        }

        this.log('WARN', '❌ Not in MaynDrive app, launching...');
        await this.adb(`shell am start -n ${CONFIG.app.package}/${CONFIG.app.mainActivity}`);
        await this.sleep(3000);

        const retryXml = await this.adb('shell uiautomator dump && cat /sdcard/window_dump.xml');
        return retryXml && retryXml.includes(CONFIG.app.package);
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

    parseClickableElements(xmlContent) {
        const elements = [];
        const nodeRegex = /<node[^>]*clickable="true"[^>]*>/g;
        let match;

        while ((match = nodeRegex.exec(xmlContent)) !== null) {
            const element = this.parseElement(match[0]);
            if (element && (element.text || element.contentDesc)) {
                elements.push(element);
            }
        }

        return elements.sort((a, b) => b.confidence - a.confidence);
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
        if (text && text.length > 0) confidence += 50;
        if (contentDesc && contentDesc.length > 0) confidence += 30;
        if (text && (text.includes('Login') || text.includes('Start') || text.includes('Scan') || text.includes('Buy'))) {
            confidence += 20;
        }

        return {
            text,
            contentDesc,
            x,
            y,
            confidence,
            bounds: `${boundsMatch[1]},${boundsMatch[2]}-${boundsMatch[3]},${boundsMatch[4]}`
        };
    }

    async analyzeScreen() {
        this.step++;
        this.log('INFO', '🔍 ANALYZING CURRENT SCREEN');

        if (!await this.checkMaynDriveApp()) {
            this.log('ERROR', '❌ Cannot access MaynDrive app');
            return;
        }

        const xmlContent = await this.adb('shell cat /sdcard/window_dump.xml');
        if (!xmlContent) {
            this.log('ERROR', 'No XML content available');
            return;
        }

        const screenState = this.detectScreenState(xmlContent);
        this.log('INFO', `📱 Screen state: ${screenState}`);

        // Save current state
        await this.saveScreenState(xmlContent, screenState);

        // Parse elements
        const elements = this.parseClickableElements(xmlContent);
        this.log('INFO', `🔘 Found ${elements.length} clickable elements`);

        // Show top elements
        const topElements = elements.slice(0, 8);
        this.log('INFO', '🎯 Top elements:');
        topElements.forEach((el, i) => {
            const label = el.text || el.contentDesc || 'unnamed';
            this.log('INFO', `  ${i+1}. "${label}" (${el.confidence}%) at (${el.x}, ${el.y})`);
        });

        // Store elements
        elements.forEach(el => {
            this.discoveredElements.push({
                ...el,
                screen: screenState,
                step: this.step,
                timestamp: new Date().toISOString()
            });
        });

        this.saveState();

        // Suggest next actions
        this.suggestActions(screenState);
    }

    async saveScreenState(xmlContent, screenState) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

        // Save XML
        const xmlFile = path.join(CONFIG.discovery.outputDir, `step_${this.step}_${screenState}.xml`);
        fs.writeFileSync(xmlFile, xmlContent);

        // Save screenshot
        const screenshotFile = path.join(CONFIG.discovery.outputDir, `step_${this.step}_${screenState}.png`);
        await this.adb(`shell screencap -p /sdcard/screenshot.png`);
        execSync(`adb -s ${CONFIG.device} pull /sdcard/screenshot.png ${screenshotFile}`);

        this.log('INFO', `💾 Saved: ${xmlFile}`);
        this.log('INFO', `📸 Saved: ${screenshotFile}`);
    }

    suggestActions(screenState) {
        this.log('INFO', '💡 SUGGESTED ACTIONS:');

        if (screenState === 'MAIN_MAP') {
            this.log('INFO', '  node step_by_step_discovery.js tap 540 1557');
            this.log('INFO', '  node step_by_step_discovery.js tap 540 1689');
            this.log('INFO', '  node step_by_step_discovery.js tap 1000 1386');
            this.log('INFO', '  node step_by_step_discovery.js tap 77 154');
        } else if (screenState === 'VEHICLE_PANEL') {
            this.log('INFO', '  node step_by_step_discovery.js tap 631 730');
            this.log('INFO', '  node step_by_step_discovery.js tap 270 336');
            this.log('INFO', '  node step_by_step_discovery.js back');
        } else if (screenState === 'LOGIN') {
            this.log('INFO', '  node step_by_step_discovery.js tap 540 1910');
            this.log('INFO', '  node step_by_step_discovery.js back');
        }

        this.log('INFO', '  node step_by_step_discovery.js analyze  (re-analyze current screen)');
        this.log('INFO', '  node step_by_step_discovery.js report   (generate final report)');
    }

    async tap(x, y) {
        this.step++;
        this.log('INFO', `👆 TAPPING at (${x}, ${y})`);

        if (!await this.checkMaynDriveApp()) {
            this.log('ERROR', '❌ Cannot access MaynDrive app');
            return;
        }

        await this.adb(`shell input tap ${x} ${y}`);
        await this.sleep(2000);

        this.log('INFO', '✅ Tap completed, checking new state...');

        // Auto-analyze after tap
        setTimeout(() => {
            this.analyzeScreen();
        }, 1000);
    }

    async goBack() {
        this.step++;
        this.log('INFO', '🔙 GOING BACK');

        if (!await this.checkMaynDriveApp()) {
            this.log('ERROR', '❌ Cannot access MaynDrive app');
            return;
        }

        await this.adb('shell input keyevent KEYCODE_BACK');
        await this.sleep(2000);

        this.log('INFO', '✅ Back completed, checking new state...');

        // Auto-analyze after back
        setTimeout(() => {
            this.analyzeScreen();
        }, 1000);
    }

    generateReport() {
        this.log('INFO', '📊 GENERATING FINAL REPORT');

        const report = {
            summary: {
                totalSteps: this.step,
                totalElements: this.discoveredElements.length,
                discoveredStates: [...new Set(this.discoveredElements.map(el => el.screen))],
                highConfidenceElements: this.discoveredElements.filter(el => el.confidence >= 70),
                timestamp: new Date().toISOString()
            },
            elements: this.discoveredElements,
            elementsByScreen: this.groupElementsByScreen(),
            automationTargets: this.getAutomationTargets()
        };

        const reportPath = path.join(CONFIG.discovery.outputDir, 'final_discovery_report.json');
        fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

        this.log('INFO', `📋 Report saved: ${reportPath}`);
        this.log('INFO', `📈 Summary: ${report.summary.totalElements} elements across ${report.summary.discoveredStates.length} screens`);
        this.log('INFO', `🎯 High confidence elements: ${report.summary.highConfidenceElements.length}`);

        // Show best automation targets
        this.log('INFO', '🎯 BEST AUTOMATION TARGETS:');
        report.automationTargets.slice(0, 5).forEach((target, i) => {
            this.log('INFO', `  ${i+1}. "${target.text}" (${target.confidence}%) - tap (${target.x}, ${target.y})`);
        });
    }

    groupElementsByScreen() {
        const grouped = {};
        this.discoveredElements.forEach(element => {
            if (!grouped[element.screen]) {
                grouped[element.screen] = [];
            }
            grouped[element.screen].push(element);
        });
        return grouped;
    }

    getAutomationTargets() {
        return this.discoveredElements
            .filter(el => el.confidence >= 40)
            .sort((a, b) => b.confidence - a.confidence);
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async run(action, x, y) {
        this.log('INFO', '🚀 STARTING STEP-BY-STEP DISCOVERY');

        switch (action) {
            case 'analyze':
                await this.analyzeScreen();
                break;
            case 'tap':
                if (x && y) {
                    await this.tap(parseInt(x), parseInt(y));
                } else {
                    this.log('ERROR', '❌ Tap requires x and y coordinates');
                }
                break;
            case 'back':
                await this.goBack();
                break;
            case 'report':
                this.generateReport();
                break;
            default:
                this.log('ERROR', `❌ Unknown action: ${action}`);
                this.log('INFO', 'Available actions: analyze, tap <x> <y>, back, report');
                this.log('INFO', 'Example: node step_by_step_discovery.js analyze');
                this.log('INFO', 'Example: node step_by_step_discovery.js tap 540 1557');
        }
    }
}

// CLI interface
if (require.main === module) {
    const args = process.argv.slice(2);

    if (args.length === 0) {
        console.log('Step-by-Step UI Discovery for MaynDrive');
        console.log('');
        console.log('Usage: node step_by_step_discovery.js <action> [x] [y]');
        console.log('');
        console.log('Actions:');
        console.log('  analyze          - Analyze current screen');
        console.log('  tap <x> <y>      - Tap at coordinates');
        console.log('  back             - Go back');
        console.log('  report           - Generate final report');
        console.log('');
        console.log('Examples:');
        console.log('  node step_by_step_discovery.js analyze');
        console.log('  node step_by_step_discovery.js tap 540 1557');
        console.log('  node step_by_step_discovery.js back');
        console.log('  node step_by_step_discovery.js report');
        process.exit(0);
    }

    const discovery = new StepByStepDiscovery();
    discovery.run(args[0], args[1], args[2]).catch(error => {
        console.error('Discovery failed:', error);
        process.exit(1);
    });
}

module.exports = StepByStepDiscovery;