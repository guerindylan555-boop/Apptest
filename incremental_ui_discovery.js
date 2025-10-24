#!/usr/bin/env node

/**
 * Incremental UI Discovery for MaynDrive
 *
 * This script provides step-by-step output so we can monitor progress
 * and adjust the discovery strategy as needed.
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
        outputDir: './incremental_discovery',
        delay: 2000
    }
};

class IncrementalUIDiscovery {
    constructor() {
        this.step = 0;
        this.discoveredElements = [];
        this.currentScreenState = 'UNKNOWN';
        this.setupOutputDirectory();
    }

    setupOutputDirectory() {
        if (!fs.existsSync(CONFIG.discovery.outputDir)) {
            fs.mkdirSync(CONFIG.discovery.outputDir, { recursive: true });
        }
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

    async checkCurrentState() {
        this.step++;
        this.log('INFO', `=== STEP ${this.step}: CHECKING CURRENT STATE ===`);

        const xml = await this.adb('shell uiautomator dump');
        if (!xml.includes('UI hierchary dumped to')) {
            this.log('ERROR', 'Failed to dump UI');
            return 'ERROR';
        }

        const xmlContent = await this.adb('shell cat /sdcard/window_dump.xml');

        if (!xmlContent.includes(CONFIG.app.package)) {
            this.log('ERROR', '❌ NOT IN MAYNDRIVE APP!');
            this.log('INFO', 'Current app does not match MaynDrive package');
            return 'WRONG_APP';
        }

        // Detect screen state
        let state = 'UNKNOWN';
        if (xmlContent.includes('Google Map') || xmlContent.includes('Scan & ride')) {
            state = 'MAIN_MAP';
        } else if (xmlContent.includes('TUF') || xmlContent.includes('Start to ride') || xmlContent.includes('paused')) {
            state = 'VEHICLE_PANEL';
        } else if (xmlContent.includes('Login') && xmlContent.includes('Signup')) {
            state = 'LOGIN';
        } else if (xmlContent.includes('Unlocking') || xmlContent.includes('Unlock')) {
            state = 'UNLOCKING';
        } else if (xmlContent.includes('error') || xmlContent.includes('Error')) {
            state = 'ERROR';
        }

        this.currentScreenState = state;
        this.log('INFO', `✅ Current state: ${state}`);
        return state;
    }

    async analyzeCurrentScreen() {
        this.step++;
        this.log('INFO', `=== STEP ${this.step}: ANALYZING CURRENT SCREEN ===`);

        const xmlContent = await this.adb('shell cat /sdcard/window_dump.xml');
        if (!xmlContent) {
            this.log('ERROR', 'No XML content available');
            return [];
        }

        // Save current state
        await this.saveCurrentState(xmlContent);

        // Parse clickable elements
        const elements = this.parseClickableElements(xmlContent);
        this.log('INFO', `Found ${elements.length} clickable elements`);

        // Show top elements
        const topElements = elements.slice(0, 5);
        this.log('INFO', 'Top 5 elements:');
        topElements.forEach((el, i) => {
            this.log('INFO', `  ${i+1}. "${el.text || el.contentDesc}" (${el.confidence}%) at (${el.x}, ${el.y})`);
        });

        // Store elements
        this.discoveredElements.push(...elements.map(el => ({...el, screen: this.currentScreenState, step: this.step})));

        return elements;
    }

    async saveCurrentState(xmlContent) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');

        // Save XML
        const xmlFile = path.join(CONFIG.discovery.outputDir, `step_${this.step}_${this.currentScreenState}.xml`);
        fs.writeFileSync(xmlFile, xmlContent);

        // Save screenshot
        const screenshotFile = path.join(CONFIG.discovery.outputDir, `step_${this.step}_${this.currentScreenState}.png`);
        await this.adb(`shell screencap -p /sdcard/screenshot.png`);
        execSync(`adb -s ${CONFIG.device} pull /sdcard/screenshot.png ${screenshotFile}`);

        this.log('INFO', `📸 Saved: ${xmlFile}`);
        this.log('INFO', `📸 Saved: ${screenshotFile}`);
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

    async waitForUserInput() {
        this.log('INPUT', '⏸️  PAUSED - Please review the output above');
        this.log('INPUT', 'Options:');
        this.log('INPUT', '  1. Continue with next step');
        this.log('INPUT', '  2. Tap specific coordinates (format: tap x,y)');
        this.log('INPUT', '  3. Go back to previous screen');
        this.log('INPUT', '  4. Exit discovery');
        this.log('INPUT', 'Enter your choice (wait 30s for auto-continue):');

        return new Promise((resolve) => {
            let answered = false;

            // Auto-continue after 30 seconds
            const timeout = setTimeout(() => {
                if (!answered) {
                    answered = true;
                    this.log('INFO', '⏭️  Auto-continuing...');
                    resolve('continue');
                }
            }, 30000);

            // Simple stdin handling
            process.stdin.setRawMode(true);
            process.stdin.resume();
            process.stdin.on('data', (key) => {
                if (!answered) {
                    answered = true;
                    clearTimeout(timeout);
                    process.stdin.setRawMode(false);
                    process.stdin.pause();

                    const input = key.toString().trim();
                    if (input === '1') {
                        resolve('continue');
                    } else if (input === '3') {
                        resolve('back');
                    } else if (input === '4') {
                        resolve('exit');
                    } else if (input.startsWith('tap')) {
                        resolve(input);
                    } else {
                        resolve('continue');
                    }
                }
            });
        });
    }

    async performAction(action) {
        this.step++;
        this.log('INFO', `=== STEP ${this.step}: PERFORMING ACTION: ${action} ===`);

        if (action === 'back') {
            this.log('INFO', '🔙 Going back...');
            await this.adb('shell input keyevent KEYCODE_BACK');
            await this.sleep(CONFIG.discovery.delay);
            return true;
        }

        if (action.startsWith('tap')) {
            const match = action.match(/tap (\d+),(\d+)/);
            if (match) {
                const x = parseInt(match[1]);
                const y = parseInt(match[2]);
                this.log('INFO', `👆 Tapping at (${x}, ${y})`);
                await this.adb(`shell input tap ${x} ${y}`);
                await this.sleep(CONFIG.discovery.delay);
                return true;
            }
        }

        return false;
    }

    async suggestNextActions() {
        this.log('INFO', '💡 SUGGESTED NEXT ACTIONS:');

        const currentState = this.currentScreenState;

        if (currentState === 'MAIN_MAP') {
            this.log('INFO', '  1. tap 540,1557  (Buy a Pass button)');
            this.log('INFO', '  2. tap 540,1689  (Scan & ride button)');
            this.log('INFO', '  3. tap 1000,1386 (My location button)');
            this.log('INFO', '  4. tap 77,154    (Menu button)');
        } else if (currentState === 'VEHICLE_PANEL') {
            this.log('INFO', '  1. tap 631,730   (Start to ride button)');
            this.log('INFO', '  2. tap 270,336   (Vehicle info area)');
            this.log('INFO', '  3. back          (Go back to map)');
        } else if (currentState === 'LOGIN') {
            this.log('INFO', '  1. tap 540,1910  (Login button)');
            this.log('INFO', '  2. back          (Go back)');
        }

        this.log('INFO', '  custom: tap x,y    (Tap specific coordinates)');
        this.log('INFO', '  back            (Go back one screen)');
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async startInteractiveDiscovery() {
        this.log('INFO', '🚀 STARTING INCREMENTAL UI DISCOVERY FOR MAYNDRIVE');
        this.log('INFO', 'This script will pause after each step for your review');

        // Enable stdin for user input
        process.stdin.setEncoding('utf8');

        try {
            // Check initial state
            await this.checkCurrentState();
            if (this.currentScreenState === 'WRONG_APP') {
                this.log('INFO', '🔄 Launching MaynDrive app...');
                await this.adb(`shell am start -n ${CONFIG.app.package}/${CONFIG.app.mainActivity}`);
                await this.sleep(3000);
                await this.checkCurrentState();
            }

            // Main discovery loop
            let running = true;
            while (running) {
                // Analyze current screen
                await this.analyzeCurrentScreen();

                // Suggest next actions
                this.suggestNextActions();

                // Wait for user input
                const userChoice = await this.waitForUserInput();

                if (userChoice === 'exit') {
                    running = false;
                    this.log('INFO', '🛑 Exiting discovery...');
                } else {
                    // Perform the chosen action
                    await this.performAction(userChoice);

                    // Check new state
                    await this.checkCurrentState();
                }
            }

            // Generate final report
            this.generateFinalReport();

        } catch (error) {
            this.log('ERROR', 'Discovery failed:', error.message);
        }
    }

    generateFinalReport() {
        this.log('INFO', '📊 GENERATING FINAL REPORT...');

        const report = {
            summary: {
                totalSteps: this.step,
                totalElements: this.discoveredElements.length,
                discoveredStates: [...new Set(this.discoveredElements.map(el => el.screen))],
                timestamp: new Date().toISOString()
            },
            elements: this.discoveredElements,
            highConfidenceElements: this.discoveredElements.filter(el => el.confidence >= 70),
            elementsByScreen: this.groupElementsByScreen()
        };

        const reportPath = path.join(CONFIG.discovery.outputDir, 'incremental_discovery_report.json');
        fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

        this.log('INFO', `📋 Report saved to: ${reportPath}`);
        this.log('INFO', `📈 Summary: ${report.summary.totalElements} elements across ${report.summary.discoveredStates.length} screens`);
        this.log('INFO', '✅ Incremental discovery completed!');
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
}

// CLI interface
if (require.main === module) {
    const discovery = new IncrementalUIDiscovery();
    discovery.startInteractiveDiscovery().catch(error => {
        console.error('Discovery failed:', error);
        process.exit(1);
    });
}

module.exports = IncrementalUIDiscovery;