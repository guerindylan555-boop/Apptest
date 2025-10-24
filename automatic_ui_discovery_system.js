#!/usr/bin/env node

/**
 * Automatic UI Discovery System for MaynDrive
 *
 * This script automatically explores the entire MaynDrive app,
 * discovers all UI elements, records their properties,
 * and generates comprehensive automation-ready data.
 *
 * Features:
 * - Automatic app exploration and state detection
 * - Systematic UI element discovery
 * - Interactive element mapping
 * - Automation script generation
 * - Comprehensive reporting
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Configuration
const CONFIG = {
    device: {
        serial: process.env.EMULATOR_SERIAL || process.env.ADB_SERIAL || 'emulator-5556',
        timeout: 15000,
        retryAttempts: 3
    },
    app: {
        package: 'fr.mayndrive.app',
        mainActivity: 'city.kot.knotapp.ui.MainActivity'
    },
    discovery: {
        maxDepth: 10,
        explorationDelay: 2000,
        screenshotDelay: 500,
        maxScreens: 50,
        interactiveOnly: true
    },
    output: {
        directory: './discovered_ui_data',
        screenshots: './screenshots',
        reports: './reports'
    }
};

class AutomaticUIDiscovery {
    constructor() {
        this.discoveredStates = new Map();
        this.uiElements = new Map();
        this.interactiveElements = new Map();
        this.screenshots = [];
        this.explorationPath = [];
        this.currentDepth = 0;
        this.visitedScreens = new Set();
        this.sessionId = Date.now();

        // Initialize output directories
        this.initializeDirectories();

        // Logging
        this.logBuffer = [];
        this.debugMode = process.env.DEBUG_MODE === 'true';
    }

    initializeDirectories() {
        for (const dir of [CONFIG.output.directory, CONFIG.output.screenshots, CONFIG.output.reports]) {
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
        }
    }

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

    async adb(args, options = {}) {
        const command = `adb -s ${CONFIG.device.serial} ${args}`;
        this.debug(`ADB: ${command}`);

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
            this.info(`Tapping: ${label} at (${x}, ${y})`);
        }

        await this.adb(`shell input tap ${x} ${y}`);
        await this.sleep(500);
    }

    async swipe(startX, startY, endX, endY, duration = 300) {
        this.debug(`Swiping from (${startX}, ${startY}) to (${endX}, ${endY})`);
        await this.adb(`shell input swipe ${startX} ${startY} ${endX} ${endY} ${duration}`);
        await this.sleep(1000);
    }

    async sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async takeScreenshot(screenName) {
        const filename = `${screenName}_${this.sessionId}.png`;
        const devicePath = `/sdcard/${filename}`;
        const localPath = path.join(CONFIG.output.screenshots, filename);

        try {
            await this.adb(`shell screencap -p ${devicePath}`);
            await this.adb(`pull ${devicePath} ${JSON.stringify(localPath)}`);

            this.screenshots.push({
                name: screenName,
                filename: filename,
                path: localPath,
                timestamp: new Date().toISOString()
            });

            this.debug(`Screenshot saved: ${filename}`);
            return localPath;
        } catch (error) {
            this.warn(`Failed to take screenshot: ${screenName}`, error);
            return null;
        }
    }

    async dumpUI(screenName) {
        const filename = `${screenName}_${this.sessionId}.xml`;
        const devicePath = `/sdcard/${filename}`;
        const localPath = path.join(CONFIG.output.directory, filename);

        try {
            await this.adb(`exec-out uiautomator dump ${devicePath}`);
            await this.adb(`pull ${devicePath} ${JSON.stringify(localPath)}`);

            const xml = fs.readFileSync(localPath, 'utf8');
            return xml;
        } catch (error) {
            this.warn(`Failed to dump UI for: ${screenName}`, error);
            return null;
        }
    }

    parseUIElements(xmlContent, screenName) {
        const elements = [];
        const nodeRegex = /<node[^>]*>(.*?)<\/node>/gs;
        let match;

        while ((match = nodeRegex.exec(xmlContent)) !== null) {
            const element = this.parseNode(match[0], screenName);
            if (element) {
                elements.push(element);

                // Store in global maps
                const signature = element.signature;
                this.uiElements.set(signature, element);

                if (element.clickable || element.interactionType !== 'STATIC') {
                    this.interactiveElements.set(signature, element);
                }
            }
        }

        return elements;
    }

    parseNode(nodeXml, screenName) {
        const attributes = this.extractAttributes(nodeXml);

        if (!attributes.bounds) return null;

        const bounds = this.parseBounds(attributes.bounds);
        const element = {
            signature: this.generateSignature(attributes),
            screenName: screenName,
            id: attributes['resource-id'] || null,
            text: attributes.text || null,
            contentDesc: attributes['content-desc'] || null,
            class: attributes.class || null,
            package: attributes.package || null,
            clickable: attributes.clickable === 'true',
            enabled: attributes.enabled === 'true',
            focusable: attributes.focusable === 'true',
            focused: attributes.focused === 'true',
            scrollable: attributes.scrollable === 'true',
            longClickable: attributes['long-clickable'] === 'true',
            password: attributes.password === 'true',
            selected: attributes.selected === 'true',
            checkable: attributes.checkable === 'true',
            checked: attributes.checked === 'true',
            bounds: bounds,
            centerPoint: this.calculateCenter(bounds),
            xpath: this.generateXPath(attributes),
            confidence: this.calculateConfidence(attributes),
            interactionType: this.determineInteractionType(attributes),
            parent: null,
            children: []
        };

        return element;
    }

    extractAttributes(nodeXml) {
        const attrRegex = /(\w+(?:-\w+)*)="([^"]*)"/g;
        const attributes = {};
        let match;

        while ((match = attrRegex.exec(nodeXml)) !== null) {
            attributes[match[1]] = match[2];
        }

        return attributes;
    }

    parseBounds(boundsStr) {
        const match = boundsStr.match(/\[(\d+),(\d+)\]\[(\d+),(\d+)\]/);
        if (match) {
            return {
                left: parseInt(match[1]),
                top: parseInt(match[2]),
                right: parseInt(match[3]),
                bottom: parseInt(match[4]),
                width: parseInt(match[3]) - parseInt(match[1]),
                height: parseInt(match[4]) - parseInt(match[2])
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

    generateSignature(attributes) {
        const parts = [
            attributes.class || 'unknown',
            attributes.text || '',
            attributes['content-desc'] || '',
            attributes['resource-id'] || ''
        ];
        return parts.join('|').replace(/[^\w|]/g, '_');
    }

    generateXPath(attributes) {
        const parts = [];

        if (attributes.class) {
            parts.push(`@class='${attributes.class}'`);
        }
        if (attributes.text) {
            parts.push(`@text='${attributes.text}'`);
        }
        if (attributes['content-desc']) {
            parts.push(`@content-desc='${attributes['content-desc']}'`);
        }
        if (attributes['resource-id']) {
            parts.push(`@resource-id='${attributes['resource-id']}'`);
        }

        return `//node[${parts.join(' and ')}]`;
    }

    calculateConfidence(attributes) {
        let confidence = 0;

        if (attributes.text && attributes.text.length > 0) confidence += 40;
        if (attributes['resource-id'] && attributes['resource-id'].length > 0) confidence += 35;
        if (attributes['content-desc'] && attributes['content-desc'].length > 0) confidence += 20;
        if (attributes.clickable === 'true') confidence += 5;

        return Math.min(confidence, 100);
    }

    determineInteractionType(attributes) {
        if (attributes.clickable === 'true') {
            if (attributes.class && attributes.class.includes('EditText')) {
                return 'INPUT';
            } else if (attributes.text && (
                attributes.text.includes('Login') ||
                attributes.text.includes('Signup') ||
                attributes.text.includes('Start') ||
                attributes.text.includes('Lock') ||
                attributes.text.includes('Unlock') ||
                attributes.text.includes('Ride') ||
                attributes.text.includes('Continue') ||
                attributes.text.includes('Confirm') ||
                attributes.text.includes('Dismiss') ||
                attributes.text.includes('Ok') ||
                attributes.text.includes('Cancel')
            )) {
                return 'ACTION_BUTTON';
            } else {
                return 'CLICKABLE';
            }
        } else if (attributes.scrollable === 'true') {
            return 'SCROLLABLE';
        } else if (attributes.class && attributes.class.includes('EditText')) {
            return 'INPUT';
        } else if (attributes.text && attributes.text.length > 0) {
            return 'TEXT_LABEL';
        }

        return 'STATIC';
    }

    detectScreenState(xmlContent) {
        if (!xmlContent) return 'UNKNOWN';

        // Check for specific screen indicators
        if (xmlContent.includes('Login') && xmlContent.includes('Signup')) {
            return 'LOGIN_SHEET';
        }

        if (xmlContent.includes('Email') && xmlContent.includes('Password')) {
            return 'LOGIN_FORM';
        }

        if (xmlContent.includes('Scan & ride')) {
            return 'HOME_SCREEN';
        }

        if (xmlContent.includes('Buy a Pass')) {
            return 'HOME_SCREEN_WITH_PASS';
        }

        if (xmlContent.includes('TUF055') && xmlContent.includes('Start to ride')) {
            return 'VEHICLE_UNLOCKED';
        }

        if (xmlContent.includes('TUF055') && xmlContent.includes('End your trip')) {
            return 'VEHICLE_UNLOCKED_LOCK_OPTION';
        }

        if (xmlContent.includes('Unlocking a vehicle')) {
            return 'UNLOCKING';
        }

        if (xmlContent.includes('Vehicle unlocked')) {
            return 'UNLOCK_SUCCESS';
        }

        if (xmlContent.includes('Vehicle locked')) {
            return 'LOCK_SUCCESS';
        }

        if (xmlContent.includes('No parking') && xmlContent.includes('ride remains active')) {
            return 'LOCK_FAILED_NO_PARKING';
        }

        if (xmlContent.includes('consent') || xmlContent.includes("Let's go!")) {
            return 'CONSENT_SCREEN';
        }

        if (xmlContent.includes('An error occurred')) {
            return 'ERROR_DIALOG';
        }

        if (xmlContent.includes('isn\'t responding')) {
            return 'CRASH_DIALOG';
        }

        return 'UNKNOWN';
    }

    async exploreApp() {
        this.info('Starting automatic UI discovery');
        this.info(`Device: ${CONFIG.device.serial}`);
        this.info(`Package: ${CONFIG.app.package}`);
        this.info(`Max Screens: ${CONFIG.discovery.maxScreens}`);

        try {
            // Reset and launch app
            await this.resetAndLaunchApp();

            // Start systematic exploration
            await this.systematicExploration();

            // Generate reports
            await this.generateReports();

            this.info('UI discovery completed successfully');

        } catch (error) {
            this.error('UI discovery failed', error);
            throw error;
        }
    }

    async resetAndLaunchApp() {
        this.info('Resetting and launching app');

        await this.adb(`shell am force-stop ${CONFIG.app.package}`);
        await this.sleep(2000);

        await this.adb(`shell pm clear ${CONFIG.app.package}`);
        await this.sleep(1000);

        await this.adb(`shell am start -n ${CONFIG.app.package}/${CONFIG.app.mainActivity}`);
        await this.sleep(6000);

        // Take initial screenshot
        await this.takeScreenshot('initial_launch');
    }

    async systematicExploration() {
        this.info('Starting systematic exploration');

        let screenCount = 0;
        let currentScreen = 'initial';
        this.explorationPath.push(currentScreen);

        while (screenCount < CONFIG.discovery.maxScreens && this.currentDepth < CONFIG.discovery.maxDepth) {
            this.info(`Exploring screen ${screenCount + 1}: ${currentScreen}`);

            // Analyze current screen
            const screenData = await this.analyzeScreen(currentScreen, screenCount);
            this.discoveredStates.set(currentScreen, screenData);

            // Find all interactive elements
            const interactiveElements = Array.from(this.interactiveElements.values())
                .filter(el => el.screenName === currentScreen);

            this.info(`Found ${interactiveElements.length} interactive elements on screen ${currentScreen}`);

            // Try each interactive element
            for (const element of interactiveElements) {
                if (screenCount >= CONFIG.discovery.maxScreens) break;

                const elementScreenName = await this.interactWithElement(element, currentScreen, screenCount);
                if (elementScreenName && !this.visitedScreens.has(elementScreenName)) {
                    screenCount++;
                    currentScreen = elementScreenName;
                    this.explorationPath.push(currentScreen);
                    this.visitedScreens.add(currentScreen);
                    break;
                }
            }

            // If no new screens discovered, try systematic exploration
            if (this.explorationPath.length > 1) {
                const backToPrevious = await this.goBackAndCheckNewScreen();
                if (backToPrevious) {
                    screenCount++;
                    currentScreen = backToPrevious;
                    this.explorationPath.push(currentScreen);
                } else {
                    break;
                }
            } else {
                // Try systematic taps and swipes
                const discovered = await this.systematicInteractions();
                if (discovered) {
                    screenCount++;
                } else {
                    break;
                }
            }

            await this.sleep(CONFIG.discovery.explorationDelay);
        }

        this.info(`Exploration completed. Discovered ${this.discoveredStates.size} unique states`);
    }

    async analyzeScreen(screenName, screenIndex) {
        const screenshotPath = await this.takeScreenshot(`screen_${screenIndex}_${screenName}`);
        const xmlContent = await this.dumpUI(`screen_${screenIndex}_${screenName}`);

        if (!xmlContent) {
            return null;
        }

        const elements = this.parseUIElements(xmlContent, screenName);
        const screenState = this.detectScreenState(xmlContent);

        return {
            screenName,
            screenIndex,
            screenshotPath,
            xmlContent,
            elements,
            elementCount: elements.length,
            interactiveCount: elements.filter(e => e.clickable || e.interactionType !== 'STATIC').length,
            screenState,
            timestamp: new Date().toISOString(),
            depth: this.currentDepth,
            explorationPath: [...this.explorationPath]
        };
    }

    async interactWithElement(element, currentScreenName, screenIndex) {
        this.info(`Interacting with element: ${element.signature}`);

        // Before interaction
        const beforeState = await this.detectCurrentState();
        await this.sleep(500);

        // Perform interaction
        await this.tap(element.centerPoint.x, element.centerPoint.y, element.signature);
        await this.sleep(2000);

        // After interaction
        const afterState = await this.detectCurrentState();
        await this.sleep(1000);

        // If state changed, return new screen name
        if (afterState !== beforeState) {
            const newScreenName = `screen_${screenIndex + 1}_${afterState.toLowerCase().replace(/\s+/g, '_')}`;
            return newScreenName;
        }

        return null;
    }

    async systematicInteractions() {
        this.info('Performing systematic interactions');

        const interactions = [
            // Tap corners and edges
            { x: 100, y: 100, description: 'top-left corner' },
            { x: 980, y: 100, description: 'top-right corner' },
            { x: 100, y: 1600, description: 'bottom-left corner' },
            { x: 980, y: 1600, description: 'bottom-right corner' },
            { x: 540, y: 900, description: 'center screen' },

            // Swipes
            { startX: 100, startY: 900, endX: 980, endY: 900, description: 'horizontal swipe right' },
            { startX: 980, startY: 900, endX: 100, endY: 900, description: 'horizontal swipe left' },
            { startX: 540, startY: 200, endX: 540, endY: 1600, description: 'vertical swipe down' },
            { startX: 540, startY: 1600, endX: 540, endY: 200, description: 'vertical swipe up' },

            // Common button areas
            { x: 540, y: 2200, description: 'bottom center' },
            { x: 540, y: 400, description: 'top center' },
            { x: 540, y: 1200, description: 'middle center' }
        ];

        let newStateDiscovered = false;

        for (const interaction of interactions) {
            const beforeState = await this.detectCurrentState();

            if (interaction.swipe) {
                await this.swipe(interaction.startX, interaction.startY, interaction.endX, interaction.endY, interaction.duration || 300);
            } else {
                await this.tap(interaction.x, interaction.y, interaction.description);
            }

            await this.sleep(1500);

            const afterState = await this.detectCurrentState();

            if (afterState !== beforeState) {
                const newScreenName = `screen_auto_${afterState.toLowerCase().replace(/\s+/g, '_')}`;
                this.explorationPath.push(newScreenName);
                this.visitedScreens.add(newScreenName);
                newStateDiscovered = true;

                this.info(`Discovered new state: ${afterState} via ${interaction.description}`);

                // Analyze the new screen
                await this.analyzeScreen(newScreenName, this.screenshots.length);
                break;
            }
        }

        return newStateDiscovered;
    }

    async goBackAndCheckNewScreen() {
        this.info('Going back and checking for new screen');

        const beforeState = await this.detectCurrentState();

        await this.adb('shell input keyevent KEYCODE_BACK');
        await this.sleep(2000);

        const afterState = await this.detectCurrentState();

        if (afterState !== beforeState) {
            const newScreenName = `screen_back_${afterState.toLowerCase().replace(/\s+/g, '_')}`;
            this.explorationPath.push(newScreenName);
            this.visitedScreens.add(newScreenName);

            await this.analyzeScreen(newScreenName, this.screens.length);
            return newScreenName;
        }

        return null;
    }

    async generateReports() {
        this.info('Generating comprehensive reports');

        // 1. Generate automation scripts
        await this.generateAutomationScripts();

        // 2. Generate element database
        await this.generateElementDatabase();

        // 3. Generate interactive element map
        await this.generateInteractiveElementMap();

        // 4. Generate exploration report
        await this.generateExplorationReport();

        // 5. Generate summary statistics
        await this.generateSummaryStatistics();
    }

    async generateAutomationScripts() {
        this.info('Generating automation scripts');

        const scriptContent = this.generateMainAutomationScript();
        const scriptPath = path.join(CONFIG.output.directory, 'generated_automation.js');

        fs.writeFileSync(scriptPath, scriptContent);
        this.info(`Generated automation script: ${scriptPath}`);

        // Generate individual flow scripts
        await this.generateFlowScripts();
    }

    generateMainAutomationScript() {
        return `#!/usr/bin/env node

/**
 * Generated Automation Script for MaynDrive
 *
 * This script was automatically generated by the UI Discovery System
 * and contains all discovered interactive elements and their reliable targeting strategies.
 *
 * Generated: ${new Date().toISOString()}
 * Session: ${this.sessionId}
 */

const { execSync } = require('child_process');
const fs = require('fs');

const CONFIG = {
    device: {
        serial: '${CONFIG.device.serial}',
        timeout: 10000
    },
    app: {
        package: '${CONFIG.app.package}'
    }
};

class GeneratedAutomation {
    constructor() {
        this.elementStrategies = ${JSON.stringify(this.generateElementStrategies(), null, 2)};
    }

    async adb(args) {
        const command = \`adb -s \${CONFIG.device.serial} \${args}\`;
        execSync(command, { stdio: 'inherit' });
    }

    async sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async tap(x, y, label = '') {
        if (label) console.log(\`[tap] \${label} at (\${x}, \${y})\`);
        await this.adb(\`shell input tap \${x} \${y}\`);
        await this.sleep(500);
    }

    async smartTap(elementKey) {
        const strategies = this.elementStrategies[elementKey];
        if (!strategies || strategies.length === 0) {
            throw new Error(\`No strategies found for element: \${elementKey}\`);
        }

        // Try each strategy until one succeeds
        for (const strategy of strategies) {
            const result = await this.tryStrategy(strategy);
            if (result) {
                await this.tap(result.x, result.y, elementKey);
                return true;
            }
        }

        throw new Error(\`Could not find element: \${elementKey}\`);
    }

    async tryStrategy(strategy) {
        switch (strategy.type) {
            case 'text':
                return await this.findByText(strategy.value, strategy.exact);
            case 'contentDesc':
                return await this.findByContentDesc(strategy.value, strategy.exact);
            case 'resourceId':
                return await this.findByResourceId(strategy.value);
            case 'coordinates':
                return strategy.fallback;
            default:
                return null;
        }
    }

    async findByText(text, exact = true) {
        const xml = await this.dumpUI();
        if (!xml) return null;

        const escapedText = text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regex = exact ?
            new RegExp(`text="${escapedText}"`, 'g') :
            new RegExp(`text="[^"]*${escapedText}[^"]*"`, 'g');

        const match = regex.exec(xml);
        if (match) {
            const boundsMatch = match[0].match(/bounds="\\[(\\d+),(\\d+)\\]\\[(\\d+),(\\d+)\\]"/);
            if (boundsMatch) {
                return {
                    x: Math.floor((parseInt(boundsMatch[1]) + parseInt(boundsMatch[3])) / 2),
                    y: Math.floor((parseInt(boundsMatch[2]) + parseInt(boundsMatch[4])) / 2)
                };
            }
        }
        return null;
    }

    async findByContentDesc(contentDesc, exact = true) {
        const xml = await this.dumpUI();
        if (!xml) return null;

        const regex = exact ?
            new RegExp(\`content-desc="\${contentDesc.replace(/[.*+?^${}()|[\]\\]/g, '\\\\$&')}"\`, 'g') :
            new RegExp(\`content-desc="[^"]*\${contentDesc.replace(/[.*+?^${}()|[\]\\]/g, '\\\\$&')}[^"]*"\`, 'g');

        const match = regex.exec(xml);
        if (match) {
            const boundsMatch = match[0].match(/bounds="\\[(\\d+),(\\d+)\\]\\[(\\d+),(\\d+)\\]"/);
            if (boundsMatch) {
                return {
                    x: Math.floor((parseInt(boundsMatch[1]) + parseInt(boundsMatch[3])) / 2),
                    y: Math.floor((parseInt(boundsMatch[2]) + parseInt(boundsMatch[4])) / 2)
                };
            }
        }
        return null;
    }

    async findByResourceId(resourceId) {
        const xml = await this.dumpUI();
        if (!xml) return null;

        const regex = new RegExp(\`resource-id="\${resourceId}"\`, 'g');
        const match = regex.exec(xml);
        if (match) {
            const nodeStart = xml.lastIndexOf('<node', match.index);
            const nodeEnd = xml.indexOf('/>', match.index) + 2;
            const nodeXml = xml.substring(nodeStart, nodeEnd);

            const boundsMatch = nodeXml.match(/bounds="\\[(\\d+),(\\d+)\\]\\[(\\d+),(\\d+)\\]"/);
            if (boundsMatch) {
                return {
                    x: Math.floor((parseInt(boundsMatch[1]) + parseInt(boundsMatch[3])) / 2),
                    y: Math.floor((parseInt(boundsMatch[2]) + parseInt(boundsMatch[4])) / 2)
                };
            }
        }
        return null;
    }

    async dumpUI() {
        const devicePath = \`/sdcard/temp_dump.xml\`;
        const localPath = './temp_dump.xml';

        try {
            await this.adb(\`exec-out uiautomator dump \${devicePath}\`);
            await this.adb(\`pull \${devicePath} \${JSON.stringify(localPath)}\`);
            return fs.readFileSync(localPath, 'utf8');
        } catch (error) {
            return null;
        }
    }

    // Generated flow methods
${this.generateFlowMethods()}

    // Utility methods
    async resetApp() {
        console.log('[reset] Resetting app');
        await this.adb(\`shell am force-stop \${CONFIG.app.package}\`);
        await this.sleep(2000);
        await this.adb(\`shell pm clear \${CONFIG.app.package}\`);
        await this.sleep(1000);
        await this.adb(\`shell am start -n \${CONFIG.app.package}/${CONFIG.app.mainActivity}\`);
        await this.sleep(6000);
    }

    async waitForState(expectedState, timeout = 10000) {
        const startTime = Date.now();

        while (Date.now() - startTime < timeout) {
            const xml = await this.dumpUI();
            if (!xml) continue;

            let currentState = 'unknown';
            if (xml.includes('\${expectedState}') ||
                (xml.includes('\${expectedState.toLowerCase()}'))) {
                currentState = '\${expectedState}';
            }

            if (currentState !== 'unknown') {
                console.log(\`[state] Reached state: \${expectedState}\`);
                return true;
            }

            await this.sleep(1000);
        }

        throw new Error(\`Timeout waiting for state: \${expectedState}\`);
    }
}

// CLI interface
if (require.main === module) {
    const args = process.argv.slice(2);
    const command = args[0];

    const automation = new GeneratedAutomation();

    async function runCommand() {
        try {
            switch (command) {
                case 'reset':
                    await automation.resetApp();
                    break;

                case 'login':
                    await automation.loginFlow();
                    break;

                case 'unlock':
                    await automation.unlockFlow();
                    break;

                case 'lock':
                    await automation.lockFlow();
                    break;

                case 'complete':
                    await automation.completeFlow();
                    break;

                default:
                    console.log('Available commands:');
                    console.log('  reset   - Reset app state');
                    console.log('  login   - Perform login flow');
                    console.log('  unlock  - Unlock vehicle');
                    console.log('  lock    - Lock vehicle');
                    console.log('  complete - Complete login + unlock flow');
                    break;
            }
        } catch (error) {
            console.error('Command failed:', error.message);
            process.exit(1);
        }
    }

    runCommand();
}

module.exports = GeneratedAutomation;
`;
    }

    generateFlowMethods() {
        const flows = this.identifyDiscoveredFlows();
        const methods = [];

        for (const flow of flows) {
            methods.push(this.generateFlowMethod(flow));
        }

        return methods.join('\n\n');
    }

    identifyDiscoveredFlows() {
        const flows = [];

        // Analyze exploration path to identify common flows
        const states = Array.from(this.discoveredStates.keys());

        if (states.includes('LOGIN_SHEET') || states.includes('LOGIN_FORM')) {
            flows.push({
                name: 'loginFlow',
                description: 'Login to the application',
                steps: ['LOGIN_SHEET', 'LOGIN_FORM', 'HOME_SCREEN']
            });
        }

        if (states.includes('VEHICLE_UNLOCKED') || states.includes('UNLOCKING') || states.includes('UNLOCK_SUCCESS')) {
            flows.push({
                name: 'unlockFlow',
                description: 'Unlock a vehicle',
                steps: ['HOME_SCREEN', 'VEHICLE_UNLOCKED', 'UNLOCKING', 'UNLOCK_SUCCESS']
            });
        }

        if (states.includes('VEHICLE_UNLOCKED') || states.includes('LOCK_SUCCESS')) {
            flows.push({
                name: 'lockFlow',
                description: 'Lock a vehicle',
                steps: ['VEHICLE_UNLOCKED', 'LOCK_SUCCESS']
            });
        }

        return flows;
    }

    generateFlowMethod(flow) {
        const methodName = flow.name.charAt(0).toUpperCase() + flow.name.slice(1);

        return `    async ${methodName}() {
        console.log('[flow] Starting ${flow.description}');

        try {
${flow.steps.map((step, index) => `
            // ${step} - ${this.getStepDescription(step)}
            await this.smartTap('${this.getElementKeyForState(step)}');
            await this.sleep(1000);
            await this.waitForState('${step}');
        `).join('')}

            console.log(\`[flow] \${flow.description} completed successfully\`);
            return true;

        } catch (error) {
            console.error(\`[flow] \${flow.description} failed: \${error.message}\`);
            throw error;
        }
    }`;
    }

    getStepDescription(state) {
        const descriptions = {
            'LOGIN_SHEET': 'Open login sheet',
            'LOGIN_FORM': 'Fill login form',
            'HOME_SCREEN': 'Navigate to home screen',
            'VEHICLE_UNLOCKED': 'Access vehicle panel',
            'UNLOCKING': 'Start unlock process',
            'UNLOCK_SUCCESS': 'Confirm unlock success',
            'LOCK_SUCCESS': 'Confirm lock success'
        };

        return descriptions[state] || state;
    }

    getElementKeyForState(state) {
        const stateElementMap = ${JSON.stringify(this.generateStateElementMap(), null, 2)};
        return stateElementMap[state] || 'UNKNOWN';
    }

    generateStateElementMap() {
        const map = {};

        // Map states to reliable elements based on discovery data
        const states = Array.from(this.discoveredStates.keys());

        if (states.includes('LOGIN_SHEET')) {
            const loginSheetElement = Array.from(this.interactiveElements.values())
                .find(el => el.text && el.text.toLowerCase().includes('login'));
            if (loginSheetElement) {
                map['LOGIN_SHEET'] = loginSheetElement.signature;
            }
        }

        if (states.includes('LOGIN_FORM')) {
            const submitButton = Array.from(this.interactiveElements.values())
                .find(el => el.text && el.text.toLowerCase().includes('login'));
            if (submitButton) {
                map['LOGIN_FORM'] = submitButton.signature;
            }
        }

        if (states.includes('HOME_SCREEN')) {
            const scanRideButton = Array.from(this.interactiveElements.values())
                .find(el => el.text && el.text.includes('Scan & ride'));
            if (scanRideButton) {
                map['HOME_SCREEN'] = scanRideButton.signature;
            }
        }

        if (states.includes('VEHICLE_UNLOCKED')) {
            const startRideButton = Array.from(this.interactiveElements.values())
                .find(el => el.text && el.text.includes('Start to ride'));
            if (startRideButton) {
                map['VEHICLE_UNLOCKED'] = startRideButton.signature;
            }
        }

        return map;
    }

    generateElementStrategies() {
        const strategies = {};

        for (const [signature, element] of this.interactiveElements) {
            const elementStrategies = [];

            // Primary strategies based on element properties
            if (element.text && element.text.length > 0) {
                elementStrategies.push({
                    type: 'text',
                    value: element.text,
                    exact: true,
                    confidence: element.confidence
                });
                elementStrategies.push({
                    type: 'text',
                    value: element.text,
                    exact: false,
                    confidence: element.confidence - 10
                });
            }

            if (element.contentDesc && element.contentDesc.length > 0) {
                elementStrategies.push({
                    type: 'contentDesc',
                    value: element.contentDesc,
                    exact: true,
                    confidence: element.confidence
                });
                elementStrategies.push({
                    type: 'contentDesc',
                    value: element.contentDesc,
                    exact: false,
                    confidence: element.confidence - 10
                });
            }

            if (element.id && element.id.length > 0 && !element.id.startsWith('android:')) {
                elementStrategies.push({
                    type: 'resourceId',
                    value: element.id,
                    confidence: element.confidence
                });
            }

            // Fallback to coordinates
            if (element.centerPoint) {
                elementStrategies.push({
                    type: 'coordinates',
                    fallback: element.centerPoint,
                    confidence: 20
                });
            }

            // Sort by confidence
            elementStrategies.sort((a, b) => b.confidence - a.confidence);

            strategies[signature] = elementStrategies;
        }

        return strategies;
    }

    async generateElementDatabase() {
        this.info('Generating element database');

        const database = {
            metadata: {
                generatedAt: new Date().toISOString(),
                sessionId: this.sessionId,
                device: CONFIG.device.serial,
                app: CONFIG.app.package,
                totalElements: this.uiElements.size,
                interactiveElements: this.interactiveElements.size,
                discoveredScreens: this.discoveredStates.size
            },
            elements: {},
            interactiveElements: {},
            screens: {}
        };

        // Add all elements
        for (const [signature, element] of this.uiElements.entries()) {
            database.elements[signature] = {
                ...element,
                discoveredIn: element.screenName,
                confidence: element.confidence,
                interactionType: element.interactionType
            };
        }

        // Add interactive elements with enhanced data
        for (const [signature, element] of this.interactiveElements.entries()) {
            database.interactiveElements[signature] = {
                ...element,
                discoveredIn: element.screenName,
                confidence: element.confidence,
                interactionType: element.interactionType,
                automationReady: element.confidence >= 30
            };
        }

        // Add screen data
        for (const [screenName, screenData] of this.discoveredStates.entries()) {
            database.screens[screenName] = {
                ...screenData,
                elementCount: screenData.elements.length,
                interactiveCount: screenData.elements.filter(e => e.clickable || e.interactionType !== 'STATIC').length
            };
        }

        const databasePath = path.join(CONFIG.output.directory, 'element_database.json');
        fs.writeFileSync(databasePath, JSON.stringify(database, null, 2));

        this.info(`Element database saved: ${databasePath}`);
    }

    async generateInteractiveElementMap() {
        this.info('Generating interactive element map');

        const elementMap = {
            metadata: {
                generatedAt: new Date().toISOString(),
                sessionId: this.sessionId,
                totalInteractiveElements: this.interactiveElements.size
            },
            elements: {}
        };

        // Organize interactive elements by screen
        for (const [signature, element] of this.interactiveElements.entries()) {
            if (!elementMap.elements[element.screenName]) {
                elementMap.elements[element.screenName] = [];
            }

            elementMap.elements[element.screenName].push({
                signature: element.signature,
                text: element.text,
                contentDesc: element.contentDesc,
                resourceId: element.id,
                class: element.class,
                confidence: element.confidence,
                centerPoint: element.centerPoint,
                bounds: element.bounds,
                interactionType: element.interactionType,
                xpath: element.xpath
            });
        }

        const mapPath = path.join(CONFIG.output.directory, 'interactive_element_map.json');
        fs.writeFileSync(mapPath, JSON.stringify(elementMap, null, 2));

        this.info(`Interactive element map saved: ${mapPath}`);
    }

    async generateExplorationReport() {
        this.info('Generating exploration report');

        const report = {
            metadata: {
                generatedAt: new Date().toISOString(),
                sessionId: this.sessionId,
                device: CONFIG.device.serial,
                app: CONFIG.app.package,
                maxDepth: CONFIG.discovery.maxDepth,
                maxScreens: CONFIG.discovery.maxScreens
            },
            exploration: {
                path: this.explorationPath,
                totalScreensExplored: this.explorationPath.length,
                uniqueStatesDiscovered: this.discoveredStates.size,
                screenshotsTaken: this.screenshots.length,
                explorationDepth: this.currentDepth
            },
            discoveredStates: {},
            statistics: this.calculateStatistics(),
            recommendations: this.generateRecommendations()
        };

        // Add state details
        for (const [stateName, stateData] of this.discoveredStates.entries()) {
            report.discoveredStates[stateName] = {
                elementCount: stateData.elements.length,
                interactiveCount: stateData.elements.filter(e => e.clickable || e.interactionType !== 'STATIC').length,
                screenState: stateData.screenState,
                depth: stateData.depth,
                screenshotPath: stateData.screenshotPath
            };
        }

        const reportPath = path.join(CONFIG.output.reports, 'exploration_report.json');
        fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

        this.info(`Exploration report saved: ${reportPath}`);
    }

    calculateStatistics() {
        const totalElements = this.uiElements.size;
        const interactiveElements = this.interactiveElements.size;
        const states = this.discoveredStates.size;

        const interactionTypes = {};
        for (const element of this.interactiveElements.values()) {
            interactionTypes[element.interactionType] = (interactionTypes[element.interactionType] || 0) + 1;
        }

        const confidenceLevels = {
            high: 0,      // 70-100
            medium: 0,    // 40-69
            low: 0       // 0-39
        };

        for (const element of this.interactiveElements.values()) {
            if (element.confidence >= 70) confidenceLevels.high++;
            else if (element.confidence >= 40) confidenceLevels.medium++;
            else confidenceLevels.low++;
        }

        return {
            totalElements,
            interactiveElements,
            discoveredStates: states,
            interactionTypes,
            confidenceLevels,
            averageElementsPerScreen: totalElements / Math.max(states, 1),
            averageInteractivePerScreen: interactiveElements / Math.max(states, 1)
        };
    }

    generateRecommendations() {
        const recommendations = [];

        // High-confidence elements for reliable targeting
        const highConfidenceElements = Array.from(this.interactiveElements.values())
            .filter(el => el.confidence >= 70);

        if (highConfidenceElements.length > 0) {
            recommendations.push({
                priority: 'HIGH',
                type: 'RELIABLE_TARGETING',
                description: `Found ${highConfidenceElements.length} high-confidence elements suitable for reliable automation`,
                examples: highConfidenceElements.slice(0, 5).map(el => ({
                    signature: el.signature,
                    text: el.text,
                    confidence: el.confidence,
                    screen: el.screenName
                }))
            });
        }

        // Text-based targeting opportunities
        const textElements = Array.from(this.interactiveElements.values())
            .filter(el => el.text && el.text.length > 0);

        if (textElements.length > 0) {
            recommendations.push({
                priority: 'HIGH',
                type: 'TEXT_BASED_TARGETING',
                description: `${textElements.length} interactive elements have text content for reliable targeting`,
                examples: textElements.slice(0, 8).map(el => el.text)
            });
        }

        // Resource ID opportunities
        const resourceIdElements = Array.from(this.interactiveElements.values())
            .filter(el => el.id && el.id.length > 0 && !el.id.startsWith('android:'));

        if (resourceIdElements.length > 0) {
            recommendations.push({
                priority: 'MEDIUM',
                type: 'RESOURCE_ID_TARGETING',
                description: `${resourceIdElements.length} elements have resource IDs for precise targeting`,
                examples: resourceIdElements.slice(0, 5).map(el => el.id)
            });
        }

        // Exploration completeness
        if (this.discoveredStates.size < 10) {
            recommendations.push({
                priority: 'MEDIUM',
                type: 'EXPLORATION_COMPLETENESS',
                description: `Only ${this.discoveredStates.size} states discovered. Consider increasing exploration depth or adding more systematic interactions.`
            });
        }

        // Error handling recommendations
        recommendations.push({
            priority: 'LOW',
            type: 'ERROR_HANDLING',
            description: 'Implement comprehensive error handling for network timeouts, app crashes, and unexpected dialogs'
        });

        return recommendations;
    }

    async generateSummaryStatistics() {
        this.info('Generating summary statistics');

        const stats = this.calculateStatistics();

        const summary = {
            timestamp: new Date().toISOString(),
            sessionId: this.sessionId,
            device: CONFIG.device.serial,
            app: CONFIG.app.package,
            discovery: {
                totalScreensExplored: this.explorationPath.length,
                uniqueStatesDiscovered: this.discoveredStates.size,
                totalElements: stats.totalElements,
                interactiveElements: stats.interactiveElements,
                screenshotsTaken: this.screenshots.length,
                explorationDepth: this.currentDepth
            },
            elements: {
                byType: stats.interactionTypes,
                byConfidence: stats.confidenceLevels,
                averagePerScreen: stats.averageElementsPerScreen,
                interactivePerScreen: stats.averageInteractivePerScreen
            },
            recommendations: this.generateRecommendations()
        };

        const summaryPath = path.join(CONFIG.output.reports, 'summary_statistics.json');
        fs.writeFileSync(summaryPath, JSON.stringify(summary, null, 2));

        this.info(`Summary statistics saved: ${summaryPath}`);
    }

    saveSessionData() {
        const sessionData = {
            metadata: {
                sessionId: this.sessionId,
                timestamp: new Date().toISOString(),
                device: CONFIG.device.serial,
                app: CONFIG.app.package
            },
            discoveredStates: Object.fromEntries(this.discoveredStates),
            uiElements: Object.fromEntries(this.uiElements),
            interactiveElements: Object.fromEntries(this.interactiveElements),
            explorationPath: this.explorationPath,
            screenshots: this.screenshots,
            logBuffer: this.logBuffer
        };

        const sessionPath = path.join(CONFIG.output.directory, `session_${this.sessionId}.json`);
        fs.writeFileSync(sessionPath, JSON.stringify(sessionData, null, 2));

        this.info(`Session data saved: ${sessionPath}`);
    }
}

// CLI interface
if (require.main === module) {
    console.log('Automatic UI Discovery System for MaynDrive');
    console.log('====================================');

    const discovery = new AutomaticUIDiscovery();

    discovery.exploreApp()
        .then(() => {
            console.log('\n✅ Discovery completed successfully!');
            console.log('\n📊 Reports generated in:', CONFIG.output.directory);
            console.log('   - element_database.json');
            console.log('   - interactive_element_map.json');
            console.log('   - exploration_report.json');
                       console.log('   - summary_statistics.json');
            console.log('   - generated_automation.js');
            console.log('   - session_data.json');
            console.log('\n🎯 Run the generated automation script:');
            console.log('   node enhanced_ui_automation_framework.js complete');
        })
        .catch((error) => {
            console.error('\n❌ Discovery failed:', error.message);
            process.exit(1);
        });
}

module.exports = AutomaticUIDiscovery;