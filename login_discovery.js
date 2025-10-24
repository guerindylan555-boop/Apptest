/**
 * Login Discovery System for MaynDrive
 * Discovers and documents the complete login process
 */

const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

class LoginDiscovery {
    constructor() {
        this.device = 'emulator-5556';
        this.appPackage = 'fr.mayndrive.app';
        this.step = 0;
        this.discoveryDir = './login_discovery';

        this.setupDirectories();
    }

    setupDirectories() {
        if (!fs.existsSync(this.discoveryDir)) {
            fs.mkdirSync(this.discoveryDir, { recursive: true });
        }
    }

    async log(message, level = 'INFO') {
        const timestamp = new Date().toISOString();
        const logMessage = `[${timestamp}] [${level}] [LOGIN STEP ${this.step}] ${message}`;
        console.log(logMessage);

        const logFile = path.join(this.discoveryDir, 'login_discovery.log');
        fs.appendFileSync(logFile, logMessage + '\n');
    }

    async adb(command) {
        return new Promise((resolve, reject) => {
            const fullCommand = `adb -s ${this.device} ${command}`;
            this.log(`Executing: ${fullCommand}`);

            exec(fullCommand, (error, stdout, stderr) => {
                if (error) {
                    this.log(`ADB Error: ${error.message}`, 'ERROR');
                    reject(error);
                } else {
                    resolve(stdout.trim());
                }
            });
        });
    }

    async startApp() {
        this.log('🚀 Starting MaynDrive app to discover login screen');
        try {
            await this.adb(`shell am start -n ${this.appPackage}/.MainActivity`);
            await this.delay(5000); // Wait for app to fully load
            return true;
        } catch (error) {
            this.log(`Failed to start app: ${error.message}`, 'ERROR');
            return false;
        }
    }

    async takeScreenshot(name) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `login_step_${this.step}_${name}_${timestamp}.png`;
        const filepath = path.join(this.discoveryDir, filename);

        try {
            await this.adb(`shell screencap -p /sdcard/${filename}`);
            await this.adb(`pull /sdcard/${filename} ${filepath}`);
            await this.adb(`shell rm /sdcard/${filename}`);
            this.log(`📸 Screenshot saved: ${filename}`);
            return filepath;
        } catch (error) {
            this.log(`Screenshot failed: ${error.message}`, 'ERROR');
            return null;
        }
    }

    async captureUIState(name) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const xmlFile = `login_step_${this.step}_${name}_${timestamp}.xml`;
        const xmlPath = path.join(this.discoveryDir, xmlFile);

        try {
            await this.adb('shell uiautomator dump');
            await this.adb(`shell cat /sdcard/window_dump.xml > ${xmlPath}`);
            this.log(`📄 UI state saved: ${xmlFile}`);
            return xmlPath;
        } catch (error) {
            this.log(`UI capture failed: ${error.message}`, 'ERROR');
            return null;
        }
    }

    async analyzeCurrentScreen() {
        try {
            const xml = await this.adb('shell uiautomator dump');
            if (!xml.includes('UI hierchary dumped to')) {
                return 'UNKNOWN';
            }

            const xmlContent = await this.adb('shell cat /sdcard/window_dump.xml');

            // Check for login-related patterns
            if (xmlContent.toLowerCase().includes('login') ||
                xmlContent.toLowerCase().includes('sign in') ||
                xmlContent.toLowerCase().includes('email') ||
                xmlContent.toLowerCase().includes('password') ||
                xmlContent.toLowerCase().includes('connexion')) {
                return 'LOGIN';
            }

            // Check for main map patterns
            if (xmlContent.toLowerCase().includes('buy a pass') ||
                xmlContent.toLowerCase().includes('scan & ride') ||
                xmlContent.toLowerCase().includes('google map')) {
                return 'MAIN_MAP';
            }

            // Check for onboarding/welcome
            if (xmlContent.toLowerCase().includes('welcome') ||
                xmlContent.toLowerCase().includes('get started') ||
                xmlContent.toLowerCase().includes('let\'s go')) {
                return 'ONBOARDING';
            }

            return 'UNKNOWN';
        } catch (error) {
            this.log(`Screen analysis failed: ${error.message}`, 'ERROR');
            return 'UNKNOWN';
        }
    }

    async tap(x, y, description = '') {
        const action = `Tap at (${x}, ${y})${description ? ` - ${description}` : ''}`;
        this.log(`👆 ${action}`);

        try {
            await this.adb(`shell input tap ${x} ${y}`);
            await this.delay(2000);
            this.log(`✅ ${action} completed`);
            return true;
        } catch (error) {
            this.log(`❌ ${action} failed: ${error.message}`, 'ERROR');
            return false;
        }
    }

    async delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    async startDiscovery() {
        this.log('🔍 Starting Login Discovery Process');
        this.step = 1;

        try {
            // Start the app
            if (!await this.startApp()) {
                this.log('Failed to start app', 'ERROR');
                return;
            }

            // Analyze initial screen
            const initialScreen = await this.analyzeCurrentScreen();
            this.log(`Initial screen detected: ${initialScreen}`);
            await this.takeScreenshot('initial_screen');
            await this.captureUIState('initial_screen');

            // If we're already on main map, we need to logout first
            if (initialScreen === 'MAIN_MAP') {
                this.log('Already logged in - attempting to logout');
                await this.discoverLogoutProcess();
                return;
            }

            // If we're on login screen, discover login elements
            if (initialScreen === 'LOGIN') {
                await this.discoverLoginElements();
                return;
            }

            // If onboarding, try to skip it
            if (initialScreen === 'ONBOARDING') {
                await this.discoverOnboardingProcess();
                return;
            }

            this.log(`Unknown initial screen: ${initialScreen}`, 'ERROR');

        } catch (error) {
            this.log(`Discovery failed: ${error.message}`, 'ERROR');
        }
    }

    async discoverLoginElements() {
        this.log('🔍 Discovering login screen elements');
        this.step = 2;

        // Take screenshot of login screen
        await this.takeScreenshot('login_screen');
        await this.captureUIState('login_screen');

        // Try common login element positions
        const loginElements = [
            { x: 540, y: 600, desc: 'Email/Username field' },
            { x: 540, y: 750, desc: 'Password field' },
            { x: 540, y: 900, desc: 'Login button' },
            { x: 540, y: 1050, desc: 'Forgot password' },
            { x: 540, y: 1200, desc: 'Create account' },
            { x: 300, y: 1400, desc: 'Social login (Facebook/Google)' },
            { x: 780, y: 1400, desc: 'Social login (Apple/Other)' }
        ];

        for (const element of loginElements) {
            this.step++;
            this.log(`Testing element: ${element.desc}`);
            await this.tap(element.x, element.y, element.desc);

            // Check if screen changed
            const newScreen = await this.analyzeCurrentScreen();
            if (newScreen !== 'LOGIN') {
                this.log(`Screen changed to: ${newScreen} - element was interactive`);
                await this.takeScreenshot(`after_${element.desc.replace(/\s+/g, '_')}`);
                await this.captureUIState(`after_${element.desc.replace(/\s+/g, '_')}`);

                // If we reached main map, we successfully logged in
                if (newScreen === 'MAIN_MAP') {
                    this.log('✅ Successfully reached main map - login process complete!');
                    return;
                }

                // Go back to login screen to continue discovery
                await this.delay(2000);
                await this.adb('shell input keyevent KEYCODE_BACK');
                await this.delay(2000);
            }
        }

        this.log('Login discovery completed');
    }

    async discoverLogoutProcess() {
        this.log('🔍 Discovering logout process');
        this.step = 10;

        // Try to access menu and logout
        await this.tap(77, 154, 'Menu button');
        await this.delay(3000);

        const currentScreen = await this.analyzeCurrentScreen();
        await this.takeScreenshot('menu_opened');
        await this.captureUIState('menu_opened');

        if (currentScreen === 'UNKNOWN' || currentScreen.includes('MENU')) {
            // Look for logout option (usually at bottom)
            const logoutPositions = [
                { x: 540, y: 950, desc: 'Logout option' },
                { x: 540, y: 1000, desc: 'Logout option' },
                { x: 540, y: 1050, desc: 'Logout option' }
            ];

            for (const pos of logoutPositions) {
                this.step++;
                await this.tap(pos.x, pos.y, pos.desc);
                await this.delay(2000);

                // Check for confirmation dialog
                const confirmScreen = await this.analyzeCurrentScreen();
                if (confirmScreen !== 'MAIN_MAP') {
                    await this.takeScreenshot('logout_confirmation');
                    await this.captureUIState('logout_confirmation');

                    // Try to confirm logout
                    await this.tap(540, 1200, 'Confirm logout');
                    await this.delay(3000);

                    const finalScreen = await this.analyzeCurrentScreen();
                    if (finalScreen === 'LOGIN') {
                        this.log('✅ Successfully logged out - now discovering login');
                        await this.discoverLoginElements();
                        return;
                    }
                }
            }
        }

        this.log('Logout discovery completed');
    }

    async discoverOnboardingProcess() {
        this.log('🔍 Discovering onboarding process');
        this.step = 20;

        // Try to skip through onboarding
        for (let i = 0; i < 5; i++) {
            this.step++;
            this.log(`Trying to skip onboarding step ${i + 1}`);

            // Try common skip/next positions
            const skipPositions = [
                { x: 900, y: 100, desc: 'Skip button' },
                { x: 540, y: 1600, desc: 'Next/Continue button' },
                { x: 540, y: 1700, desc: 'Get Started button' }
            ];

            for (const pos of skipPositions) {
                await this.tap(pos.x, pos.y, pos.desc);
                await this.delay(2000);

                const newScreen = await this.analyzeCurrentScreen();
                if (newScreen === 'LOGIN') {
                    this.log('Reached login screen after onboarding');
                    await this.discoverLoginElements();
                    return;
                } else if (newScreen === 'MAIN_MAP') {
                    this.log('Reached main map directly - no login required');
                    return;
                }
            }
        }

        this.log('Onboarding discovery completed');
    }

    async generateLoginReport() {
        this.log('📊 Generating Login Discovery Report');

        const report = {
            timestamp: new Date().toISOString(),
            device: this.device,
            appPackage: this.appPackage,
            totalSteps: this.step,
            screensDiscovered: [],
            loginElements: [],
            coordinates: {},
            screenshots: [],
            notes: []
        };

        // Analyze all discovery files
        const files = fs.readdirSync(this.discoveryDir);
        const xmlFiles = files.filter(f => f.endsWith('.xml'));
        const pngFiles = files.filter(f => f.endsWith('.png'));

        report.screenshots = pngFiles;

        // Save report
        const reportPath = path.join(this.discoveryDir, 'login_discovery_report.json');
        fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));

        this.log(`📋 Login discovery report saved: ${reportPath}`);
        return report;
    }
}

// Start the discovery process
if (require.main === module) {
    const discovery = new LoginDiscovery();
    discovery.startDiscovery().then(() => {
        return discovery.generateLoginReport();
    }).then(() => {
        console.log('Login discovery completed');
        process.exit(0);
    }).catch(error => {
        console.error('Login discovery failed:', error);
        process.exit(1);
    });
}

module.exports = LoginDiscovery;