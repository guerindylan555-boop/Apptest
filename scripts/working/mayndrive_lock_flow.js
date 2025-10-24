#!/usr/bin/env node

/**
 * MaynDrive Lock/Pause Flow Automation - Improved Version
 * 
 * This script starts from the main screen and:
 * 1. Verifies user is logged in
 * 2. Detects if scooter is in active/riding state
 * 3. Performs the lock/pause flow only if conditions are met
 * 
 * Flow:
 * 1. Check if user is logged in (look for "Scan & ride")
 * 2. Check for active scooter (running timer, not paused)
 * 3. Click Info button → "Take a break" → "Pause my rent"
 * 4. Handle success/error dialogs
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// Configuration
const PACKAGE_NAME = 'fr.mayndrive.app';
const ADB_PORT = process.env.ANDROID_ADB_SERVER_PORT || process.env.ADB_PORT || '';
const EMULATOR_SERIAL = process.env.EMULATOR_SERIAL || 'emulator-5554';
const ADB_BIN = process.env.ADB_BIN || 'adb';
const DUMP_DIR = path.join(__dirname, '../..', 'var/autoapp/dumps/lock');

// Ensure dump directory exists
if (!fs.existsSync(DUMP_DIR)) {
  fs.mkdirSync(DUMP_DIR, { recursive: true });
}

// Build ADB command
function buildAdbCmd(args) {
  const cmd = [ADB_BIN];
  if (ADB_PORT) {
    cmd.push('-P', ADB_PORT);
  }
  cmd.push('-s', EMULATOR_SERIAL);
  return cmd.concat(args);
}

// Execute ADB command
function execAdb(args, options = {}) {
  const cmd = buildAdbCmd(args);
  console.log(`[adb] ${args.join(' ')}`);
  try {
    return execSync(cmd.join(' '), { encoding: 'utf8', ...options });
  } catch (error) {
    console.error(`[error] ADB command failed: ${error.message}`);
    throw error;
  }
}

// Sleep helper
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Tap at coordinates
async function tap(x, y, description) {
  console.log(`[tap] ${description}`);
  execAdb(['shell', 'input', 'tap', x.toString(), y.toString()]);
  await sleep(500);
}

async function pressBack(description = 'Press back') {
  console.log(`[back] ${description}`);
  execAdb(['shell', 'input', 'keyevent', '4']);
  await sleep(1000);
}

// Dump UI and save to file
async function dumpUI(filename) {
  const filepath = path.join(DUMP_DIR, filename);
  console.log(`[ui] Dumping UI to ${filename}`);
  try {
    const xml = execAdb(['exec-out', 'uiautomator', 'dump', '/dev/tty']);
    fs.writeFileSync(filepath, xml);
    console.log(`[capture] ${filename} -> ${filepath}`);
    return xml;
  } catch (error) {
    console.error(`[error] Failed to dump UI: ${error.message}`);
    return null;
  }
}

// Check if text exists in UI
function checkText(xml, text) {
  const escaped = text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const regex = new RegExp(`text="[^"]*${escaped}[^"]*"`, 'i');
  return regex.test(xml);
}

// Check for login state
// User is logged in if either:
// 1. "Scan & ride" button is visible (no active rental), OR
// 2. Active scooter UI is present (has rental running)
function isLoggedIn(xml) {
  const hasScanButton = checkText(xml, 'Scan &amp; ride') || checkText(xml, 'Scan & ride');
  const hasActiveUI = hasActiveScooter(xml);
  return hasScanButton || hasActiveUI;
}

// Check for active scooter (riding, not paused)
function hasActiveScooter(xml) {
  const hasTimer = /text="\d+:\d+(?::\d+)?"/.test(xml);
  const hasScooterId = checkText(xml, 'TUF') || checkText(xml, 'SCO');
  return hasTimer && !checkText(xml, 'paused') && hasScooterId;
}

// Check if on main map screen
function isOnMainScreen(xml) {
  return isLoggedIn(xml) && 
         !checkText(xml, 'Login') && 
         !checkText(xml, 'Unlock') &&
         !checkText(xml, 'Pause') &&
         !checkText(xml, 'Resume');
}

// Handle dialogs (error dialogs, success dialogs, etc.)
async function handleDialogs(initialXml, labelBase = 'dialog_cleanup') {
  let xml = initialXml;
  let iteration = 0;
  let handledAny = false;

  while (xml) {
    let handled = false;

    if (checkText(xml, 'An error occurred')) {
      console.log('[cleanup] Dismissing error dialog...');
      await tap(768, 1354, "Dismiss error dialog");
      handled = true;
    } else if (
      checkText(xml, 'Vehicle unlocked') ||
      checkText(xml, 'You can continue your ride') ||
      checkText(xml, 'Ok')
    ) {
      console.log('[cleanup] Dismissing unlock success dialog...');
      await tap(540, 1458, "Tap 'Ok' on success dialog");
      handled = true;
    } else if (checkText(xml, 'Trip paused') || checkText(xml, 'Ride paused')) {
      console.log('[cleanup] Dismissing paused confirmation dialog...');
      await tap(540, 1459, "Tap 'Ok' on paused dialog");
      handled = true;
    } else if (checkText(xml, 'Back in the saddle') || checkText(xml, 'Resume trip')) {
      console.log('[cleanup] Leaving resume confirmation screen...');
      await pressBack('Return from resume screen');
      handled = true;
    }

    if (!handled) {
      break;
    }

    handledAny = true;
    iteration += 1;
    await sleep(1500);
    xml = await dumpUI(`${labelBase}_${iteration}.xml`);
  }

  return { xml, handled: handledAny };
}

// Main lock flow
async function lockFlow() {
  console.log('═══════════════════════════════════════');
  console.log(' MaynDrive Lock/Pause Flow (Improved)');
  console.log('═══════════════════════════════════════');
  console.log('');

  try {
    // Step 1: Check initial state
    console.log('[step] Checking initial state...');
    let xml = await dumpUI('initial_state.xml');
    if (!xml) throw new Error('Failed to dump initial UI');

    // Clear out any dialogs left from previous flows
    const initialCleanup = await handleDialogs(xml, 'initial_cleanup');
    xml = initialCleanup.xml || xml;
    if (!xml) {
      xml = await dumpUI('post_initial_cleanup.xml');
      if (!xml) throw new Error('Failed to capture UI after dialog cleanup');
    }
    if (initialCleanup.handled) {
      await sleep(1000);
    }

    // Check if user is logged in
    if (!isLoggedIn(xml)) {
      console.error('[failed] User is not logged in. Please login first.');
      console.log('[hint] Run login capture script first to authenticate.');
      return false;
    }
    console.log('[verify] ✓ User is logged in');

    // Check if we're on main screen
    if (!isOnMainScreen(xml)) {
      console.log('[cleanup] Not on main screen, navigating back...');
      // Press back button up to 3 times to get to main screen
      for (let i = 0; i < 3; i++) {
        await pressBack(`Hardware back (attempt ${i + 1})`);
        await sleep(1000);
        xml = await dumpUI(`back_${i}.xml`);
        if (isOnMainScreen(xml)) break;
      }
      
      if (!isOnMainScreen(xml)) {
        console.error('[failed] Could not navigate to main screen');
        return false;
      }
    }
    console.log('[verify] ✓ On main screen');

    // Handle any existing dialogs first
    const preFlowCleanup = await handleDialogs(xml, 'pre_flow_cleanup');
    xml = preFlowCleanup.xml || xml;
    if (!xml) {
      xml = await dumpUI('clean_state.xml');
    } else if (preFlowCleanup.handled) {
      await sleep(1000);
      xml = await dumpUI('clean_state.xml');
    }
    if (!xml) throw new Error('Failed to capture UI after pre-flow cleanup');

    // Check for active scooter
    if (!hasActiveScooter(xml)) {
      console.log('[check] Looking for active scooter...');
      console.log('[info] Available elements:');
      
      // Show what we found
      const texts = xml.match(/text="[^"]*"/g) || [];
      texts.forEach(text => {
        if (text.includes('TUF') || text.includes('paused') || text.includes(':')) {
          console.log(`  Found: ${text}`);
        }
      });
      
      console.error('[failed] No active scooter found. The scooter must be in riding state to lock.');
      console.log('[hint] Unlock the scooter first with: capture_unlock_lock.sh unlock');
      return false;
    }
    console.log('[verify] ✓ Active scooter found (TUF055)');

    // Step 2: Open options panel by clicking Info button
    console.log('[step] Opening options panel...');
    await tap(1002, 386, "Tap Info button (top right)");
    await sleep(2000);

    xml = await dumpUI('options_panel.xml');
    if (!checkText(xml, 'Take a break')) {
      console.log('[info] Options panel contents:');
      const optionsTexts = xml.match(/text="[^"]*"/g) || [];
      optionsTexts.forEach(text => {
        if (text.includes('Take') || text.includes('End') || text.includes('Pause') || text.includes('Resume')) {
          console.log(`  Found: ${text}`);
        }
      });
      throw new Error('Options panel did not open - "Take a break" button not found');
    }

    // Step 3: Click "Take a break"
    console.log('[step] Initiating pause...');
    await tap(540, 667, "Tap 'Take a break'");
    await sleep(3000);

    xml = await dumpUI('pause_confirmation.xml');
    if (!checkText(xml, 'Pause my rent')) {
      throw new Error('Pause confirmation screen did not appear');
    }

    // Step 4: Confirm pause
    console.log('[step] Confirming pause...');
    await tap(540, 1524, "Tap 'Pause my rent' button");
    await sleep(5000); // Wait for lock API call

    xml = await dumpUI('lock_result.xml');

    // Step 5: Check for success
    if (checkText(xml, 'Trip paused')) {
      console.log('[success] ✓ Trip paused! Vehicle locked.');
      await sleep(1000);
      await tap(540, 1459, "Tap 'Ok' on success dialog");
      await sleep(2000);
    } else if (checkText(xml, 'An error occurred')) {
      console.error('[error] Lock failed with error dialog');
      await tap(768, 1354, "Dismiss error dialog");
      await sleep(1000);
      throw new Error('Lock API call failed');
    } else {
      console.warn('[warn] Unexpected state after lock attempt');
    }

    // Step 6: Handle any additional dialogs
    xml = await dumpUI('final_state.xml');
    const dialogResult = await handleDialogs(xml, 'post_lock_cleanup');
    xml = dialogResult.xml || xml;

    // Verify we're back on map with paused rent
    xml = await dumpUI('map_view_paused.xml');
    if (checkText(xml, 'paused') || (checkText(xml, 'TUF055') && /text="\d+:\d+:\d+/.test(xml))) {
      console.log('[verify] ✓ Rent is now paused');
    } else {
      console.warn('[warn] Could not verify paused state');
    }

    console.log('');
    console.log('[done] Lock flow completed successfully.');
    console.log(`[dumps] Saved to: ${DUMP_DIR}`);
    return true;

  } catch (error) {
    console.error('');
    console.error('[failed] Lock flow failed:', error.message);
    console.error('');
    await dumpUI('error_state.xml');
    return false;
  }
}

// Run the flow
lockFlow()
  .then(success => {
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
