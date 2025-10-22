#!/usr/bin/env node

/**
 * Mayn Drive login automation.
 *
 * Launches the app, clears dialogs, performs login, and stops as soon as the
 * post-login home screen is available. Every significant step writes a UI dump
 * to `var/autoapp/dumps/login/` so you can inspect what happened.
 */

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const SERIAL = process.env.EMULATOR_SERIAL || process.env.ADB_SERIAL || 'emulator-5554';
const PACKAGE_NAME = 'fr.mayndrive.app';
const MAIN_ACTIVITY = 'city.knot.knotapp.ui.MainActivity';
const EMAIL = process.env.MAYNDRIVE_EMAIL || 'blhackapple@gmail.com';
const PASSWORD = process.env.MAYNDRIVE_PASSWORD || 'Yolo01610';
const ADB_BIN = process.env.ADB_BIN || 'adb';
const ADB_PORT =
  process.env.ANDROID_ADB_SERVER_PORT ||
  process.env.ADB_SERVER_PORT ||
  process.env.ADB_PORT ||
  '';

const BASE_ARGS = [];
if (ADB_PORT) {
  BASE_ARGS.push('-P', ADB_PORT);
}
BASE_ARGS.push('-s', SERIAL);

const DUMP_DIR = path.resolve('var', 'autoapp', 'dumps', 'login');
fs.mkdirSync(DUMP_DIR, { recursive: true });

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const hasCrashDialog = (xml) => xml.includes('An error occurred') && xml.includes('Ok');

const execAdb = (args, { capture = false } = {}) => {
  const displayArgs = args.join(' ');
  console.log(`[adb] ${displayArgs}`);
  try {
    if (capture) {
      return execFileSync(ADB_BIN, [...BASE_ARGS, ...args], { encoding: 'utf8' });
    }
    execFileSync(ADB_BIN, [...BASE_ARGS, ...args], { stdio: 'inherit' });
    return '';
  } catch (error) {
    if (error.stdout) {
      console.error(error.stdout.toString());
    }
    if (error.stderr) {
      console.error(error.stderr.toString());
    }
    throw error;
  }
};

const tap = async (x, y, label) => {
  if (label) {
    console.log(`[tap] ${label}`);
  }
  execAdb(['shell', 'input', 'tap', String(x), String(y)]);
  await sleep(900);
};

const typeText = async (text) => {
  if (!text) {
    return;
  }
  execAdb(['shell', 'input', 'text', text.replace(/ /g, '%s')]);
  await sleep(400);
};

const typeEmail = async (email) => {
  const [user, domain = ''] = email.split('@');
  await typeText(user);
  execAdb(['shell', 'input', 'keyevent', 'KEYCODE_AT']);
  await sleep(200);
  await typeText(domain);
};

const clearFocusedField = async () => {
  execAdb(['shell', 'input', 'keyevent', 'KEYCODE_MOVE_END']);
  await sleep(120);
  for (let i = 0; i < 40; i += 1) {
    execAdb(['shell', 'input', 'keyevent', 'KEYCODE_DEL']);
  }
  await sleep(200);
};

const captureUi = async (tag, { retries = 5, delayMs = 600 } = {}) => {
  const safeTag = tag.replace(/[^a-z0-9_-]/gi, '_');
  const remotePath = `/sdcard/${safeTag}.xml`;
  const localPath = path.join(DUMP_DIR, `${safeTag}.xml`);
  let lastError;
  for (let attempt = 1; attempt <= retries; attempt += 1) {
    try {
      execAdb(['exec-out', 'uiautomator', 'dump', remotePath], { capture: true });
      execAdb(['pull', remotePath, localPath]);
      const xml = fs.readFileSync(localPath, 'utf8');
      console.log(`[capture] ${tag} -> ${localPath}`);
      return { xml, localPath };
    } catch (error) {
      lastError = error;
      console.warn(
        `[warn] Failed to capture UI dump '${tag}' (attempt ${attempt}/${retries}): ${error.message}`
      );
      if (attempt < retries) {
        await sleep(delayMs);
      }
    }
  }
  throw lastError;
};

const captureWithoutCrash = async (tag) => {
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    const result = await captureUi(tag);
    if (!hasCrashDialog(result.xml)) {
      return result;
    }
    console.log('[dialog] Crash dialog detected; dismissing');
    await tap(768, 1320, "Dismiss 'An error occurred'");
    await sleep(1500);
  }
  throw new Error(`Crash dialog persisted while capturing '${tag}'`);
};

const ensureTap = async (performTap, description, tagBase, predicate) => {
  let attempt = 1;
  while (attempt <= 4) {
    await performTap();
    await sleep(1200);
    const { xml } = await captureWithoutCrash(`${tagBase}_${attempt}`);
    if (!predicate || predicate(xml)) {
      return xml;
    }
    console.log(`[retry] ${description} not in expected state (attempt ${attempt})`);
    attempt += 1;
  }
  throw new Error(`Unable to achieve expected state for ${description}`);
};

const assertLoggedIn = (xml) => {
  const plain = xml.replace(/&amp;/g, '&');
  if (plain.includes('Scan & ride')) {
    console.log('[verify] Found "Scan & ride" – login confirmed.');
    return;
  }
  if (plain.includes('Login to rent')) {
    throw new Error('Returned to login sheet; credentials may have failed.');
  }
  console.warn('[warn] "Scan & ride" not detected; review dumps for details.');
};

async function main() {
  console.log(`[info] Using device ${SERIAL}`);
  if (ADB_PORT) {
    console.log(`[info] Targeting adb server port ${ADB_PORT}`);
  }

  console.log('[step] Force-stopping app');
  execAdb(['shell', 'am', 'force-stop', PACKAGE_NAME]);

  console.log('[step] Clearing application data');
  try {
    execAdb(['shell', 'pm', 'clear', PACKAGE_NAME]);
  } catch (error) {
    console.warn('[warn] Unable to clear data (continuing):', error.message);
  }

  console.log('[step] Launching app');
  execAdb(['shell', 'am', 'start', '-n', `${PACKAGE_NAME}/${MAIN_ACTIVITY}`]);
  await sleep(6500);

  console.log('[step] Clearing startup dialog');
  await captureWithoutCrash('after_launch');

  await captureWithoutCrash('home_initial');

  console.log('[step] Opening login sheet');
  await ensureTap(
    () => tap(540, 2240, 'Open login sheet'),
    'Open login sheet',
    'login_sheet',
    (xml) => xml.includes('Login') && xml.includes('Signup')
  );

  console.log('[step] Selecting login option');
  await ensureTap(
    () => tap(540, 1910, "Select 'Login'"),
    "Select 'Login'",
    'login_form',
    (xml) => xml.includes('Email') && xml.includes('Password')
  );

  console.log('[step] Entering credentials');
  await tap(540, 390, 'Focus email field');
  await clearFocusedField();
  await typeEmail(EMAIL);

  await tap(540, 620, 'Focus password field');
  await clearFocusedField();
  await typeText(PASSWORD);

  await captureWithoutCrash('credentials_filled');

  console.log('[step] Submitting login');
  await tap(540, 1015, "Tap 'Login'");
  await sleep(4000);

  console.log('[step] Clearing post-login dialog');
  await captureWithoutCrash('post_login');

  const { xml: finalXml } = await captureWithoutCrash('post_login_home');
  assertLoggedIn(finalXml);

  console.log('[done] Mayn Drive login sequence finished.');
}

main().catch((error) => {
  console.error('[error]', error.message);
  process.exit(1);
});
