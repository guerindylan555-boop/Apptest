import { spawnSync } from 'child_process';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { logger } from './logger';

type Bounds = {
  left: number;
  top: number;
  right: number;
  bottom: number;
};

type UiAction = {
  id: string;
  label: string;
  className?: string;
  text?: string;
  contentDesc?: string;
  resourceId?: string;
  bounds: Bounds;
  center: { x: number; y: number };
};

export type UiDiscoveryOptions = {
  serial?: string;
  maxDepth?: number;
  maxActionsPerScreen?: number;
  waitAfterTapMs?: number;
  waitAfterBackMs?: number;
};

type ScreenRecord = {
  id: string;
  hash: string;
  xmlPath: string;
  screenshotPath: string;
  actions: UiAction[];
  path: string[];
};

type TransitionRecord = {
  from: string;
  to: string;
  actionId: string;
  label: string;
};

export type UiDiscoveryResult = {
  runId: string;
  startedAt: string;
  completedAt: string;
  deviceSerial: string;
  screenCount: number;
  transitionCount: number;
  runDirectory: string;
  screens: Array<{
    id: string;
    hash: string;
    path: string[];
    xmlPath: string;
    screenshotPath: string;
    actions: UiAction[];
  }>;
  transitions: TransitionRecord[];
};

const UI_DISCOVERY_ROOT = path.resolve('var', 'autoapp', 'ui-discovery');
const DEFAULT_SERIAL = process.env.UI_DISCOVERY_SERIAL || process.env.EMULATOR_SERIAL || 'emulator-5556';
const DEFAULT_ADB_BIN = process.env.ADB_BIN || 'adb';
const DEFAULT_ADB_PORT =
  process.env.ANDROID_ADB_SERVER_PORT ||
  process.env.ADB_SERVER_PORT ||
  process.env.ADB_PORT ||
  process.env.ADB_HOST_PORT ||
  '';

const DEFAULT_OPTIONS: Required<Omit<UiDiscoveryOptions, 'serial'>> = {
  maxDepth: 2,
  maxActionsPerScreen: 6,
  waitAfterTapMs: 1200,
  waitAfterBackMs: 800
};

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const ensureDirectory = (target: string) => {
  fs.mkdirSync(target, { recursive: true });
};

const buildDeviceArgs = (serial: string) => {
  const args: string[] = [];
  if (DEFAULT_ADB_PORT) {
    args.push('-P', DEFAULT_ADB_PORT);
  }
  args.push('-s', serial);
  return args;
};

const parseBounds = (value?: string): Bounds | undefined => {
  if (!value) return undefined;
  const match = value.match(/\[(\d+),(\d+)\]\[(\d+),(\d+)\]/);
  if (!match) return undefined;
  const [_, left, top, right, bottom] = match;
  return {
    left: Number(left),
    top: Number(top),
    right: Number(right),
    bottom: Number(bottom)
  };
};

const parseNodeAttributes = (nodeSnippet: string) => {
  const attributes: Record<string, string> = {};
  const regex = /([a-zA-Z0-9\-\_:]+)="([^"]*)"/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(nodeSnippet))) {
    attributes[match[1]] = match[2];
  }
  return attributes;
};

const shouldSkipAction = (action: UiAction) => {
  const label = action.label.toLowerCase();
  if (!label.trim() && !action.resourceId && !action.contentDesc) {
    return true;
  }
  if (label.includes('logout') || label.includes('log out')) return true;
  if (label.includes('delete') || label.includes('remove account')) return true;
  const height = action.bounds.bottom - action.bounds.top;
  const width = action.bounds.right - action.bounds.left;
  if (height > 1800 && width > 900) {
    return true;
  }
  if (action.bounds.top < 80 && height < 160) {
    return true;
  }
  return false;
};

const extractActions = (xml: string): UiAction[] => {
  const actions: UiAction[] = [];
  const seenBounds = new Set<string>();
  const nodeRegex = /<node\b[^>]*>/g;
  let match: RegExpExecArray | null;
  let index = 0;
  while ((match = nodeRegex.exec(xml))) {
    const snippet = match[0];
    if (!snippet.includes('clickable="true"') && !snippet.includes('long-clickable="true"')) {
      continue;
    }

    const attributes = parseNodeAttributes(snippet);
    const bounds = parseBounds(attributes.bounds);
    if (!bounds) {
      continue;
    }

    const key = `${bounds.left},${bounds.top},${bounds.right},${bounds.bottom}`;
    if (seenBounds.has(key)) {
      continue;
    }
    seenBounds.add(key);

    const text = attributes.text?.trim();
    const contentDesc = attributes['content-desc']?.trim();
    const resourceId = attributes['resource-id']?.trim();
    const label =
      (text && text.length > 0 && text) ||
      (contentDesc && contentDesc.length > 0 && contentDesc) ||
      (resourceId && resourceId.split('/').pop()) ||
      attributes.class ||
      `Action ${index + 1}`;

    const center = {
      x: Math.floor((bounds.left + bounds.right) / 2),
      y: Math.floor((bounds.top + bounds.bottom) / 2)
    };

    const action: UiAction = {
      id: `${index}-${bounds.left}-${bounds.top}`,
      label,
      className: attributes.class,
      text,
      contentDesc,
      resourceId,
      bounds,
      center
    };

    if (shouldSkipAction(action)) {
      index += 1;
      continue;
    }

    actions.push(action);
    index += 1;
  }

  return actions;
};

const captureUiXml = (deviceArgs: string[]): string => {
  const output = spawnSync(DEFAULT_ADB_BIN, [...deviceArgs, 'exec-out', 'uiautomator', 'dump', '/dev/tty'], {
    encoding: 'utf8',
    maxBuffer: 4 * 1024 * 1024
  });

  if (output.error) {
    throw output.error;
  }

  if (output.status !== 0) {
    throw new Error(output.stderr ? output.stderr.toString() : 'Failed to capture UI dump');
  }

  const content = output.stdout ?? '';
  const cleaned = content.replace(/^UI hierarchy dumped to:.*$/gm, '').trim();
  return cleaned;
};

const captureScreenshot = (deviceArgs: string[]): Buffer => {
  const output = spawnSync(DEFAULT_ADB_BIN, [...deviceArgs, 'exec-out', 'screencap', '-p'], {
    encoding: 'binary',
    maxBuffer: 10 * 1024 * 1024
  });

  if (output.error) {
    throw output.error;
  }

  if (output.status !== 0) {
    throw new Error(output.stderr ? output.stderr.toString() : 'Failed to capture screenshot');
  }

  const stdout = output.stdout as string;
  return Buffer.from(stdout, 'binary');
};

type CaptureContext = {
  deviceArgs: string[];
  runDir: string;
  visited: Map<string, ScreenRecord>;
  counter: { value: number };
};

const ensureScreen = (context: CaptureContext, pathTrail: string[]): ScreenRecord => {
  const xml = captureUiXml(context.deviceArgs);
  const hash = crypto.createHash('sha1').update(xml).digest('hex');

  const existing = context.visited.get(hash);
  if (existing) {
    return existing;
  }

  const screenshot = captureScreenshot(context.deviceArgs);

  const xmlPath = path.join(context.runDir, `${hash}.xml`);
  const pngPath = path.join(context.runDir, `${hash}.png`);

  fs.writeFileSync(xmlPath, `${xml}\n`, 'utf8');
  fs.writeFileSync(pngPath, screenshot);

  const screenId = `screen-${String(context.counter.value).padStart(3, '0')}`;
  context.counter.value += 1;

  const actions = extractActions(xml);

  const record: ScreenRecord = {
    id: screenId,
    hash,
    xmlPath: path.relative(process.cwd(), xmlPath),
    screenshotPath: path.relative(process.cwd(), pngPath),
    actions,
    path: [...pathTrail]
  };

  context.visited.set(hash, record);
  return record;
};

type QueueItem = {
  screen: ScreenRecord;
  depth: number;
};

export const runUiDiscovery = async (options: UiDiscoveryOptions = {}): Promise<UiDiscoveryResult> => {
  const serial = options.serial || DEFAULT_SERIAL;
  const runId = crypto.randomUUID();
  const runDir = path.join(UI_DISCOVERY_ROOT, runId);

  ensureDirectory(runDir);

  logger.info('Starting UI discovery run', {
    runId,
    serial,
    maxDepth: options.maxDepth ?? DEFAULT_OPTIONS.maxDepth,
    maxActionsPerScreen: options.maxActionsPerScreen ?? DEFAULT_OPTIONS.maxActionsPerScreen
  });

  const startedAt = new Date().toISOString();

  // Ensure adb server is ready and device available
  try {
    spawnSync(DEFAULT_ADB_BIN, ['start-server'], { stdio: 'ignore' });
  } catch (error) {
    logger.warn('Failed to start adb server', { error });
  }

  const deviceArgs = buildDeviceArgs(serial);
  const waitResult = spawnSync(DEFAULT_ADB_BIN, [...deviceArgs, 'wait-for-device'], { stdio: 'ignore' });
  if (waitResult.status !== 0) {
    throw new Error(`Device ${serial} not reachable for UI discovery`);
  }

  const captureContext: CaptureContext = {
    deviceArgs,
    runDir,
    visited: new Map<string, ScreenRecord>(),
    counter: { value: 1 }
  };

  const rootScreen = ensureScreen(captureContext, []);

  const queue: QueueItem[] = [{ screen: rootScreen, depth: 0 }];
  const transitions: TransitionRecord[] = [];
  const attemptedActions = new Set<string>();
  const processedScreens = new Set<string>();

  const maxDepth = options.maxDepth ?? DEFAULT_OPTIONS.maxDepth;
  const maxActionsPerScreen = options.maxActionsPerScreen ?? DEFAULT_OPTIONS.maxActionsPerScreen;
  const waitAfterTapMs = options.waitAfterTapMs ?? DEFAULT_OPTIONS.waitAfterTapMs;
  const waitAfterBackMs = options.waitAfterBackMs ?? DEFAULT_OPTIONS.waitAfterBackMs;

  while (queue.length > 0) {
    const current = queue.shift();
    if (!current) {
      break;
    }

    if (processedScreens.has(current.screen.hash)) {
      continue;
    }
    processedScreens.add(current.screen.hash);

    logger.debug('Processing screen for UI discovery', {
      screenId: current.screen.id,
      depth: current.depth,
      actionCount: current.screen.actions.length
    });

    const actions = current.screen.actions.slice(0, maxActionsPerScreen);

    for (const action of actions) {
      const actionKey = `${current.screen.hash}:${action.bounds.left}:${action.bounds.top}:${action.bounds.right}:${action.bounds.bottom}`;
      if (attemptedActions.has(actionKey)) {
        continue;
      }
      attemptedActions.add(actionKey);

      try {
        spawnSync(DEFAULT_ADB_BIN, [...deviceArgs, 'shell', 'input', 'tap', String(action.center.x), String(action.center.y)], {
          stdio: 'ignore'
        });
      } catch (error) {
        logger.warn('Failed to tap UI element during discovery', {
          error: (error as Error).message,
          action
        });
        continue;
      }

      await sleep(waitAfterTapMs);

      let nextScreen: ScreenRecord;
      try {
        nextScreen = ensureScreen(captureContext, [...current.screen.path, action.label]);
      } catch (error) {
        logger.warn('Failed to capture screen after tap', {
          error: (error as Error).message,
          action
        });
        continue;
      }

      transitions.push({
        from: current.screen.id,
        to: nextScreen.id,
        actionId: action.id,
        label: action.label
      });

      if (nextScreen.id === current.screen.id) {
        logger.debug('Tap did not change screen', { screenId: current.screen.id, action: action.label });
      } else if (
        nextScreen.path.length === current.screen.path.length + 1 &&
        !processedScreens.has(nextScreen.hash) &&
        !queue.find((item) => item.screen.hash === nextScreen.hash)
      ) {
        if (current.depth + 1 <= maxDepth) {
          queue.push({ screen: nextScreen, depth: current.depth + 1 });
        }
      }

      spawnSync(DEFAULT_ADB_BIN, [...deviceArgs, 'shell', 'input', 'keyevent', '4'], { stdio: 'ignore' });
      await sleep(waitAfterBackMs);
    }
  }

  const completedAt = new Date().toISOString();

  const screens = Array.from(captureContext.visited.values()).map((screen) => ({
    id: screen.id,
    hash: screen.hash,
    path: screen.path,
    xmlPath: screen.xmlPath,
    screenshotPath: screen.screenshotPath,
    actions: screen.actions
  }));

  const result: UiDiscoveryResult = {
    runId,
    startedAt,
    completedAt,
    deviceSerial: serial,
    screenCount: screens.length,
    transitionCount: transitions.length,
    runDirectory: path.relative(process.cwd(), runDir),
    screens,
    transitions
  };

  logger.info('UI discovery run completed', {
    runId,
    screenCount: result.screenCount,
    transitions: result.transitionCount
  });

  return result;
};
