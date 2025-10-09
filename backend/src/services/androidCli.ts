import { spawn, type ChildProcess, type SpawnOptions } from 'child_process';
import { logger } from './logger';
import path from 'path';

// Android SDK paths
const ANDROID_SDK_ROOT = process.env.ANDROID_SDK_ROOT ?? path.join(process.env.HOME ?? '', 'android-sdk');
const SDK_TOOLS_PATH = path.join(ANDROID_SDK_ROOT, 'cmdline-tools', 'latest', 'bin');
const PLATFORM_TOOLS_PATH = path.join(ANDROID_SDK_ROOT, 'platform-tools');
const EMULATOR_PATH = path.join(ANDROID_SDK_ROOT, 'emulator');

// Full paths to Android SDK tools
const getFullPath = (tool: string, sdkPath: string = SDK_TOOLS_PATH) => {
  const ext = process.platform === 'win32' ? '.exe' : '';
  return path.join(sdkPath, tool + ext);
};

export interface RunOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
}

const runCommand = (
  executable: string,
  args: string[],
  { cwd, env, timeoutMs }: RunOptions = {}
): Promise<{ code: number | null; stdout: string; stderr: string }> => {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      cwd,
      env,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';

    child.stdout?.on('data', (data) => {
      stdout += data.toString();
    });

    child.stderr?.on('data', (data) => {
      stderr += data.toString();
    });

    const onExit = (code: number | null) => {
      resolve({ code, stdout, stderr });
    };

    child.on('error', (error) => {
      reject(error);
    });

    child.on('close', onExit);

    if (timeoutMs) {
      setTimeout(() => {
        logger.warn('Command timeout — terminating', { executable, args, timeoutMs });
        child.kill('SIGKILL');
      }, timeoutMs).unref();
    }
  });
};

export const sdkmanager = (packages: string[]) =>
  runCommand(process.env.SDKMANAGER ?? getFullPath('sdkmanager'), packages);

export const avdmanager = (args: string[]) =>
  runCommand(process.env.AVDMANAGER ?? getFullPath('avdmanager'), args);

export const emulatorCli = (args: string[], options?: RunOptions) =>
  runCommand(process.env.EMULATOR ?? getFullPath('emulator', EMULATOR_PATH), args, options);

export const launchEmulator = (
  args: string[],
  options?: SpawnOptions
): ChildProcess =>
  spawn(process.env.EMULATOR ?? getFullPath('emulator', EMULATOR_PATH), args, {
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options
  });

export const adb = (args: string[], options?: RunOptions) =>
  runCommand(process.env.ADB ?? getFullPath('adb', PLATFORM_TOOLS_PATH), args, options);

export const adbShell = (serial: string, shellArgs: string[], options?: RunOptions) =>
  adb(['-s', serial, 'shell', ...shellArgs], options);

export const adbWaitForDevice = (serial: string, options?: RunOptions) =>
  adb(['-s', serial, 'wait-for-device'], options);

export const adbGetProp = (serial: string, prop: string, options?: RunOptions) =>
  adb(['-s', serial, 'shell', 'getprop', prop], options);

export const adbEmu = (serial: string, subcommand: string, options?: RunOptions) =>
  adb(['-s', serial, 'emu', subcommand], options);
