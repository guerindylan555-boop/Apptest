import { spawn, type ChildProcess, type SpawnOptions } from 'child_process';
import { logger } from './logger';

export interface RunOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
}

/**
 * Creates a merged environment with Android SDK paths
 */
const getAndroidEnv = (customEnv?: NodeJS.ProcessEnv): NodeJS.ProcessEnv => {
  const homeDir = process.env.HOME || '/root';
  const androidRoot = process.env.ANDROID_SDK_ROOT?.replace(/^~/, homeDir) || `${homeDir}/Android`;
  const javaHome = process.env.JAVA_HOME || '/usr/lib/jvm/java-17-openjdk-amd64';
  const pathAdditions = [
    `${androidRoot}/cmdline-tools/latest/bin`,
    `${androidRoot}/platform-tools`,
    `${androidRoot}/emulator`
  ].join(':');

  // Expand ~ in environment variable paths
  const expandPath = (path?: string) => path?.replace(/^~/, homeDir) || '';

  return {
    ...process.env,
    ...customEnv,
    ANDROID_SDK_ROOT: androidRoot,
    JAVA_HOME: javaHome,
    PATH: `${process.env.PATH}:${pathAdditions}`,
    ADB: expandPath(process.env.ADB) || `${androidRoot}/platform-tools/adb`,
    EMULATOR: expandPath(process.env.EMULATOR) || `${androidRoot}/emulator/emulator`,
    AVDMANAGER: expandPath(process.env.AVDMANAGER) || `${androidRoot}/cmdline-tools/latest/bin/avdmanager`,
    LD_LIBRARY_PATH: `${androidRoot}/emulator/lib64:${process.env.LD_LIBRARY_PATH || ''}`
  };
};

const runCommand = (
  executable: string,
  args: string[],
  { cwd, env, timeoutMs }: RunOptions = {}
): Promise<{ code: number | null; stdout: string; stderr: string }> => {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      cwd,
      env: getAndroidEnv(env),
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
  runCommand(process.env.SDKMANAGER ?? 'sdkmanager', packages);

export const avdmanager = (args: string[]) =>
  runCommand(process.env.AVDMANAGER ?? 'avdmanager', args);

export const emulatorCli = (args: string[], options?: RunOptions) =>
  runCommand(process.env.EMULATOR ?? 'emulator', args, options);

export const launchEmulator = (
  args: string[],
  options?: SpawnOptions
): ChildProcess => {
  // Use wrapper script to ensure proper environment
  const wrapperScript = '/home/blhack/project/Apptest/backend/scripts/launch-emulator.sh';
  return spawn(wrapperScript, args, {
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options,
    env: getAndroidEnv(options?.env)
  });
};

export const adb = (args: string[], options?: RunOptions) =>
  runCommand(process.env.ADB ?? 'adb', args, options);

export const adbShell = (serial: string, shellArgs: string[], options?: RunOptions) =>
  adb(['-s', serial, 'shell', ...shellArgs], options);

export const adbWaitForDevice = (serial: string, options?: RunOptions) =>
  adb(['-s', serial, 'wait-for-device'], options);

export const adbGetProp = (serial: string, prop: string, options?: RunOptions) =>
  adb(['-s', serial, 'shell', 'getprop', prop], options);

export const adbEmu = (serial: string, subcommand: string, options?: RunOptions) =>
  adb(['-s', serial, 'emu', subcommand], options);
