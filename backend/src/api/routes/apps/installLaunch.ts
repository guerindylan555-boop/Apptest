import { Request, Response } from 'express';
import * as appsRepo from '../../../services/apps/appsRepository';
import { installApk } from '../../../services/apps/installService';
import { launchApp } from '../../../services/apps/launchService';
import * as appsStore from '../../../state/appsStore';
import { InstallStatus } from '../../../types/apps';
import type { InstallLaunchRequest, InstallLaunchResponse } from '../../../types/apps';

/**
 * Install & Launch Handler
 *
 * POST /apps/:id/install-launch
 * Installs an APK and launches it with fallback strategies
 */

export async function installLaunchHandler(req: Request, res: Response): Promise<void> {
  try {
    const { id } = req.params;
    const body: InstallLaunchRequest = req.body;

    // Get APK entry
    const entry = appsRepo.getEntryById(id);
    if (!entry) {
      res.status(404).json({ error: 'APK entry not found' });
      return;
    }

    console.log(`[InstallLaunch] Starting install & launch for: ${entry.displayName}`);

    // Step 1: Install
    const installResult = await installApk(entry.filePath, {
      allowDowngrade: body.allowDowngrade || false,
      autoGrantPermissions: body.autoGrantPermissions || false
    });

    if (!installResult.success) {
      // Installation failed
      await appsStore.logInstall(entry.id, entry.displayName, 'failed', installResult.message);

      const response: InstallLaunchResponse = {
        status: InstallStatus.Failed,
        launchResolution: 'failed' as any,
        message: installResult.message,
        installLogPath: null
      };

      res.status(400).json(response);
      return;
    }

    // Log successful install
    await appsStore.logInstall(entry.id, entry.displayName, 'success', 'Installed successfully');

    // Step 2: Launch
    const launchResult = await launchApp(entry.packageName, entry.launchableActivity);

    if (!launchResult.success) {
      // Install succeeded but launch failed
      await appsStore.logLaunch(entry.id, entry.displayName, launchResult.resolution, 'failed');

      const response: InstallLaunchResponse = {
        status: InstallStatus.Success,
        launchResolution: launchResult.resolution,
        message: `Installed successfully, but launch failed: ${launchResult.message}`,
        installLogPath: null
      };

      // Update lastUsedAt since install succeeded
      await appsRepo.updateEntry(id, { lastUsedAt: new Date().toISOString() });

      res.status(200).json(response);
      return;
    }

    // Both install and launch succeeded
    await appsStore.logLaunch(entry.id, entry.displayName, launchResult.resolution, 'success');

    // Update lastUsedAt
    await appsRepo.updateEntry(id, { lastUsedAt: new Date().toISOString() });

    const response: InstallLaunchResponse = {
      status: InstallStatus.Success,
      launchResolution: launchResult.resolution,
      message: `Installed and launched successfully via ${launchResult.resolution}`,
      installLogPath: null
    };

    res.status(200).json(response);
  } catch (error) {
    console.error('[InstallLaunch] Operation failed:', error);
    res.status(500).json({
      error: 'Install/launch operation failed',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}
