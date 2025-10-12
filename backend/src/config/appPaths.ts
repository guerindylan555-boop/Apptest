import path from 'path';

const PROJECT_ROOT = path.resolve(__dirname, '..', '..', '..');

const APPS_ROOT = process.env.APPS_DATA_ROOT ??
  path.join(PROJECT_ROOT, 'var', 'autoapp', 'apps');

export const appPaths = {
  root: APPS_ROOT,
  libraryDir: path.join(APPS_ROOT, 'library'),
  logsDir: path.join(APPS_ROOT, 'logs'),
  scriptsDir: path.join(APPS_ROOT, 'scripts'),
  metadataIndexFile: path.join(APPS_ROOT, 'library', 'index.json'),
  activityLogFile: path.join(APPS_ROOT, 'logs', 'activity.log')
};
