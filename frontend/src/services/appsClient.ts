import type { ApkEntry } from '../types/apps';

/**
 * Apps API Client
 *
 * Communicates with the backend Apps API for APK management operations.
 */

// Runtime config for backend URL (injected at runtime if available)
declare global {
  interface Window {
    __RUNTIME_CONFIG__?: {
      BACKEND_URL?: string;
    };
  }
}

const BACKEND_URL = window.__RUNTIME_CONFIG__?.BACKEND_URL || 'http://127.0.0.1:3001/api';

/**
 * Fetch all APK entries with optional filters
 */
export async function fetchEntries(options?: {
  search?: string;
  sortBy?: string;
  sortOrder?: string;
}): Promise<ApkEntry[]> {
  const params = new URLSearchParams();
  if (options?.search) params.append('search', options.search);
  if (options?.sortBy) params.append('sortBy', options.sortBy);
  if (options?.sortOrder) params.append('sortOrder', options.sortOrder);

  const url = `${BACKEND_URL}/apps${params.toString() ? `?${params.toString()}` : ''}`;
  const response = await fetch(url);

  if (!response.ok) {
    throw new Error(`Failed to fetch entries: ${response.statusText}`);
  }

  return response.json();
}

/**
 * Upload an APK file
 */
export async function uploadApk(
  file: File,
  onProgress?: (progress: number) => void
): Promise<ApkEntry> {
  const formData = new FormData();
  formData.append('file', file);

  const xhr = new XMLHttpRequest();

  return new Promise((resolve, reject) => {
    xhr.upload.addEventListener('progress', (e) => {
      if (e.lengthComputable && onProgress) {
        const progress = (e.loaded / e.total) * 100;
        onProgress(progress);
      }
    });

    xhr.addEventListener('load', () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const result = JSON.parse(xhr.responseText);
          resolve(result);
        } catch (error) {
          reject(new Error('Invalid response from server'));
        }
      } else {
        try {
          const error = JSON.parse(xhr.responseText);
          reject(new Error(error.message || `Upload failed: ${xhr.statusText}`));
        } catch {
          reject(new Error(`Upload failed: ${xhr.statusText}`));
        }
      }
    });

    xhr.addEventListener('error', () => {
      reject(new Error('Network error during upload'));
    });

    xhr.addEventListener('abort', () => {
      reject(new Error('Upload aborted'));
    });

    xhr.open('POST', `${BACKEND_URL}/apps`);
    xhr.send(formData);
  });
}

/**
 * Update an APK entry (display name or pin state)
 */
export async function updateEntry(
  id: string,
  updates: { displayName?: string; pinned?: boolean }
): Promise<ApkEntry> {
  const response = await fetch(`${BACKEND_URL}/apps/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates)
  });

  if (!response.ok) {
    throw new Error(`Failed to update entry: ${response.statusText}`);
  }

  return response.json();
}

/**
 * Delete an APK entry
 */
export async function deleteEntry(id: string): Promise<void> {
  const response = await fetch(`${BACKEND_URL}/apps/${id}`, {
    method: 'DELETE'
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(error.message || `Failed to delete entry: ${response.statusText}`);
  }
}
