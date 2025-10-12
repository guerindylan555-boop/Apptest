import { Request, Response } from 'express';
import * as appsRepo from '../../../services/apps/appsRepository';

/**
 * List Handler for APK Entries
 *
 * Returns all APK entries with optional search and sorting.
 * Query parameters:
 * - search: Filter by display name or package name
 * - sortBy: Field to sort by (uploadedAt, lastUsedAt, displayName, packageName)
 * - sortOrder: asc or desc (default: desc for dates, asc for names)
 */

export async function listHandler(req: Request, res: Response): Promise<void> {
  try {
    const { search, sortBy, sortOrder } = req.query;

    // Validate sortBy parameter
    const validSortFields = ['uploadedAt', 'lastUsedAt', 'displayName', 'packageName'];
    const sortByField = sortBy && validSortFields.includes(sortBy as string)
      ? (sortBy as 'uploadedAt' | 'lastUsedAt' | 'displayName' | 'packageName')
      : undefined;

    // Validate sortOrder parameter
    const validSortOrders = ['asc', 'desc'];
    const sortOrderValue = sortOrder && validSortOrders.includes(sortOrder as string)
      ? (sortOrder as 'asc' | 'desc')
      : undefined;

    // Get entries with filters
    const entries = appsRepo.getAllEntries({
      search: search ? String(search) : undefined,
      sortBy: sortByField,
      sortOrder: sortOrderValue
    });

    res.status(200).json(entries);
  } catch (error) {
    console.error('[ListHandler] Failed to list APK entries:', error);
    res.status(500).json({
      error: 'Failed to list APK entries',
      message: error instanceof Error ? error.message : 'Unknown error'
    });
  }
}
