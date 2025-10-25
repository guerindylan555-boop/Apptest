/**
 * UUID Utilities
 *
 * UUID generation and validation utilities for the AutoApp system.
 * Provides v4 UUID generation and timestamp utilities.
 */

import { randomUUID } from 'crypto';
import { UUID, ISOTimestamp } from '../types/models';

/**
 * Generate a v4 UUID
 *
 * @returns Random UUID string
 */
export function generateUUID(): UUID {
  return randomUUID();
}

/**
 * Generate a UUID with optional namespace prefix
 *
 * @param namespace - Optional namespace prefix
 * @returns UUID string with optional namespace
 */
export function generateNamespacedUUID(namespace?: string): UUID {
  const uuid = randomUUID();
  return namespace ? `${namespace}_${uuid}` : uuid;
}

/**
 * Get current ISO timestamp
 *
 * @returns Current timestamp in ISO 8601 format
 */
export function getCurrentTimestamp(): ISOTimestamp {
  return new Date().toISOString();
}

/**
 * Generate timestamp for a specific date
 *
 * @param date - Date to convert
 * @returns ISO 8601 timestamp
 */
export function getTimestamp(date: Date = new Date()): ISOTimestamp {
  return date.toISOString();
}

/**
 * Validate UUID format
 *
 * @param uuid - UUID string to validate
 * @returns True if valid UUID
 */
export function isValidUUID(uuid: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

/**
 * Validate ISO timestamp format
 *
 * @param timestamp - Timestamp string to validate
 * @returns True if valid ISO timestamp
 */
export function isValidISOTimestamp(timestamp: string): boolean {
  const date = new Date(timestamp);
  return !isNaN(date.getTime()) && timestamp === date.toISOString();
}

/**
 * Extract date components from ISO timestamp
 *
 * @param timestamp - ISO timestamp
 * @returns Date components
 */
export function parseTimestamp(timestamp: ISOTimestamp): {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
  millisecond: number;
} | null {
  if (!isValidISOTimestamp(timestamp)) {
    return null;
  }

  const date = new Date(timestamp);
  return {
    year: date.getUTCFullYear(),
    month: date.getUTCMonth() + 1,
    day: date.getUTCDate(),
    hour: date.getUTCHours(),
    minute: date.getUTCMinutes(),
    second: date.getUTCSeconds(),
    millisecond: date.getUTCMilliseconds()
  };
}

/**
 * Calculate time difference between two timestamps
 *
 * @param timestamp1 - First timestamp
 * @param timestamp2 - Second timestamp
 * @returns Time difference in milliseconds
 */
export function getTimeDifference(timestamp1: ISOTimestamp, timestamp2: ISOTimestamp): number | null {
  if (!isValidISOTimestamp(timestamp1) || !isValidISOTimestamp(timestamp2)) {
    return null;
  }

  const date1 = new Date(timestamp1);
  const date2 = new Date(timestamp2);
  return Math.abs(date2.getTime() - date1.getTime());
}

/**
 * Check if timestamp is within specified duration from now
 *
 * @param timestamp - Timestamp to check
 * @param durationMs - Duration in milliseconds
 * @returns True if within duration
 */
export function isTimestampRecent(timestamp: ISOTimestamp, durationMs: number): boolean {
  if (!isValidISOTimestamp(timestamp)) {
    return false;
  }

  const now = new Date();
  const targetDate = new Date(timestamp);
  const difference = Math.abs(now.getTime() - targetDate.getTime());

  return difference <= durationMs;
}

/**
 * Format timestamp for display
 *
 * @param timestamp - ISO timestamp
 * @param format - Format type ('short' | 'medium' | 'long')
 * @returns Formatted timestamp
 */
export function formatTimestamp(
  timestamp: ISOTimestamp,
  format: 'short' | 'medium' | 'long' = 'medium'
): string {
  if (!isValidISOTimestamp(timestamp)) {
    return 'Invalid timestamp';
  }

  const date = new Date(timestamp);

  switch (format) {
    case 'short':
      return date.toLocaleDateString();
    case 'medium':
      return date.toLocaleString();
    case 'long':
      return date.toLocaleString('en-US', {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        timeZoneName: 'short'
      });
    default:
      return date.toLocaleString();
  }
}

/**
 * Generate a time-based UUID (v4 with timestamp prefix for sorting)
 *
 * @returns Time-based UUID string
 */
export function generateTimeBasedUUID(): UUID {
  const timestamp = Date.now().toString(36);
  const random = randomUUID().replace(/-/g, '');
  return `${timestamp}_${random}`;
}

/**
 * Generate a deterministic UUID from string input
 *
 * @param input - Input string to hash
 * @returns Deterministic UUID
 */
export function generateDeterministicUUID(input: string): UUID {
  const crypto = require('crypto');
  const hash = crypto.createHash('sha256').update(input).digest('hex');

  // Convert hash to UUID format
  return [
    hash.substring(0, 8),
    hash.substring(8, 12),
    // Set version to 4
    '4' + hash.substring(13, 16),
    // Set variant bits
    ((parseInt(hash.substring(16, 18), 16) & 0x3f) | 0x80).toString(16) + hash.substring(18, 20),
    hash.substring(20, 32)
  ].join('-');
}

/**
 * Extract namespace from namespaced UUID
 *
 * @param namespacedUuid - Namespaced UUID
 * @returns Namespace part or null if not namespaced
 */
export function extractNamespace(namespacedUuid: string): string | null {
  const parts = namespacedUuid.split('_');
  if (parts.length >= 2 && isValidUUID(parts.slice(1).join('_'))) {
    return parts[0];
  }
  return null;
}

/**
 * Generate UUID for specific entity types
 *
 * @param entityType - Type of entity
 * @param id - Optional base ID
 * @returns Entity-specific UUID
 */
export function generateEntityUUID(entityType: string, id?: string): UUID {
  if (id) {
    return generateDeterministicUUID(`${entityType}:${id}`);
  }
  return generateNamespacedUUID(entityType);
}