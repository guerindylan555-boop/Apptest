/**
 * Cryptographic Utilities
 *
 * Cryptographic functions for hashing, digest generation, and security operations
 * used throughout the AutoApp system.
 */

import { createHash, createHmac } from 'crypto';

/**
 * Calculate SHA-256 digest of input data
 *
 * @param data - Data to hash (string or Buffer)
 * @returns SHA-256 hash as hex string
 */
export function calculateDigest(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

/**
 * Calculate SHA-256 digest with salt
 *
 * @param data - Data to hash
 * @param salt - Salt value
 * @returns Salted SHA-256 hash
 */
export function calculateSaltedDigest(data: string, salt: string): string {
  return createHash('sha256').update(data + salt).digest('hex');
}

/**
 * Calculate HMAC-SHA256
 *
 * @param data - Data to sign
 * @param secret - Secret key
 * @returns HMAC-SHA256 signature
 */
export function calculateHMAC(data: string, secret: string): string {
  return createHmac('sha256', secret).update(data).digest('hex');
}

/**
 * Generate random hex string
 *
 * @param length - Length of hex string (bytes)
 * @returns Random hex string
 */
export function generateRandomHex(length: number): string {
  const crypto = require('crypto');
  return crypto.randomBytes(length).toString('hex');
}

/**
 * Generate random alphanumeric string
 *
 * @param length - Length of string
 * @returns Random alphanumeric string
 */
export function generateRandomString(length: number): string {
  const crypto = require('crypto');
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const bytes = crypto.randomBytes(length);

  for (let i = 0; i < length; i++) {
    result += chars[bytes[i] % chars.length];
  }

  return result;
}

/**
 * Calculate MD5 hash (for legacy compatibility)
 *
 * @param data - Data to hash
 * @returns MD5 hash as hex string
 */
export function calculateMD5(data: string | Buffer): string {
  return createHash('md5').update(data).digest('hex');
}

/**
 * Verify hash matches data
 *
 * @param data - Original data
 * @param hash - Hash to verify
 * @returns True if hash matches
 */
export function verifyHash(data: string, hash: string): boolean {
  const calculatedHash = calculateDigest(data);
  return calculatedHash === hash;
}

/**
 * Calculate hash for object with sorted keys
 *
 * @param obj - Object to hash
 * @returns SHA-256 hash
 */
export function hashObject(obj: Record<string, any>): string {
  const sorted = Object.keys(obj)
    .sort()
    .reduce((result, key) => {
      if (obj[key] !== undefined && obj[key] !== null) {
        result[key] = obj[key];
      }
      return result;
    }, {} as Record<string, any>);

  const input = JSON.stringify(sorted);
  return createHash('sha256').update(input).digest('hex');
}

/**
 * Calculate file integrity checksum
 *
 * @param content - File content (string or Buffer)
 * @returns SHA-256 checksum
 */
export function calculateFileChecksum(content: string | Buffer): string {
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Generate cryptographically secure random number
 *
 * @param min - Minimum value (inclusive)
 * @param max - Maximum value (exclusive)
 * @returns Random number
 */
export function generateSecureRandomNumber(min: number, max: number): number {
  const crypto = require('crypto');
  const range = max - min;
  const bytesNeeded = Math.ceil(Math.log2(range) / 8);
  const maxVal = Math.pow(256, bytesNeeded);

  let randomNumber;
  do {
    randomNumber = crypto.randomBytes(bytesNeeded).readUIntBE(0, bytesNeeded);
  } while (randomNumber >= maxVal - (maxVal % range));

  return min + (randomNumber % range);
}