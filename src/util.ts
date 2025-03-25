import { webcrypto } from 'crypto';

/**
 * Generate a random hex string of specified length
 * @param bytes Number of random bytes to generate
 * @returns Hex string
 */
export function generateRandomHex(bytes: number): string {
  const randomBytes = new Uint8Array(bytes);
  webcrypto.getRandomValues(randomBytes);
  return Array.from(randomBytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

export function toBase64(input: Buffer): string {
  const bytes = new Uint8Array(input);
  return btoa(String.fromCharCode(...bytes));
}

export function toHex(input: Buffer): string {
  const bytes = new Uint8Array(input);
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}
