/**
 * Generate a random hex string of specified length
 * @param bytes Number of random bytes to generate
 * @returns Hex string
 */
export function generateRandomHex(bytes: number): string {
  const randomBytes = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i++) {
    randomBytes[i] = Math.floor(Math.random() * 256);
  }
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

/**
 * Convert a buffer to base64 string without padding
 * @param input Buffer to convert
 * @returns Base64 string without padding
 */
export function toBase64NoPadding(input: Buffer): string {
  const base64 = toBase64(input);
  return base64.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

/**
 * Validates if a string is base64url encoded.
 * Base64url is a URL-safe variant of base64 encoding that uses '-' instead of '+' and '_' instead of '/'.
 * @param str The string to validate
 * @returns True if the string is base64url encoded, false otherwise
 */
export const isBase64UrlEncoded = (str: string): boolean => {
  // Check if the string is empty or contains characters outside the base64url character set
  if (!str || !/^[-A-Za-z0-9_]*={0,2}$/.test(str)) {
    return false;
  }

  // Check if padding is correct (if present)
  const padding = str.match(/=*$/)?.[0]?.length || 0;
  if (padding > 0) {
    // If padding exists, it must be either 1 or 2 characters
    if (padding > 2) {
      return false;
    }

    // Check if length is valid with padding
    if ((str.length - padding) % 4 !== 0) {
      return false;
    }
  }

  return true;
};

/**
 * Decodes a base64url encoded string to a base64 string.
 * Base64url is a URL-safe variant of base64 encoding that uses '-' instead of '+' and '_' instead of '/'.
 * @param str The base64url encoded string to decode
 * @returns The base64 string
 */
export function fromBase64Url(str: string): string {
  // Convert from base64url to standard base64
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');

  // Add padding if necessary
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return base64;
}
