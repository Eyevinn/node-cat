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
  return base64.replace(/=+$/, '');
}
