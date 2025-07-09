import * as crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16; // For AES, this is 16 bytes


/**
 * Encrypts a string using AES-256-GCM.
 *
 * @param text The plain text to encrypt.
 * @param encryptionKey The secret key (32 bytes, base64 encoded) for encryption.
 * @returns A string containing the IV, encrypted data, and auth tag, all base64 encoded and joined by colons.
 */
export function encrypt(text: string, encryptionKey: string): string {
  const keyBuffer = Buffer.from(encryptionKey, 'base64');
  if (keyBuffer.length !== 32) {
    throw new Error('Encryption key must be 32 bytes (256 bits) when base64 decoded.');
  }

  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, keyBuffer, iv);

  let encrypted = cipher.update(text, 'utf8', 'base64');
  encrypted += cipher.final('base64');

  const tag = cipher.getAuthTag();

  return `${iv.toString('base64')}:${encrypted}:${tag.toString('base64')}`;
}

/**
 * Decrypts a string using AES-256-GCM.
 *
 * @param encryptedText The encrypted string (IV:encryptedData:authTag, all base64 encoded).
 * @param encryptionKey The secret key (32 bytes, base64 encoded) for decryption.
 * @returns The decrypted plain text.
 */
export function decrypt(encryptedText: string, encryptionKey: string): string {
  const keyBuffer = Buffer.from(encryptionKey, 'base64');
  if (keyBuffer.length !== 32) {
    throw new Error('Encryption key must be 32 bytes (256 bits) when base64 decoded.');
  }

  const parts = encryptedText.split(':');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted text format. Expected IV:EncryptedData:AuthTag');
  }

  const iv = Buffer.from(parts[0], 'base64');
  const encryptedData = parts[1];
  const tag = Buffer.from(parts[2], 'base64');

  const decipher = crypto.createDecipheriv(ALGORITHM, keyBuffer, iv);
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}