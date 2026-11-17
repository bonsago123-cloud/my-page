import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
export const now = () => Date.now();
export const randomToken = () => randomBytes(32).toString('base64url');
export const digest = token => createHash('sha256').update(token).digest('hex');
export const normalizeName = value => typeof value === 'string' ? value.trim() : '';
export const isUsername = value => /^[a-z0-9][a-z0-9-]{1,22}[a-z0-9]$/.test(value);
export const isPasskeyName = value => typeof value === 'string' && value.length >= 1 && value.length <= 48 && !/[<>\x00-\x1f]/.test(value);
export function cookieValue(req, name = 'passkey_session') {
  const parts = (req.headers.cookie || '').split(';');
  for (const part of parts) {
    const index = part.indexOf('=');
    if (index >= 0 && part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return null;
}
export function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}
