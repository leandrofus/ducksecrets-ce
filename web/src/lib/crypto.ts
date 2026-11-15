// Zero-knowledge client-side encryption using Web Crypto API with pure JS fallback.
// Keys never leave the browser; URLs store the key in the hash fragment.

import { gcm } from '@noble/ciphers/aes.js'
import { pbkdf2 } from '@noble/hashes/pbkdf2.js'
import { sha256 } from '@noble/hashes/sha2.js'

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

export function base64ToBytes(base64: string): Uint8Array {
  let binary: string
  try {
    binary = atob(base64)
  } catch {
    throw new Error('Invalid or corrupted base64 data in share payload or URL.')
  }
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

export function base64UrlToBytes(base64url: string): Uint8Array {
  if (!base64url || !/^[A-Za-z0-9_-]+={0,2}$/.test(base64url)) {
    throw new Error('Invalid or malformed decryption key in share URL.')
  }
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
  while (base64.length % 4) {
    base64 += '='
  }
  return base64ToBytes(base64)
}

function getRandomBytes(length: number): Uint8Array {
  const cryptoObj = globalThis.crypto
  if (!cryptoObj || typeof cryptoObj.getRandomValues !== 'function') {
    throw new Error('Secure random number generator (crypto.getRandomValues) is unavailable in this environment.')
  }
  const bytes = new Uint8Array(length)
  cryptoObj.getRandomValues(bytes)
  return bytes
}

export interface EncryptedShareResult {
  ciphertext: string // Base64
  nonce: string // Base64 (12 bytes)
  keyUrlSafe: string // Base64URL
  hasPassphrase: boolean
  passphraseSalt?: string // Base64 (16 bytes)
}

export async function encryptShare(
  secretText: string,
  passphrase?: string
): Promise<EncryptedShareResult> {
  const secretBytes = new TextEncoder().encode(secretText)
  const rawKey = getRandomBytes(32)
  const nonce = getRandomBytes(12)

  let saltBytes: Uint8Array | undefined
  let ciphertextBytes: Uint8Array

  const hasSubtle = typeof window !== 'undefined' && window.crypto && !!window.crypto.subtle

  if (hasSubtle) {
    let cryptoKey: CryptoKey
    if (passphrase && passphrase.trim() !== '') {
      saltBytes = getRandomBytes(16)
      const passBytes = new TextEncoder().encode(passphrase.trim())
      const combined = new Uint8Array(rawKey.length + passBytes.length)
      combined.set(rawKey)
      combined.set(passBytes, rawKey.length)

      const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        combined as any,
        'PBKDF2',
        false,
        ['deriveKey']
      )

      cryptoKey = await window.crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: saltBytes as any,
          iterations: 100000,
          hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
      )
    } else {
      cryptoKey = await window.crypto.subtle.importKey(
        'raw',
        rawKey as any,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
      )
    }

    const ciphertextBuf = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce as any },
      cryptoKey,
      secretBytes as any
    )
    ciphertextBytes = new Uint8Array(ciphertextBuf)
  } else {
    // Pure JS fallback for non-secure contexts (HTTP / Tailscale / LAN)
    let encKey = rawKey
    if (passphrase && passphrase.trim() !== '') {
      saltBytes = getRandomBytes(16)
      const passBytes = new TextEncoder().encode(passphrase.trim())
      const combined = new Uint8Array(rawKey.length + passBytes.length)
      combined.set(rawKey)
      combined.set(passBytes, rawKey.length)

      encKey = pbkdf2(sha256, combined, saltBytes, { c: 100000, dkLen: 32 })
    }
    const cipher = gcm(encKey, nonce)
    ciphertextBytes = cipher.encrypt(secretBytes)
  }

  return {
    ciphertext: bytesToBase64(ciphertextBytes),
    nonce: bytesToBase64(nonce),
    keyUrlSafe: bytesToBase64Url(rawKey),
    hasPassphrase: Boolean(passphrase && passphrase.trim() !== ''),
    passphraseSalt: saltBytes ? bytesToBase64(saltBytes) : undefined,
  }
}

export async function decryptShare(
  ciphertextBase64: string,
  nonceBase64: string,
  keyUrlSafe: string,
  passphrase?: string,
  passphraseSaltBase64?: string
): Promise<string> {
  const ciphertextBytes = base64ToBytes(ciphertextBase64)
  const nonceBytes = base64ToBytes(nonceBase64)
  const rawKey = base64UrlToBytes(keyUrlSafe)
  if (rawKey.length !== 32) {
    throw new Error('Invalid decryption key length in share URL.')
  }

  const hasSubtle = typeof window !== 'undefined' && window.crypto && !!window.crypto.subtle

  if (hasSubtle) {
    let cryptoKey: CryptoKey

    if (passphraseSaltBase64) {
      if (!passphrase || passphrase.trim() === '') {
        throw new Error('A passphrase is required to decrypt this secret.')
      }
      const saltBytes = base64ToBytes(passphraseSaltBase64)
      const passBytes = new TextEncoder().encode(passphrase.trim())
      const combined = new Uint8Array(rawKey.length + passBytes.length)
      combined.set(rawKey)
      combined.set(passBytes, rawKey.length)

      const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        combined as any,
        'PBKDF2',
        false,
        ['deriveKey']
      )

      cryptoKey = await window.crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: saltBytes as any,
          iterations: 100000,
          hash: 'SHA-256',
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      )
    } else {
      cryptoKey = await window.crypto.subtle.importKey(
        'raw',
        rawKey as any,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
      )
    }

    try {
      const decryptedBuf = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonceBytes as any },
        cryptoKey,
        ciphertextBytes as any
      )
      return new TextDecoder().decode(decryptedBuf)
    } catch {
      throw new Error('Decryption failed. Invalid key or incorrect passphrase.')
    }
  } else {
    // Pure JS fallback
    let decKey = rawKey
    if (passphraseSaltBase64) {
      if (!passphrase || passphrase.trim() === '') {
        throw new Error('A passphrase is required to decrypt this secret.')
      }
      const saltBytes = base64ToBytes(passphraseSaltBase64)
      const passBytes = new TextEncoder().encode(passphrase.trim())
      const combined = new Uint8Array(rawKey.length + passBytes.length)
      combined.set(rawKey)
      combined.set(passBytes, rawKey.length)

      decKey = pbkdf2(sha256, combined, saltBytes, { c: 100000, dkLen: 32 })
    }
    try {
      const cipher = gcm(decKey, nonceBytes)
      const decrypted = cipher.decrypt(ciphertextBytes)
      return new TextDecoder().decode(decrypted)
    } catch {
      throw new Error('Decryption failed. Invalid key or incorrect passphrase.')
    }
  }
}
