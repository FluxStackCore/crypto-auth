/**
 * Tests for CryptoAuthClient bug fixes
 * Covers: Bug #1 (private key in localStorage), Bug #2 (Ed25519 sign hash),
 *         Bug #8 (localStorage as default)
 */

import { describe, test, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519'
import { hexToBytes, bytesToHex } from '@noble/hashes/utils'

// We import the class directly
import { CryptoAuthClient } from '../client/CryptoAuthClient'

describe('Bug #1 & #8: Default storage should be memory, not localStorage', () => {
  test('default storage config should be "memory"', () => {
    const client = new CryptoAuthClient({ autoInit: false })
    // Access config via the public interface - the default should be memory
    // We verify by checking that the internal config was set correctly
    expect((client as any).config.storage).toBe('memory')
  })

  test('default constructor uses Map storage (not localStorage)', () => {
    const client = new CryptoAuthClient({ autoInit: false })
    expect((client as any).storage).toBeInstanceOf(Map)
  })

  test('explicitly requesting localStorage should still work', () => {
    // In a non-browser env, localStorage is undefined so it falls back to Map
    // But the config should be set to localStorage
    const client = new CryptoAuthClient({ storage: 'localStorage', autoInit: false })
    expect((client as any).config.storage).toBe('localStorage')
  })

  test('keys are stored in memory by default and not leaked', () => {
    const client = new CryptoAuthClient()
    const keys = client.getKeys()
    expect(keys).not.toBeNull()
    expect(keys!.privateKey).toBeTruthy()

    // The storage should be a Map (memory)
    const storage = (client as any).storage as Map<string, string>
    expect(storage).toBeInstanceOf(Map)

    // Key should be in the map
    const storedData = storage.get('fluxstack_crypto_keys')
    expect(storedData).toBeTruthy()

    // Clear and verify
    client.clearKeys()
    expect(storage.get('fluxstack_crypto_keys')).toBeUndefined()
  })
})

describe('Bug #2: Ed25519 should sign raw message, not SHA256 hash', () => {
  test('signature should be verifiable with standard ed25519.verify using raw message', () => {
    const client = new CryptoAuthClient()
    const keys = client.getKeys()!

    // Simulate what signMessage does internally
    const timestamp = Date.now()
    const nonce = 'testnonce1234567890abcdef'
    const message = 'GET:http://example.com/api/test'

    // Call the private signMessage method
    const signature = (client as any).signMessage(message, timestamp, nonce)

    // Reconstruct the full message as the client does
    const fullMessage = `${keys.publicKey}:${timestamp}:${nonce}:${message}`
    const messageBytes = new TextEncoder().encode(fullMessage)

    // Verify with standard ed25519.verify - this should work with the fix
    const signatureBytes = hexToBytes(signature)
    const publicKeyBytes = hexToBytes(keys.publicKey)

    const isValid = ed25519.verify(signatureBytes, messageBytes, publicKeyBytes)
    expect(isValid).toBe(true)
  })

  test('signature should NOT be verifiable if message is tampered', () => {
    const client = new CryptoAuthClient()
    const keys = client.getKeys()!

    const timestamp = Date.now()
    const nonce = 'testnonce1234567890abcdef'
    const message = 'GET:http://example.com/api/test'

    const signature = (client as any).signMessage(message, timestamp, nonce)

    // Tamper with message
    const tamperedMessage = `${keys.publicKey}:${timestamp}:${nonce}:POST:http://example.com/api/test`
    const tamperedBytes = new TextEncoder().encode(tamperedMessage)

    const signatureBytes = hexToBytes(signature)
    const publicKeyBytes = hexToBytes(keys.publicKey)

    const isValid = ed25519.verify(signatureBytes, tamperedBytes, publicKeyBytes)
    expect(isValid).toBe(false)
  })
})
