/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2020-2030 The XdagJ Developers
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package io.xdag.crypto.encryption;

import static org.junit.jupiter.api.Assertions.*;

import io.xdag.crypto.core.CryptoProvider;
import io.xdag.crypto.exception.CryptoException;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

public class AesTest {

    private static final int NONCE_SIZE = 12; // 12 bytes for GCM

    @Test
    void shouldEncryptAndDecryptWithAes256() throws CryptoException {
        Bytes plaintext = Bytes.wrap("Hello, XDAG!".getBytes());
        Bytes32 key = Bytes32.random(); // 32 bytes - AES-256
        Bytes nonce = Bytes.wrap(CryptoProvider.nextBytes(NONCE_SIZE));

        Bytes ciphertext = Aes.encrypt(plaintext, key, nonce);
        assertNotNull(ciphertext);
        assertNotEquals(plaintext, ciphertext);

        Bytes decrypted = Aes.decrypt(ciphertext, key, nonce);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void shouldEncryptAndDecryptWithAes192() throws CryptoException {
        Bytes plaintext = Bytes.wrap("Hello, XDAG with AES-192!".getBytes());
        Bytes key = Bytes.wrap(CryptoProvider.nextBytes(24)); // 24 bytes - AES-192
        Bytes nonce = Bytes.wrap(CryptoProvider.nextBytes(NONCE_SIZE));

        Bytes ciphertext = Aes.encrypt(plaintext, key, nonce);
        assertNotNull(ciphertext);
        assertNotEquals(plaintext, ciphertext);

        Bytes decrypted = Aes.decrypt(ciphertext, key, nonce);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void shouldEncryptAndDecryptWithAes128() throws CryptoException {
        Bytes plaintext = Bytes.wrap("Hello, XDAG with AES-128!".getBytes());
        Bytes key = Bytes.wrap(CryptoProvider.nextBytes(16)); // 16 bytes - AES-128
        Bytes nonce = Bytes.wrap(CryptoProvider.nextBytes(NONCE_SIZE));

        Bytes ciphertext = Aes.encrypt(plaintext, key, nonce);
        assertNotNull(ciphertext);
        assertNotEquals(plaintext, ciphertext);

        Bytes decrypted = Aes.decrypt(ciphertext, key, nonce);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void shouldWorkWithXdagProjectKeySize() throws CryptoException {
        // Test specifically for xdagj compatibility - 24 byte key
        Bytes plaintext = Bytes.wrap("XDAG wallet data".getBytes());
        Bytes key = Bytes.wrap(CryptoProvider.nextBytes(24)); // 24 bytes like xdagj uses
        Bytes nonce = Bytes.wrap(CryptoProvider.nextBytes(NONCE_SIZE));

        Bytes ciphertext = Aes.encrypt(plaintext, key, nonce);
        assertNotNull(ciphertext);
        
        Bytes decrypted = Aes.decrypt(ciphertext, key, nonce);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void shouldSupportLegacy16ByteNonce() throws CryptoException {
        // Test for xdagj compatibility - 16 byte nonce (legacy)
        Bytes plaintext = Bytes.wrap("Legacy nonce test".getBytes());
        Bytes key = Bytes.wrap(CryptoProvider.nextBytes(24)); // AES-192
        Bytes legacyNonce = Bytes.wrap(CryptoProvider.nextBytes(16)); // 16 bytes like xdagj uses

        Bytes ciphertext = Aes.encrypt(plaintext, key, legacyNonce);
        assertNotNull(ciphertext);
        
        Bytes decrypted = Aes.decrypt(ciphertext, key, legacyNonce);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void shouldSupportXdagWalletCompatibility() throws CryptoException {
        // Test exact xdagj Wallet scenario: 24-byte key + 16-byte IV
        Bytes plaintext = Bytes.wrap("Private key data for wallet".getBytes());
        Bytes key = Bytes.wrap(CryptoProvider.nextBytes(24)); // BCrypt key length
        Bytes iv = Bytes.wrap(CryptoProvider.nextBytes(16)); // SecureRandomProvider IV

        // This should work without throwing exceptions
        Bytes ciphertext = Aes.encrypt(plaintext, key, iv);
        assertNotNull(ciphertext);
        assertTrue(ciphertext.size() > plaintext.size()); // Should include auth tag
        
        Bytes decrypted = Aes.decrypt(ciphertext, key, iv);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void shouldPreferRecommendedNonceSize() throws CryptoException {
        // Test that 12-byte nonce still works (recommended)
        Bytes plaintext = Bytes.wrap("Recommended nonce test".getBytes());
        Bytes key = Bytes.wrap(CryptoProvider.nextBytes(32)); // AES-256
        Bytes recommendedNonce = Bytes.wrap(CryptoProvider.nextBytes(12)); // Recommended size

        Bytes ciphertext = Aes.encrypt(plaintext, key, recommendedNonce);
        assertNotNull(ciphertext);
        
        Bytes decrypted = Aes.decrypt(ciphertext, key, recommendedNonce);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void shouldEncryptAndDecryptEmptyData() throws CryptoException {
        Bytes plaintext = Bytes.EMPTY;
        Bytes32 key = Bytes32.random();
        Bytes nonce = Bytes.wrap(CryptoProvider.nextBytes(NONCE_SIZE));

        Bytes ciphertext = Aes.encrypt(plaintext, key, nonce);
        assertNotNull(ciphertext);
        // Ciphertext should contain at least the authentication tag (16 bytes)
        assertTrue(ciphertext.size() >= 16);

        Bytes decrypted = Aes.decrypt(ciphertext, key, nonce);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void shouldEncryptAndDecryptLongerData() throws CryptoException {
        Bytes plaintext = Bytes.wrap("This is a longer message that should be encrypted and decrypted correctly.".getBytes());
        Bytes32 key = Bytes32.random();
        Bytes nonce = Bytes.wrap(CryptoProvider.nextBytes(NONCE_SIZE));

        Bytes ciphertext = Aes.encrypt(plaintext, key, nonce);
        assertNotNull(ciphertext);
        assertNotEquals(plaintext, ciphertext);

        Bytes decrypted = Aes.decrypt(ciphertext, key, nonce);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void shouldThrowOnNullPlaintext() {
        Bytes32 key = Bytes32.random();
        Bytes nonce = Bytes.wrap(CryptoProvider.nextBytes(NONCE_SIZE));

        CryptoException exception = assertThrows(CryptoException.class, () -> Aes.encrypt(null, key, nonce));
        assertTrue(exception.getMessage().contains("Plaintext cannot be null"));
    }

    @Test
    void shouldThrowOnNullKey() {
        Bytes plaintext = Bytes.wrap("test".getBytes());
        Bytes nonce = Bytes.wrap(CryptoProvider.nextBytes(NONCE_SIZE));

        CryptoException exception = assertThrows(CryptoException.class, () -> Aes.encrypt(plaintext, null, nonce));
        assertTrue(exception.getMessage().contains("Key cannot be null"));
    }

    @Test
    void shouldThrowOnNullNonce() {
        Bytes plaintext = Bytes.wrap("test".getBytes());
        Bytes32 key = Bytes32.random();

        CryptoException exception = assertThrows(CryptoException.class, () -> Aes.encrypt(plaintext, key, null));
        assertTrue(exception.getMessage().contains("Nonce cannot be null"));
    }

    @Test
    void shouldThrowOnDecryptWithNullCiphertext() {
        Bytes32 key = Bytes32.random();
        Bytes nonce = Bytes.wrap(CryptoProvider.nextBytes(NONCE_SIZE));

        CryptoException exception = assertThrows(CryptoException.class, () -> Aes.decrypt(null, key, nonce));
        assertTrue(exception.getMessage().contains("Ciphertext cannot be null"));
    }

    @Test
    void shouldThrowOnDecryptWithNullKey() {
        Bytes ciphertext = Bytes.wrap(new byte[32]);
        Bytes nonce = Bytes.wrap(CryptoProvider.nextBytes(NONCE_SIZE));

        CryptoException exception = assertThrows(CryptoException.class, () -> Aes.decrypt(ciphertext, null, nonce));
        assertTrue(exception.getMessage().contains("Key cannot be null"));
    }

    @Test
    void shouldThrowOnDecryptWithNullNonce() {
        Bytes ciphertext = Bytes.wrap(new byte[32]);
        Bytes32 key = Bytes32.random();

        CryptoException exception = assertThrows(CryptoException.class, () -> Aes.decrypt(ciphertext, key, null));
        assertTrue(exception.getMessage().contains("Nonce cannot be null"));
    }

    @Test
    void shouldThrowOnInvalidKeySize() {
        Bytes plaintext = Bytes.wrap("test".getBytes());
        Bytes invalidKey = Bytes.wrap(new byte[15]); // Invalid size (15 bytes)
        Bytes nonce = Bytes.wrap(CryptoProvider.nextBytes(NONCE_SIZE));

        CryptoException exception = assertThrows(CryptoException.class, () -> Aes.encrypt(plaintext, invalidKey, nonce));
        assertTrue(exception.getMessage().contains("Invalid AES key size: 15 bytes"));
        assertTrue(exception.getMessage().contains("Valid sizes are: 16 (AES-128), 24 (AES-192), or 32 (AES-256)"));
    }

    @Test
    void shouldThrowOnInvalidNonceSize() {
        Bytes plaintext = Bytes.wrap("test".getBytes());
        Bytes32 key = Bytes32.random();
        Bytes wrongNonce = Bytes.wrap(new byte[8]); // Invalid size (8 bytes)

        CryptoException exception = assertThrows(CryptoException.class, () -> Aes.encrypt(plaintext, key, wrongNonce));
        assertTrue(exception.getMessage().contains("Invalid nonce size: 8 bytes"));
        assertTrue(exception.getMessage().contains("Valid sizes are: 12 bytes (recommended) or 16 bytes (legacy compatibility)"));
    }

    @Test
    void shouldThrowOnShortCiphertext() {
        Bytes shortCiphertext = Bytes.wrap(new byte[10]); // Too short to contain auth tag
        Bytes32 key = Bytes32.random();
        Bytes nonce = Bytes.wrap(CryptoProvider.nextBytes(NONCE_SIZE));

        CryptoException exception = assertThrows(CryptoException.class, () -> Aes.decrypt(shortCiphertext, key, nonce));
        assertTrue(exception.getMessage().contains("Ciphertext is too short to contain a valid authentication tag"));
    }

    @Test
    void shouldFailDecryptionWithWrongKey() {
        Bytes plaintext = Bytes.wrap("test data".getBytes());
        Bytes key1 = Bytes.wrap(CryptoProvider.nextBytes(24));
        Bytes key2 = Bytes.wrap(CryptoProvider.nextBytes(24)); // Different key
        Bytes nonce = Bytes.wrap(CryptoProvider.nextBytes(NONCE_SIZE));

        try {
            Bytes ciphertext = Aes.encrypt(plaintext, key1, nonce);
            
            // Try to decrypt with wrong key
            CryptoException exception = assertThrows(CryptoException.class, () -> Aes.decrypt(ciphertext, key2, nonce));
            assertTrue(exception.getMessage().contains("AES-192-GCM decryption failed"));
        } catch (CryptoException e) {
            fail("Encryption should succeed");
        }
    }
} 