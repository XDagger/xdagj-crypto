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
    void shouldEncryptAndDecryptSuccessfully() throws CryptoException {
        Bytes plaintext = Bytes.wrap("Hello, XDAG!".getBytes());
        Bytes32 key = Bytes32.random();
        Bytes nonce = Bytes.wrap(CryptoProvider.getRandomBytes(NONCE_SIZE)); // 12 bytes for GCM

        Bytes ciphertext = Aes.encrypt(plaintext, key, nonce);
        assertNotNull(ciphertext);
        assertNotEquals(plaintext, ciphertext);

        Bytes decrypted = Aes.decrypt(ciphertext, key, nonce);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void shouldEncryptAndDecryptEmptyData() throws CryptoException {
        Bytes plaintext = Bytes.EMPTY;
        Bytes32 key = Bytes32.random();
        Bytes nonce = Bytes.wrap(CryptoProvider.getRandomBytes(NONCE_SIZE));

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
        Bytes nonce = Bytes.wrap(CryptoProvider.getRandomBytes(NONCE_SIZE)); // 12 bytes for GCM

        Bytes ciphertext = Aes.encrypt(plaintext, key, nonce);
        assertNotNull(ciphertext);
        assertNotEquals(plaintext, ciphertext);

        Bytes decrypted = Aes.decrypt(ciphertext, key, nonce);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void shouldThrowOnNullPlaintext() {
        Bytes32 key = Bytes32.random();
        Bytes nonce = Bytes.wrap(CryptoProvider.getRandomBytes(NONCE_SIZE));

        CryptoException exception = assertThrows(CryptoException.class, () -> Aes.encrypt(null, key, nonce));
        assertTrue(exception.getMessage().contains("Plaintext cannot be null"));
    }

    @Test
    void shouldThrowOnNullKey() {
        Bytes plaintext = Bytes.wrap("test".getBytes());
        Bytes nonce = Bytes.wrap(CryptoProvider.getRandomBytes(NONCE_SIZE));

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
        Bytes nonce = Bytes.wrap(CryptoProvider.getRandomBytes(NONCE_SIZE));

        CryptoException exception = assertThrows(CryptoException.class, () -> Aes.decrypt(null, key, nonce));
        assertTrue(exception.getMessage().contains("Ciphertext cannot be null"));
    }

    @Test
    void shouldThrowOnDecryptWithNullKey() {
        Bytes ciphertext = Bytes.wrap(new byte[32]);
        Bytes nonce = Bytes.wrap(CryptoProvider.getRandomBytes(NONCE_SIZE));

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
        Bytes shortKey = Bytes.wrap(new byte[16]); // Wrong size (16 bytes instead of 32)
        Bytes nonce = Bytes.wrap(CryptoProvider.getRandomBytes(NONCE_SIZE));

        CryptoException exception = assertThrows(CryptoException.class, () -> Aes.encrypt(plaintext, shortKey, nonce));
        assertTrue(exception.getMessage().contains("Key must be 32 bytes"));
    }

    @Test
    void shouldThrowOnInvalidNonceSize() {
        Bytes plaintext = Bytes.wrap("test".getBytes());
        Bytes32 key = Bytes32.random();
        Bytes wrongNonce = Bytes.wrap(new byte[16]); // Wrong size (16 bytes instead of 12)

        CryptoException exception = assertThrows(CryptoException.class, () -> Aes.encrypt(plaintext, key, wrongNonce));
        assertTrue(exception.getMessage().contains("Nonce must be 12 bytes"));
    }
} 