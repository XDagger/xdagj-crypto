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

import io.xdag.crypto.exception.CryptoException;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

class AesTest {



    @Test
    void shouldEncryptAndDecryptSuccessfully() throws CryptoException {
        Bytes plaintext = Bytes.wrap("Hello, World!".getBytes());
        Bytes32 key = Bytes32.random();
        Bytes32 nonce = Bytes32.random();

        Bytes ciphertext = Aes.encrypt(plaintext, key, nonce);
        assertNotNull(ciphertext);
        assertNotEquals(plaintext, ciphertext);

        Bytes decrypted = Aes.decrypt(ciphertext, key, nonce);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void shouldEncryptAndDecryptLongerData() throws CryptoException {
        Bytes plaintext = Bytes.wrap("This is a longer message that should be encrypted and decrypted correctly.".getBytes());
        Bytes32 key = Bytes32.random();
        Bytes32 nonce = Bytes32.random();

        Bytes ciphertext = Aes.encrypt(plaintext, key, nonce);
        assertNotNull(ciphertext);
        assertNotEquals(plaintext, ciphertext);

        Bytes decrypted = Aes.decrypt(ciphertext, key, nonce);
        assertEquals(plaintext, decrypted);
    }

    @Test
    void shouldThrowOnNullPlaintext() {
        Bytes32 key = Bytes32.random();
        Bytes32 nonce = Bytes32.random();

        CryptoException exception = assertThrows(CryptoException.class, () -> Aes.encrypt(null, key, nonce));
        assertTrue(exception.getMessage().contains("plaintext"));
    }

    @Test
    void shouldThrowOnNullKey() {
        Bytes plaintext = Bytes.wrap("test".getBytes());
        Bytes32 nonce = Bytes32.random();

        CryptoException exception = assertThrows(CryptoException.class, () -> Aes.encrypt(plaintext, null, nonce));
        assertTrue(exception.getMessage().contains("key"));
    }

    @Test
    void shouldThrowOnNullNonce() {
        Bytes plaintext = Bytes.wrap("test".getBytes());
        Bytes32 key = Bytes32.random();

        CryptoException exception = assertThrows(CryptoException.class, () -> Aes.encrypt(plaintext, key, null));
        assertTrue(exception.getMessage().contains("nonce"));
    }

    @Test
    void shouldThrowOnDecryptWithNullCiphertext() {
        Bytes32 key = Bytes32.random();
        Bytes32 nonce = Bytes32.random();

        CryptoException exception = assertThrows(CryptoException.class, () -> Aes.decrypt(null, key, nonce));
        assertTrue(exception.getMessage().contains("ciphertext"));
    }

    @Test
    void shouldThrowOnDecryptWithNullKey() {
        Bytes ciphertext = Bytes.wrap("test".getBytes());
        Bytes32 nonce = Bytes32.random();

        CryptoException exception = assertThrows(CryptoException.class, () -> Aes.decrypt(ciphertext, null, nonce));
        assertTrue(exception.getMessage().contains("key"));
    }

    @Test
    void shouldThrowOnDecryptWithNullNonce() {
        Bytes ciphertext = Bytes.wrap("test".getBytes());
        Bytes32 key = Bytes32.random();

        CryptoException exception = assertThrows(CryptoException.class, () -> Aes.decrypt(ciphertext, key, null));
        assertTrue(exception.getMessage().contains("nonce"));
    }
} 