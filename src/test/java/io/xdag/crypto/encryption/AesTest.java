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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.xdag.crypto.core.SecureRandomProvider;
import io.xdag.crypto.exception.CryptoException;
import java.nio.charset.StandardCharsets;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.MutableBytes;
import org.junit.jupiter.api.Test;

class AesTest {

    private final Bytes key = Bytes.wrap(SecureRandomProvider.getRandomBytes(32));
    private final Bytes nonce = Bytes.wrap(SecureRandomProvider.getRandomBytes(12));
    private final Bytes plainText = Bytes.wrap("Hello, XDAG! This is a test.".getBytes(StandardCharsets.UTF_8));

    @Test
    void shouldEncryptAndDecryptSuccessfully() throws CryptoException {
        Bytes cipherText = Aes.encrypt(plainText, key, nonce);
        assertThat(cipherText).isNotNull().isNotEqualTo(plainText);

        Bytes decryptedText = Aes.decrypt(cipherText, key, nonce);
        assertThat(decryptedText).isEqualTo(plainText);
    }

    @Test
    void shouldEncryptEmptyPlainText() throws CryptoException {
        Bytes emptyPlainText = Bytes.EMPTY;
        Bytes cipherText = Aes.encrypt(emptyPlainText, key, nonce);
        assertThat(cipherText).isNotNull();

        Bytes decryptedText = Aes.decrypt(cipherText, key, nonce);
        assertThat(decryptedText).isEqualTo(emptyPlainText);
    }

    @Test
    void shouldFailToDecryptTamperedCipherText() throws CryptoException {
        Bytes cipherText = Aes.encrypt(plainText, key, nonce);

        MutableBytes tamperedCipherText = cipherText.mutableCopy();
        // Flip the last byte of the ciphertext (part of the tag)
        byte originalByte = tamperedCipherText.get(tamperedCipherText.size() - 1);
        tamperedCipherText.set(tamperedCipherText.size() - 1, (byte) (originalByte + 1));

        assertThatThrownBy(() -> Aes.decrypt(tamperedCipherText, key, nonce))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("decryption failed");
    }

    @Test
    void shouldFailToDecryptWithWrongKey() throws CryptoException {
        Bytes cipherText = Aes.encrypt(plainText, key, nonce);
        Bytes wrongKey = Bytes.wrap(SecureRandomProvider.getRandomBytes(32));

        assertThatThrownBy(() -> Aes.decrypt(cipherText, wrongKey, nonce))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("decryption failed");
    }

    @Test
    void shouldFailToDecryptWithWrongNonce() throws CryptoException {
        Bytes cipherText = Aes.encrypt(plainText, key, nonce);
        Bytes wrongNonce = Bytes.wrap(SecureRandomProvider.getRandomBytes(12));

        assertThatThrownBy(() -> Aes.decrypt(cipherText, key, wrongNonce))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("decryption failed");
    }

    @Test
    void shouldThrowExceptionWithInvalidKeySize() {
        Bytes invalidKey = Bytes.wrap(SecureRandomProvider.getRandomBytes(16));
        assertThatThrownBy(() -> Aes.encrypt(plainText, invalidKey, nonce))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Key must be 32 bytes for AES-256.");
    }

    @Test
    void shouldThrowExceptionWithInvalidNonceSize() {
        Bytes invalidNonce = Bytes.wrap(SecureRandomProvider.getRandomBytes(16));
        assertThatThrownBy(() -> Aes.encrypt(plainText, key, invalidNonce))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Nonce must be 12 bytes for GCM.");
    }

    @Test
    void shouldThrowExceptionWithCipherTextTooShort() {
        // A valid tag is 16 bytes (128 bits), so anything shorter is invalid.
        Bytes shortCipherText = Bytes.wrap(SecureRandomProvider.getRandomBytes(15));
        assertThatThrownBy(() -> Aes.decrypt(shortCipherText, key, nonce))
                .isInstanceOf(CryptoException.class)
                .hasMessage("Ciphertext is too short to contain a valid authentication tag.");
    }
} 