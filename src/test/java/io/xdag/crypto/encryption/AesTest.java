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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

class AesTest {

    @BeforeAll
    static void setupSecurity() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void shouldEncryptAndDecryptCorrectly() {
        byte[] plaintext = "Hello, XDAG!".getBytes();
        byte[] key = CryptoProvider.nextBytes(32); // AES-256
        byte[] iv = CryptoProvider.nextBytes(16);  // 16 bytes for CBC

        byte[] ciphertext = Aes.encrypt(plaintext, key, iv);
        assertNotNull(ciphertext);
        assertTrue(ciphertext.length >= plaintext.length);

        byte[] decrypted = Aes.decrypt(ciphertext, key, iv);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void shouldWorkWithDifferentKeySizes() {
        byte[] plaintext = "Test data for different key sizes".getBytes();
        byte[] iv = CryptoProvider.nextBytes(16);

        // Test AES-128
        byte[] key128 = CryptoProvider.nextBytes(16);
        byte[] encrypted128 = Aes.encrypt(plaintext, key128, iv);
        assertArrayEquals(plaintext, Aes.decrypt(encrypted128, key128, iv));

        // Test AES-192
        byte[] key192 = CryptoProvider.nextBytes(24);
        byte[] encrypted192 = Aes.encrypt(plaintext, key192, iv);
        assertArrayEquals(plaintext, Aes.decrypt(encrypted192, key192, iv));

        // Test AES-256
        byte[] key256 = CryptoProvider.nextBytes(32);
        byte[] encrypted256 = Aes.encrypt(plaintext, key256, iv);
        assertArrayEquals(plaintext, Aes.decrypt(encrypted256, key256, iv));
    }

    @Test
    void shouldHandleEmptyData() {
        byte[] plaintext = new byte[0];
        byte[] key = CryptoProvider.nextBytes(32);
        byte[] iv = CryptoProvider.nextBytes(16);

        byte[] ciphertext = Aes.encrypt(plaintext, key, iv);
        byte[] decrypted = Aes.decrypt(ciphertext, key, iv);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void shouldWorkWithLargeData() {
        byte[] plaintext = CryptoProvider.nextBytes(1024 * 10); // 10KB
        
        byte[] key = CryptoProvider.nextBytes(32);
        byte[] iv = CryptoProvider.nextBytes(16);

        byte[] ciphertext = Aes.encrypt(plaintext, key, iv);
        byte[] decrypted = Aes.decrypt(ciphertext, key, iv);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void shouldFailWithWrongKey() {
        byte[] plaintext = "Secret message".getBytes();
        byte[] key = CryptoProvider.nextBytes(32);
        byte[] wrongKey = CryptoProvider.nextBytes(32);
        byte[] iv = CryptoProvider.nextBytes(16);

        byte[] ciphertext = Aes.encrypt(plaintext, key, iv);
        
        // Decryption with a wrong key should fail due to padding corruption
        assertThrows(RuntimeException.class, () -> Aes.decrypt(ciphertext, wrongKey, iv));
    }

    @Test
    void shouldWorkWithXdagWalletScenario() {
        // Test exact xdagj Wallet scenario: 24-byte key + 16-byte IV
        byte[] walletData = "Private key data for wallet".getBytes();
        byte[] key = CryptoProvider.nextBytes(24); // BCrypt key length
        byte[] iv = CryptoProvider.nextBytes(16);  // SecureRandomProvider IV

        byte[] encrypted = Aes.encrypt(walletData, key, iv);
        assertNotNull(encrypted);
        assertTrue(encrypted.length > walletData.length); // Should include padding
        
        byte[] decrypted = Aes.decrypt(encrypted, key, iv);
        assertArrayEquals(walletData, decrypted);
    }
} 