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

import io.xdag.crypto.exception.CryptoException;
import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;


/**
 * Provides AES-256-GCM authenticated encryption and decryption.
 *
 * <p>This utility class implements AES with Galois/Counter Mode (GCM), which is an authenticated
 * encryption mode. It not only ensures confidentiality but also provides strong integrity and
 * authenticity protection, safeguarding against tampering.
 *
 * <p>Key properties:
 * <ul>
 *   <li><b>Algorithm:</b> AES-256-GCM (AES/GCM/NoPadding)
 *   <li><b>Key Size:</b> 256 bits (32 bytes)
 *   <li><b>Nonce (IV) Size:</b> 96 bits (12 bytes) is recommended for GCM.
 *   <li><b>Authentication Tag Size:</b> 128 bits (16 bytes) for strong security.
 * </ul>
 *
 * This class is thread-safe and uses {@link org.apache.tuweni.bytes.Bytes} for high-performance,
 * zero-copy operations.
 */
public final class Aes {

    private static final int NONCE_SIZE_BYTES = 12;
    private static final int TAG_SIZE_BITS = 128;

    /**
     * Private constructor to prevent instantiation of this utility class.
     */
    private Aes() {
    }


    /**
     * Encrypts data using AES-256-GCM.
     *
     * @param plainText The plaintext data to encrypt.
     * @param key The 32-byte encryption key.
     * @param nonce The 12-byte nonce (IV). It must be unique for each encryption with the same key.
     * @return The encrypted data, consisting of the ciphertext concatenated with the 16-byte
     *     authentication tag.
     * @throws CryptoException if the encryption fails or inputs are invalid.
     */
    public static Bytes encrypt(Bytes plainText, Bytes key, Bytes nonce) throws CryptoException {
        // Validate inputs - check null first
        if (plainText == null) {
            throw new CryptoException("Plaintext cannot be null");
        }
        if (key == null) {
            throw new CryptoException("Key cannot be null");
        }
        if (nonce == null) {
            throw new CryptoException("Nonce cannot be null");
        }
        
        // Validate sizes
        if (key.size() != 32) {
            throw new CryptoException("Key must be 32 bytes for AES-256, got: " + key.size());
        }
        if (nonce.size() != NONCE_SIZE_BYTES) {
            throw new CryptoException("Nonce must be " + NONCE_SIZE_BYTES + " bytes for GCM, got: " + nonce.size());
        }

        GCMModeCipher cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
        AEADParameters params = new AEADParameters(new KeyParameter(key.toArrayUnsafe()), TAG_SIZE_BITS, nonce.toArrayUnsafe());
        cipher.init(true, params);

        byte[] output = new byte[cipher.getOutputSize(plainText.size())];
        int length = cipher.processBytes(plainText.toArrayUnsafe(), 0, plainText.size(), output, 0);

        try {
            length += cipher.doFinal(output, length);
        } catch (InvalidCipherTextException e) {
            throw new CryptoException("AES-GCM encryption failed during finalization.", e);
        }

        return Bytes.wrap(output, 0, length);
    }

    /**
     * Decrypts data using AES-256-GCM.
     *
     * @param cipherTextWithTag The encrypted data, which includes the ciphertext followed by the
     *     16-byte authentication tag.
     * @param key The 32-byte decryption key.
     * @param nonce The 12-byte nonce (IV) that was used for encryption.
     * @return The decrypted plaintext data.
     * @throws CryptoException if decryption fails, typically due to an invalid tag (tampering) or
     *     incorrect key/nonce.
     */
    public static Bytes decrypt(Bytes cipherText, Bytes key, Bytes nonce) throws CryptoException {
        // Validate inputs - check null first
        if (cipherText == null) {
            throw new CryptoException("Ciphertext cannot be null");
        }
        if (key == null) {
            throw new CryptoException("Key cannot be null");
        }
        if (nonce == null) {
            throw new CryptoException("Nonce cannot be null");
        }
        
        // Validate sizes
        if (key.size() != 32) {
            throw new CryptoException("Key must be 32 bytes for AES-256, got: " + key.size());
        }
        if (nonce.size() != NONCE_SIZE_BYTES) {
            throw new CryptoException("Nonce must be " + NONCE_SIZE_BYTES + " bytes for GCM, got: " + nonce.size());
        }
        if (cipherText.size() < TAG_SIZE_BITS / 8) {
            throw new CryptoException("Ciphertext is too short to contain a valid authentication tag.");
        }

        try {
            GCMModeCipher cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
            AEADParameters params = new AEADParameters(new KeyParameter(key.toArrayUnsafe()), TAG_SIZE_BITS, nonce.toArrayUnsafe());
            cipher.init(false, params);

            byte[] output = new byte[cipher.getOutputSize(cipherText.size())];
            int length = cipher.processBytes(cipherText.toArrayUnsafe(), 0, cipherText.size(), output, 0);

            length += cipher.doFinal(output, length);

            return Bytes.wrap(output, 0, length);
        } catch (InvalidCipherTextException e) {
            throw new CryptoException("AES-GCM decryption failed. The data may be tampered or the key/nonce is incorrect.", e);
        }
    }
}
