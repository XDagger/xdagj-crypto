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
 * Provides AES-GCM authenticated encryption and decryption with support for all standard key sizes.
 *
 * <p>This utility class implements AES with Galois/Counter Mode (GCM), which is an authenticated
 * encryption mode. It not only ensures confidentiality but also provides strong integrity and
 * authenticity protection, safeguarding against tampering.
 *
 * <p>Supported configurations:
 * <ul>
 *   <li><b>AES-128-GCM:</b> 128-bit key (16 bytes)</li>
 *   <li><b>AES-192-GCM:</b> 192-bit key (24 bytes)</li>
 *   <li><b>AES-256-GCM:</b> 256-bit key (32 bytes)</li>
 * </ul>
 *
 * <p>Common properties:
 * <ul>
 *   <li><b>Mode:</b> GCM (Galois/Counter Mode)</li>
 *   <li><b>Nonce (IV) Size:</b> 96 bits (12 bytes) - recommended for GCM</li>
 *   <li><b>Authentication Tag Size:</b> 128 bits (16 bytes) for strong security</li>
 * </ul>
 *
 * This class is thread-safe and uses {@link org.apache.tuweni.bytes.Bytes} for high-performance,
 * zero-copy operations.
 */
public final class Aes {

    /** Recommended nonce size for GCM mode (96 bits / 12 bytes) */
    private static final int NONCE_SIZE_BYTES = 12;
    
    /** Authentication tag size in bits (128 bits for strong security) */
    private static final int TAG_SIZE_BITS = 128;
    
    /** Valid AES key sizes in bytes */
    private static final int AES_128_KEY_SIZE = 16; // 128 bits
    private static final int AES_192_KEY_SIZE = 24; // 192 bits  
    private static final int AES_256_KEY_SIZE = 32; // 256 bits

    /**
     * Private constructor to prevent instantiation of this utility class.
     */
    private Aes() {
    }

    /**
     * Validates that the provided key size is a valid AES key length.
     * 
     * @param keySize the key size in bytes
     * @throws CryptoException if the key size is invalid
     */
    private static void validateKeySize(int keySize) throws CryptoException {
        if (keySize != AES_128_KEY_SIZE && keySize != AES_192_KEY_SIZE && keySize != AES_256_KEY_SIZE) {
            throw new CryptoException("Invalid AES key size: " + keySize + " bytes. " +
                "Valid sizes are: 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes.");
        }
    }

    /**
     * Gets the AES variant name based on key size.
     * 
     * @param keySize the key size in bytes
     * @return the AES variant name (e.g., "AES-256")
     */
    private static String getAesVariant(int keySize) {
        return switch (keySize) {
            case AES_128_KEY_SIZE -> "AES-128";
            case AES_192_KEY_SIZE -> "AES-192";
            case AES_256_KEY_SIZE -> "AES-256";
            default -> "AES-Unknown";
        };
    }

    /**
     * Encrypts data using AES-GCM with the specified key size.
     *
     * @param plainText The plaintext data to encrypt.
     * @param key The encryption key (16, 24, or 32 bytes for AES-128/192/256).
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
        validateKeySize(key.size());
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
            throw new CryptoException(getAesVariant(key.size()) + "-GCM encryption failed during finalization.", e);
        }

        return Bytes.wrap(output, 0, length);
    }

    /**
     * Decrypts data using AES-GCM with the specified key size.
     *
     * @param cipherText The encrypted data, which includes the ciphertext followed by the
     *     16-byte authentication tag.
     * @param key The decryption key (16, 24, or 32 bytes for AES-128/192/256).
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
        validateKeySize(key.size());
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
            throw new CryptoException(getAesVariant(key.size()) + "-GCM decryption failed. " +
                "The data may be tampered or the key/nonce is incorrect.", e);
        }
    }
}
