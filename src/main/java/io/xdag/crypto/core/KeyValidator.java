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

package io.xdag.crypto.core;

import io.xdag.crypto.exception.CryptoException;
import java.math.BigInteger;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/**
 * Utility class for validating cryptographic keys and related data.
 * 
 * <p>This class centralizes common validation logic used throughout the cryptographic
 * library to ensure consistency and reduce code duplication. All validation methods
 * throw {@link CryptoException} with descriptive error messages.
 * 
 * <p>The validation rules implemented here follow the SECP256K1 elliptic curve
 * specifications and standard cryptographic practices.

 */
public final class KeyValidator {
    
    private KeyValidator() {
        // Utility class
    }
    
    /**
     * Validates that a private key BigInteger is within the valid range for SECP256K1.
     * 
     * <p>A valid private key must be in the range [1, n-1] where n is the order
     * of the SECP256K1 curve. This means:
     * <ul>
     * <li>Must not be zero</li>
     * <li>Must be less than the curve order (n)</li>
     * </ul>
     * 
     * @param privateKey the private key value to validate
     * @throws CryptoException if the private key is null, zero, or >= curve order
     */
    public static void validatePrivateKeyRange(BigInteger privateKey) throws CryptoException {
        if (privateKey == null) {
            throw new CryptoException("Private key value cannot be null");
        }
        
        if (privateKey.signum() <= 0) {
            throw new CryptoException("Private key must be positive");
        }
        
        if (privateKey.compareTo(CryptoProvider.getCurve().getN()) >= 0) {
            throw new CryptoException("Private key must be less than curve order");
        }
    }
    
    /**
     * Validates that a derived key value is within the valid range for SECP256K1.
     * 
     * <p>This is used during key derivation operations where intermediate values
     * must be checked before being used as private keys.
     * 
     * @param derivedValue the derived key value to validate
     * @return true if the value is valid, false if it should be retried
     */
    public static boolean isValidDerivedKeyRange(BigInteger derivedValue) {
        if (derivedValue == null) {
            return false;
        }
        
        return !derivedValue.equals(BigInteger.ZERO) && 
               derivedValue.compareTo(CryptoProvider.getCurve().getN()) < 0;
    }
    
    /**
     * Validates that a byte array is exactly 32 bytes (256 bits).
     * 
     * <p>This is the standard length for private keys, hash values, and other
     * cryptographic data in the SECP256K1 system.
     * 
     * @param bytes the byte array to validate
     * @param fieldName descriptive name for error messages (e.g., "private key", "hash")
     * @throws CryptoException if bytes is null or not exactly 32 bytes
     */
    public static void validate32Bytes(byte[] bytes, String fieldName) throws CryptoException {
        if (bytes == null) {
            throw new CryptoException(fieldName + " cannot be null");
        }
        
        if (bytes.length != 32) {
            throw new CryptoException(fieldName + " must be exactly 32 bytes, got " + bytes.length);
        }
    }
    
    /**
     * Validates that a Bytes32 object is not null.
     * 
     * @param bytes32 the Bytes32 to validate
     * @param fieldName descriptive name for error messages
     * @throws CryptoException if bytes32 is null
     */
    public static void validateBytes32NotNull(Bytes32 bytes32, String fieldName) throws CryptoException {
        if (bytes32 == null) {
            throw new CryptoException(fieldName + " cannot be null");
        }
    }

    /**
     * Validates that a hex string represents exactly 32 bytes (64 hex characters).
     * 
     * @param hex the hex string to validate (with or without 0x prefix)
     * @param fieldName descriptive name for error messages
     * @throws CryptoException if hex is invalid or wrong length
     */
    public static void validateHex32Bytes(String hex, String fieldName) throws CryptoException {
        if (hex == null || hex.isEmpty()) {
            throw new CryptoException(fieldName + " hex cannot be null or empty");
        }
        
        // Remove 0x prefix if present
        String cleanHex = hex.startsWith("0x") ? hex.substring(2) : hex;
        
        if (cleanHex.length() != 64) {
            throw new CryptoException(fieldName + " hex must be 64 characters (32 bytes), got " + 
                                    cleanHex.length());
        }
        
        // Validate hex characters
        if (!cleanHex.matches("[0-9a-fA-F]+")) {
            throw new CryptoException(fieldName + " hex contains invalid characters");
        }
    }
    
    /**
     * Validates that a public key byte array has the correct length.
     * 
     * <p>Public keys can be either:
     * <ul>
     * <li>33 bytes for compressed format</li>
     * <li>65 bytes for uncompressed format</li>
     * </ul>
     * 
     * @param bytes the public key bytes to validate
     * @throws CryptoException if bytes is null or has invalid length
     */
    public static void validatePublicKeyBytes(byte[] bytes) throws CryptoException {
        if (bytes == null) {
            throw new CryptoException("Public key bytes cannot be null");
        }
        
        if (bytes.length != 33 && bytes.length != 65) {
            throw new CryptoException("Public key must be 33 bytes (compressed) or 65 bytes (uncompressed), got " + 
                                    bytes.length);
        }
    }
    
    /**
     * Validates that a public key Bytes object has the correct size.
     * 
     * @param bytes the public key Bytes to validate
     * @throws CryptoException if bytes is null or has invalid size
     */
    public static void validatePublicKeyBytes(Bytes bytes) throws CryptoException {
        if (bytes == null) {
            throw new CryptoException("Public key bytes cannot be null");
        }
        
        if (bytes.size() != 33 && bytes.size() != 65) {
            throw new CryptoException("Public key must be 33 bytes (compressed) or 65 bytes (uncompressed), got " + 
                                    bytes.size());
        }
    }
} 