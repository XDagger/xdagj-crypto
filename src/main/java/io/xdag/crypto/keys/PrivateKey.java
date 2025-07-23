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
package io.xdag.crypto.keys;

import io.xdag.crypto.core.CryptoProvider;
import io.xdag.crypto.core.KeyValidator;
import io.xdag.crypto.exception.CryptoException;
import java.math.BigInteger;
import java.util.Objects;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Represents an elliptic curve private key for XDAG cryptographic operations.
 * 
 * <p>This class follows the traditional cryptocurrency library pattern with dedicated
 * private key management, formatting, and key derivation capabilities.
 * 
 * <p>Key features:
 * <ul>
 *   <li>Multiple format support (hex, bytes, BigInteger)</li>
 *   <li>Public key derivation</li>
 *   <li>Secure private key validation</li>
 *   <li>Immutable design for thread safety</li>
 * </ul>
 * 
 * <p>Usage examples:
 * <pre>{@code
 * // Create from hex string
 * PrivateKey privateKey = PrivateKey.fromHex("0x123abc...");
 * 
 * // Generate public key
 * PublicKey publicKey = privateKey.getPublicKey();
 * 
 * // Get different formats
 * String hex = privateKey.toHex();
 * Bytes32 bytes = privateKey.toBytes();
 * }</pre>
 * 
 * @see PublicKey
 * @see ECKeyPair
 */
public final class PrivateKey {
    
    private final BigInteger value;
    
    /**
     * Creates a private key from a BigInteger value.
     * 
     * @param value the private key value
     * @throws CryptoException if the value is invalid for SECP256K1
     */
    private PrivateKey(BigInteger value) throws CryptoException {
        KeyValidator.validatePrivateKeyRange(value);
        this.value = value;
    }
    
    /**
     * Creates a private key from a BigInteger.
     * 
     * @param value the private key as BigInteger
     * @return a new PrivateKey instance
     * @throws CryptoException if the value is invalid
     */
    public static PrivateKey fromBigInteger(BigInteger value) throws CryptoException {
        return new PrivateKey(value);
    }
    
    /**
     * Creates a private key from a 32-byte array.
     * 
     * @param bytes the private key bytes (32 bytes)
     * @return a new PrivateKey instance
     * @throws CryptoException if the bytes are invalid
     */
    public static PrivateKey fromBytes(byte[] bytes) throws CryptoException {
        KeyValidator.validate32Bytes(bytes, "Private key");
        return fromBigInteger(new BigInteger(1, bytes));
    }
    
    /**
     * Creates a private key from Bytes32.
     * 
     * @param bytes the private key as Bytes32
     * @return a new PrivateKey instance
     * @throws CryptoException if the bytes are invalid
     */
    public static PrivateKey fromBytes(Bytes32 bytes) throws CryptoException {
        KeyValidator.validateBytes32NotNull(bytes, "Private key bytes");
        return fromBytes(bytes.toArrayUnsafe());
    }
    
    /**
     * Creates a private key from a hex string.
     * 
     * @param hex the private key as hex string (with or without 0x prefix)
     * @return a new PrivateKey instance
     * @throws CryptoException if the hex string is invalid
     */
    public static PrivateKey fromHex(String hex) throws CryptoException {
        KeyValidator.validateHex32Bytes(hex, "Private key");
        
        try {
            // Remove 0x prefix if present for Bytes32.fromHexString
            String cleanHex = hex.startsWith("0x") || hex.startsWith("0X") ? hex.substring(2) : hex;
            Bytes32 bytes = Bytes32.fromHexString("0x" + cleanHex);
            return fromBytes(bytes);
        } catch (Exception e) {
            throw new CryptoException("Invalid hex string for private key", e);
        }
    }

    /**
     * Generates a cryptographically secure random private key.
     * 
     * <p>This method uses {@link CryptoProvider} to generate a random private key
     * that is guaranteed to be in the valid range for the secp256k1 curve (1 to n-1).
     * 
     * @return a new randomly generated PrivateKey
     * @throws CryptoException if random key generation fails
     */
    public static PrivateKey generateRandom() throws CryptoException {
        BigInteger privateKey;
        
        // Generate random private key in valid range [1, n-1]
        do {
            byte[] randomBytes = new byte[32];
            CryptoProvider.getSecureRandom().nextBytes(randomBytes);
            privateKey = new BigInteger(1, randomBytes);
        } while (!KeyValidator.isValidDerivedKeyRange(privateKey));
        
        return fromBigInteger(privateKey);
    }
    
    /**
     * Derives the public key from this private key.
     * 
     * @return the corresponding PublicKey
     */
    public PublicKey getPublicKey() {
        ECPoint publicKeyPoint = CryptoProvider.getCurve().getG().multiply(value);
        return PublicKey.fromPoint(publicKeyPoint);
    }
    
    /**
     * Returns the private key value as BigInteger.
     * 
     * @return the private key value
     */
    public BigInteger toBigInteger() {
        return value;
    }
    
    /**
     * Returns the private key as 32-byte array.
     * 
     * @return the private key bytes
     */
    public byte[] toByteArray() {
        return toBytes().toArrayUnsafe();
    }
    
    /**
     * Returns the private key as Bytes32.
     * 
     * @return the private key as Bytes32
     */
    public Bytes32 toBytes() {
        byte[] bytes = value.toByteArray();
        
        if (bytes.length == 32) {
            return Bytes32.wrap(bytes);
        } else if (bytes.length == 33 && bytes[0] == 0) {
            // Remove leading zero byte
            byte[] trimmed = new byte[32];
            System.arraycopy(bytes, 1, trimmed, 0, 32);
            return Bytes32.wrap(trimmed);
        } else if (bytes.length < 32) {
            // Pad with leading zeros
            byte[] padded = new byte[32];
            System.arraycopy(bytes, 0, padded, 32 - bytes.length, bytes.length);
            return Bytes32.wrap(padded);
        } else {
            throw new IllegalStateException("Private key is too large for 32 bytes");
        }
    }
    
    /**
     * Returns the private key as hex string with 0x prefix.
     * 
     * @return the private key as hex string
     */
    public String toHex() {
        return toBytes().toHexString();
    }
    
    /**
     * Returns the private key as hex string without 0x prefix.
     * 
     * @return the private key as unprefixed hex string
     */
    public String toUnprefixedHex() {
        return toBytes().toUnprefixedHexString();
    }
    
    /**
     * Converts this private key to ECKeyPair for compatibility.
     * 
     * @return an ECKeyPair containing this private key and its public key
     */
    public ECKeyPair toECKeyPair() {
        return ECKeyPair.fromPrivateKey(this);
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        PrivateKey that = (PrivateKey) obj;
        return Objects.equals(value, that.value);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
    
    @Override
    public String toString() {
        return "PrivateKey{length=32 bytes}"; // Don't expose the actual value
    }
} 