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

import io.xdag.crypto.exception.CryptoException;
import java.util.Objects;
import lombok.Getter;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/**
 * Represents an elliptic curve key pair combining a private and public key.
 * 
 * <p>This class follows the modern cryptocurrency library pattern by composing
 * dedicated {@link PrivateKey} and {@link PublicKey} instances, providing a clean
 * and intuitive API for cryptographic operations.
 * 
 * <p>Key features:
 * <ul>
 *   <li>Clean composition of PrivateKey and PublicKey</li>
 *   <li>Convenient access to both keys</li>
 *   <li>Support for public-key-only instances</li>
 *   <li>Seamless address generation</li>
 * </ul>
 * 
 * <p>Usage examples:
 * <pre>{@code
 * // Create from private key
 * ECKeyPair keyPair = ECKeyPair.fromPrivateKey(privateKey);
 * 
 * // Access keys
 * PrivateKey privKey = keyPair.getPrivateKey();
 * PublicKey pubKey = keyPair.getPublicKey();
 * 
 * // Generate address directly
 * String address = keyPair.toBase58Address();
 * }</pre>
 * 
 * <p>This class is thread-safe and immutable.
 * 
 * @see PrivateKey
 * @see PublicKey
 */
public final class ECKeyPair {
    
    private final PrivateKey privateKey;
  /**
   * -- GETTER --
   *  Returns the public key.
   *
   * @return the public key
   */
  @Getter
  private final PublicKey publicKey;
    
    /**
     * Creates an ECKeyPair from a private key.
     * 
     * @param privateKey the private key
     */
    private ECKeyPair(PrivateKey privateKey) {
        this.privateKey = Objects.requireNonNull(privateKey, "privateKey cannot be null");
        this.publicKey = privateKey.getPublicKey();
    }
    
    /**
     * Creates a public-key-only ECKeyPair.
     * 
     * @param publicKey the public key
     */
    private ECKeyPair(PublicKey publicKey) {
        this.privateKey = null;
        this.publicKey = Objects.requireNonNull(publicKey, "publicKey cannot be null");
    }
    
    /**
     * Creates an ECKeyPair from a private key.
     * 
     * @param privateKey the private key
     * @return a new ECKeyPair instance
     */
    public static ECKeyPair fromPrivateKey(PrivateKey privateKey) {
        return new ECKeyPair(privateKey);
    }
    
    /**
     * Creates a public-key-only ECKeyPair.
     * 
     * @param publicKey the public key
     * @return a new ECKeyPair instance
     */
    public static ECKeyPair fromPublicKey(PublicKey publicKey) {
        return new ECKeyPair(publicKey);
    }

    /**
     * Generates a new random ECKeyPair.
     * 
     * <p>This is a convenience method that generates a cryptographically secure
     * random private key and derives the corresponding public key.
     * 
     * @return a new randomly generated ECKeyPair
     * @throws CryptoException if random key generation fails
     */
    public static ECKeyPair generate() throws CryptoException {
        return fromPrivateKey(PrivateKey.generateRandom());
    }
    
    /**
     * Creates an ECKeyPair from a private key hex string.
     * 
     * @param privateKeyHex the private key as hex string (64 characters)
     * @return a new ECKeyPair instance
     * @throws CryptoException if the hex is invalid
     */
    public static ECKeyPair fromHex(String privateKeyHex) throws CryptoException {
        return new ECKeyPair(PrivateKey.fromHex(privateKeyHex));
    }
    
    /**
     * Creates an ECKeyPair from private key bytes.
     * 
     * @param privateKeyBytes the private key bytes (32 bytes)
     * @return a new ECKeyPair instance
     * @throws CryptoException if the bytes are invalid
     */
    public static ECKeyPair fromBytes(byte[] privateKeyBytes) throws CryptoException {
        return new ECKeyPair(PrivateKey.fromBytes(privateKeyBytes));
    }
    
    /**
     * Creates an ECKeyPair from private key Bytes32.
     * 
     * @param privateKeyBytes the private key as Bytes32
     * @return a new ECKeyPair instance
     * @throws CryptoException if the bytes are invalid
     */
    public static ECKeyPair fromBytes(Bytes32 privateKeyBytes) throws CryptoException {
        return new ECKeyPair(PrivateKey.fromBytes(privateKeyBytes));
    }
    
    /**
     * Returns the private key.
     * 
     * @return the private key
     * @throws IllegalStateException if this is a public-key-only instance
     */
    public PrivateKey getPrivateKey() {
        if (privateKey == null) {
            throw new IllegalStateException("This is a public-key-only instance");
        }
        return privateKey;
    }

  /**
     * Checks if this key pair has access to the private key.
     * 
     * @return true if the private key is available, false if this is public-key-only
     */
    public boolean hasPrivateKey() {
        return privateKey != null;
    }
    
    /**
     * Checks if this is a public-key-only instance.
     * 
     * @return true if only the public key is available
     */
    public boolean isPublicKeyOnly() {
        return privateKey == null;
    }
    
    /**
     * Generates an XDAG address from this key pair's public key.
     * 
     * @return the XDAG address as bytes
     */
    public Bytes toAddress() {
        return publicKey.toAddress();
    }
    
    /**
     * Generates an XDAG address from this key pair's public key.
     * 
     * @param compressed whether to use compressed public key format
     * @return the XDAG address as bytes
     */
    public Bytes toAddress(boolean compressed) {
        return publicKey.toAddress(compressed);
    }
    
    /**
     * Generates a Base58Check encoded XDAG address from this key pair's public key.
     * 
     * @return the Base58Check encoded address
     */
    public String toBase58Address() {
        return publicKey.toBase58Address();
    }
    
    /**
     * Generates a Base58Check encoded XDAG address from this key pair's public key.
     * 
     * @param compressed whether to use compressed public key format
     * @return the Base58Check encoded address
     */
    public String toBase58Address(boolean compressed) {
        return publicKey.toBase58Address(compressed);
    }
    

    

    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        ECKeyPair other = (ECKeyPair) obj;
        return Objects.equals(publicKey, other.publicKey) &&
               Objects.equals(privateKey, other.privateKey);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(publicKey, privateKey);
    }
    
    @Override
    public String toString() {
        return "ECKeyPair{" +
               "publicKey=" + publicKey.toUnprefixedHex() +
               ", hasPrivateKey=" + hasPrivateKey() +
               "}";
    }
} 