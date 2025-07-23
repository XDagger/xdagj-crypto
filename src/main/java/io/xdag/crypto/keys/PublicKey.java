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
import lombok.Getter;
import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Represents an elliptic curve public key for XDAG cryptographic operations.
 * 
 * <p>This class follows the traditional cryptocurrency library pattern with dedicated
 * public key management, formatting, and address generation capabilities.
 * 
 * <p>Key features:
 * <ul>
 *   <li>Support for both compressed and uncompressed formats</li>
 *   <li>Direct address generation</li>
 *   <li>Format validation and conversion</li>
 *   <li>Integration with signature verification</li>
 * </ul>
 * 
 * <p>Usage examples:
 * <pre>{@code
 * // Create from compressed bytes
 * PublicKey publicKey = PublicKey.fromBytes(compressedBytes);
 * 
 * // Generate address
 * String address = publicKey.toAddress();
 * 
 * // Get different formats
 * Bytes compressed = publicKey.toCompressedBytes();
 * Bytes uncompressed = publicKey.toUncompressedBytes();
 * }</pre>
 * 
 * @see PrivateKey
 * @see ECKeyPair
 * @see AddressUtils
 */
@Getter
public final class PublicKey {

  private final ECPoint point;
    
    /**
     * Creates a public key from an ECPoint.
     * 
     * @param point the EC point representing the public key
     * @throws CryptoException if the point is invalid
     */
    private PublicKey(ECPoint point) throws CryptoException {
        if (point == null) {
            throw new CryptoException("Public key point cannot be null");
        }
        if (!point.isValid()) {
            throw new CryptoException("Invalid public key point");
        }
        this.point = point.normalize(); // Ensure point is in normalized form
    }
    
    /**
     * Creates a public key from an ECPoint.
     * 
     * @param point the EC point
     * @return a new PublicKey instance
     */
    public static PublicKey fromPoint(ECPoint point) {
        try {
            return new PublicKey(point);
        } catch (CryptoException e) {
            throw new IllegalArgumentException("Invalid EC point", e);
        }
    }
    
    /**
     * Creates a public key from compressed or uncompressed bytes.
     * 
     * @param bytes the public key bytes (33 bytes for compressed, 65 bytes for uncompressed)
     * @return a new PublicKey instance
     * @throws CryptoException if the bytes are invalid
     */
    public static PublicKey fromBytes(byte[] bytes) throws CryptoException {
        KeyValidator.validatePublicKeyBytes(bytes);
        
        try {
            ECPoint point = CryptoProvider.getCurve().getCurve().decodePoint(bytes);
            return fromPoint(point);
        } catch (Exception e) {
            throw new CryptoException("Invalid public key bytes", e);
        }
    }
    
    /**
     * Creates a public key from Bytes.
     * 
     * @param bytes the public key as Bytes
     * @return a new PublicKey instance
     * @throws CryptoException if the bytes are invalid
     */
    public static PublicKey fromBytes(Bytes bytes) throws CryptoException {
        KeyValidator.validatePublicKeyBytes(bytes);
        return fromBytes(bytes.toArrayUnsafe());
    }
    
    /**
     * Creates a public key from a hex string.
     * 
     * @param hex the public key as hex string (with or without 0x prefix)
     * @return a new PublicKey instance
     * @throws CryptoException if the hex string is invalid
     */
    public static PublicKey fromHex(String hex) throws CryptoException {
        if (hex == null || hex.isEmpty()) {
            throw new CryptoException("Hex string cannot be null or empty");
        }
        
        // Remove 0x prefix if present
        String cleanHex = hex.startsWith("0x") || hex.startsWith("0X") ? hex.substring(2) : hex;
        
        if (cleanHex.length() != 66 && cleanHex.length() != 130) {
            throw new CryptoException("Public key hex must be 66 characters (compressed) or 130 characters (uncompressed)");
        }
        
        try {
            Bytes bytes = Bytes.fromHexString("0x" + cleanHex);
            return fromBytes(bytes);
        } catch (Exception e) {
            throw new CryptoException("Invalid hex string for public key", e);
        }
    }
    
    /**
     * Returns the public key in compressed format (33 bytes).
     * 
     * @return the compressed public key bytes
     */
    public Bytes toCompressedBytes() {
        byte[] encoded = point.getEncoded(true);
        return Bytes.wrap(encoded);
    }
    
    /**
     * Returns the public key in uncompressed format (65 bytes).
     * 
     * @return the uncompressed public key bytes
     */
    public Bytes toUncompressedBytes() {
        byte[] encoded = point.getEncoded(false);
        return Bytes.wrap(encoded);
    }
    
    /**
     * Returns the public key in compressed format by default.
     * 
     * @return the public key bytes (compressed)
     */
    public Bytes toBytes() {
        return toCompressedBytes();
    }
    
    /**
     * Returns the public key as hex string with 0x prefix (compressed format).
     * 
     * @return the public key as hex string
     */
    public String toHex() {
        return toCompressedBytes().toHexString();
    }
    
    /**
     * Returns the public key as hex string without 0x prefix (compressed format).
     * 
     * @return the public key as unprefixed hex string
     */
    public String toUnprefixedHex() {
        return toCompressedBytes().toUnprefixedHexString();
    }
    
    /**
     * Returns the public key as hex string with 0x prefix (uncompressed format).
     * 
     * @return the uncompressed public key as hex string
     */
    public String toUncompressedHex() {
        return toUncompressedBytes().toHexString();
    }
    
    /**
     * Generates an XDAG address from this public key using compressed format.
     * 
     * @return the XDAG address as bytes
     */
    public Bytes toAddress() {
        return AddressUtils.toBytesAddress(this);
    }
    
    /**
     * Generates an XDAG address from this public key.
     * 
     * @param compressed whether to use compressed public key format
     * @return the XDAG address as bytes
     */
    public Bytes toAddress(boolean compressed) {
        return AddressUtils.toBytesAddress(this, compressed);
    }
    
    /**
     * Generates a Base58Check encoded XDAG address from this public key.
     * 
     * @return the Base58Check encoded address
     */
    public String toBase58Address() {
        return AddressUtils.toBase58Address(this);
    }
    
    /**
     * Generates a Base58Check encoded XDAG address from this public key.
     * 
     * @param compressed whether to use compressed public key format
     * @return the Base58Check encoded address
     */
    public String toBase58Address(boolean compressed) {
        return AddressUtils.toBase58Address(this, compressed);
    }

    /**
     * Returns the x coordinate of the public key point as BigInteger.
     * 
     * @return the x coordinate
     */
    public BigInteger getXCoordinate() {
        return point.getAffineXCoord().toBigInteger();
    }
    
    /**
     * Returns the y coordinate of the public key point as BigInteger.
     * 
     * @return the y coordinate
     */
    public BigInteger getYCoordinate() {
        return point.getAffineYCoord().toBigInteger();
    }
    
    /**
     * Returns the public key as BigInteger representing 64-byte uncompressed coordinates.
     * 
     * <p>This method provides compatibility with Hyperledger Besu's SECPPublicKey format.
     * The returned BigInteger represents the concatenation of 32-byte x coordinate 
     * and 32-byte y coordinate (total 64 bytes).
     * 
     * @return the public key as BigInteger (64-byte uncompressed format)
     */
    public BigInteger toBigInteger() {
        byte[] uncompressed = toUncompressedBytes().toArrayUnsafe();
        // Remove the 0x04 prefix, keep only the 64-byte coordinates
        byte[] coordinates = new byte[64];
        System.arraycopy(uncompressed, 1, coordinates, 0, 64);
        return new BigInteger(1, coordinates);
    }
    
    /**
     * Creates a public key from BigInteger representing 64-byte uncompressed coordinates.
     * 
     * <p>This method provides compatibility with Hyperledger Besu's SECPPublicKey format.
     * The BigInteger should represent the concatenation of 32-byte x coordinate 
     * and 32-byte y coordinate (total 64 bytes).
     * 
     * @param value the BigInteger representing 64-byte uncompressed coordinates
     * @return a new PublicKey instance
     * @throws CryptoException if the BigInteger is invalid
     */
    public static PublicKey fromBigInteger(BigInteger value) throws CryptoException {
        if (value == null) {
            throw new CryptoException("BigInteger value cannot be null");
        }
        
        // Convert BigInteger to 64-byte array
        byte[] bytes = value.toByteArray();
        byte[] coordinates = new byte[64];
        
        if (bytes.length == 64) {
            coordinates = bytes;
        } else if (bytes.length == 65 && bytes[0] == 0) {
            // Remove leading zero byte
            System.arraycopy(bytes, 1, coordinates, 0, 64);
        } else if (bytes.length < 64) {
            // Pad with leading zeros
            System.arraycopy(bytes, 0, coordinates, 64 - bytes.length, bytes.length);
        } else {
            throw new CryptoException("BigInteger too large for public key coordinates");
        }
        
        // Create uncompressed public key bytes (0x04 + 64 bytes)
        byte[] uncompressedBytes = new byte[65];
        uncompressedBytes[0] = 0x04; // Uncompressed format prefix
        System.arraycopy(coordinates, 0, uncompressedBytes, 1, 64);
        
        return fromBytes(uncompressedBytes);
    }
    
    /**
     * Creates a public key from x and y coordinates.
     * 
     * @param x the x coordinate
     * @param y the y coordinate
     * @return a new PublicKey instance
     * @throws CryptoException if the coordinates don't form a valid point on the curve
     */
    public static PublicKey fromCoordinates(BigInteger x, BigInteger y) throws CryptoException {
        if (x == null || y == null) {
            throw new CryptoException("Coordinates cannot be null");
        }
        
        try {
            ECPoint point = CryptoProvider.getCurve().getCurve().createPoint(x, y);
            return fromPoint(point);
        } catch (Exception e) {
            throw new CryptoException("Invalid coordinates for public key", e);
        }
    }

    /**
     * Checks if this public key is in compressed format by default.
     * 
     * @return true if the public key is typically used in compressed format
     */
    public boolean isCompressed() {
        return true; // We default to compressed format
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        PublicKey publicKey = (PublicKey) obj;
        return Objects.equals(point, publicKey.point);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(point);
    }
    
    @Override
    public String toString() {
        return "PublicKey{" + toUnprefixedHex() + "}";
    }
} 