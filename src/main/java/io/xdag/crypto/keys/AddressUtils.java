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

import io.xdag.crypto.encoding.Base58;
import io.xdag.crypto.exception.AddressFormatException;
import io.xdag.crypto.hash.HashUtils;
import org.apache.tuweni.bytes.Bytes;

/**
 * Address generation and validation utility for XDAG.
 *
 * <p>This class provides methods for generating XDAG addresses using the hash160 
 * algorithm (SHA-256 followed by RIPEMD-160) and for converting between byte 
 * representations and Base58Check encoding.
 * 
 * <p>The class prioritizes modern type-safe APIs by providing direct support for
 * {@link PrivateKey}, {@link PublicKey}, and {@link ECKeyPair} instances. While methods
 * that accept raw {@code byte[]} or {@link org.apache.tuweni.bytes.Bytes} are available
 * for compatibility, the type-safe alternatives are recommended for new code.
 *
 * <p><strong>Recommended Usage:</strong></p>
 * <pre>{@code
 * // From PrivateKey
 * PrivateKey privateKey = PrivateKey.generateRandom();
 * String address = AddressUtils.toBase58Address(privateKey);
 * 
 * // From PublicKey
 * PublicKey publicKey = privateKey.getPublicKey();
 * Bytes addressBytes = AddressUtils.toBytesAddress(publicKey);
 * 
 * // From ECKeyPair
 * ECKeyPair keyPair = ECKeyPair.generate();
 * String address = AddressUtils.toBase58Address(keyPair);
 * }</pre>
 */
public final class AddressUtils {

    /** Standard XDAG address length in bytes (20 bytes for hash160). */
    public static final int ADDRESS_LENGTH = 20;

    private AddressUtils() {
        // Utility class - prevent instantiation
    }

    /**
     * Generate XDAG address bytes from a PrivateKey using compressed public key.
     *
     * @param privateKey The PrivateKey to generate the address from.
     * @return The 20-byte address as Bytes.
     */
    public static Bytes toBytesAddress(PrivateKey privateKey) {
        return toBytesAddress(privateKey.getPublicKey());
    }

    /**
     * Generate XDAG address bytes from a PrivateKey, specifying the public key format.
     *
     * @param privateKey The PrivateKey to generate the address from.
     * @param compressed Whether to use the compressed public key format.
     * @return The 20-byte address as Bytes.
     */
    public static Bytes toBytesAddress(PrivateKey privateKey, boolean compressed) {
        return toBytesAddress(privateKey.getPublicKey(), compressed);
    }

    /**
     * Generate XDAG address bytes from a PublicKey using compressed format.
     *
     * @param publicKey The PublicKey to generate the address from.
     * @return The 20-byte address as Bytes.
     */
    public static Bytes toBytesAddress(PublicKey publicKey) {
        return toBytesAddress(publicKey, true);
    }

    /**
     * Generate XDAG address bytes from a PublicKey, specifying the format.
     *
     * @param publicKey The PublicKey to generate the address from.
     * @param compressed Whether to use the compressed public key format.
     * @return The 20-byte address as Bytes.
     */
    public static Bytes toBytesAddress(PublicKey publicKey, boolean compressed) {
        Bytes publicKeyBytes = compressed ? publicKey.toCompressedBytes() : publicKey.toUncompressedBytes();
        return HashUtils.sha256hash160(publicKeyBytes);
    }

    /**
     * Generate XDAG address bytes from an ECKeyPair using compressed public key.
     *
     * @param keyPair The ECKeyPair to generate the address from.
     * @return The 20-byte address as Bytes.
     */
    public static Bytes toBytesAddress(ECKeyPair keyPair) {
        return toBytesAddress(keyPair, true);
    }

    /**
     * Generate XDAG address bytes from an ECKeyPair, specifying the public key format.
     *
     * @param keyPair The ECKeyPair to generate the address from.
     * @param compressed Whether to use the compressed public key format.
     * @return The 20-byte address as Bytes.
     */
    public static Bytes toBytesAddress(ECKeyPair keyPair, boolean compressed) {
        Bytes publicKeyBytes = compressed ? keyPair.getPublicKey().toCompressedBytes() : keyPair.getPublicKey().toUncompressedBytes();
        return HashUtils.sha256hash160(publicKeyBytes);
    }



    /**
     * Generate a Base58Check encoded address from a PrivateKey using compressed public key.
     *
     * @param privateKey The PrivateKey.
     * @return The Base58Check encoded address string.
     */
    public static String toBase58Address(PrivateKey privateKey) {
        return toBase58Address(privateKey.getPublicKey());
    }

    /**
     * Generate a Base58Check encoded address from a PrivateKey, specifying the public key format.
     *
     * @param privateKey The PrivateKey.
     * @param compressed Whether to use the compressed public key format.
     * @return The Base58Check encoded address string.
     */
    public static String toBase58Address(PrivateKey privateKey, boolean compressed) {
        return toBase58Address(privateKey.getPublicKey(), compressed);
    }

    /**
     * Generate a Base58Check encoded address from a PublicKey using compressed format.
     *
     * @param publicKey The PublicKey.
     * @return The Base58Check encoded address string.
     */
    public static String toBase58Address(PublicKey publicKey) {
        return toBase58Address(publicKey, true);
    }

    /**
     * Generate a Base58Check encoded address from a PublicKey, specifying the format.
     *
     * @param publicKey The PublicKey.
     * @param compressed Whether to use the compressed public key format.
     * @return The Base58Check encoded address string.
     */
    public static String toBase58Address(PublicKey publicKey, boolean compressed) {
        Bytes addressBytes = toBytesAddress(publicKey, compressed);
        return Base58.encodeCheck(addressBytes);
    }

    /**
     * Generate a Base58Check encoded address from an ECKeyPair using compressed public key.
     *
     * @param keyPair The ECKeyPair.
     * @return The Base58Check encoded address string.
     */
    public static String toBase58Address(ECKeyPair keyPair) {
        return toBase58Address(keyPair, true);
    }

    /**
     * Generate a Base58Check encoded address from an ECKeyPair.
     *
     * @param keyPair The ECKeyPair.
     * @param compressed Whether to use the compressed public key format.
     * @return The Base58Check encoded address string.
     */
    public static String toBase58Address(ECKeyPair keyPair, boolean compressed) {
        Bytes addressBytes = toBytesAddress(keyPair, compressed);
        return Base58.encodeCheck(addressBytes);
    }



    /**
     * Convert a Base58Check encoded address back to its byte representation.
     *
     * @param base58Address The Base58Check encoded address.
     * @return The 20-byte address as Bytes.
     * @throws AddressFormatException if the address is invalid.
     */
    public static Bytes fromBase58Address(String base58Address) throws AddressFormatException {
        Bytes decoded = Base58.decodeCheck(base58Address);
        if (decoded.size() != ADDRESS_LENGTH) {
            throw new AddressFormatException("Invalid address length");
        }
        return decoded;
    }

    /**
     * Validate that an address has the correct length.
     *
     * @param address The address to validate.
     * @return true if the address is valid, false otherwise.
     */
    public static boolean isValidAddress(Bytes address) {
        return address != null && address.size() == ADDRESS_LENGTH;
    }

    /**
     * Checks if the given string is a valid Base58Check encoded address.
     * <p>
     * This method is lenient and simply checks if decoding is successful
     * without throwing an exception.
     *
     * @param address The Base58Check encoded address string.
     * @return true if the address is valid, false otherwise.
     */
    public static boolean isLegacyValidAddress(String address) {
        if (address == null || address.isEmpty()) {
            return false;
        }
        try {
            fromBase58Address(address);
            return true;
        } catch (AddressFormatException e) {
            return false;
        }
    }
} 