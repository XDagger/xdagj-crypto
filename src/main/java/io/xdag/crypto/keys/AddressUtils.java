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
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * Address generation and validation utility for XDAG.
 *
 * <p>This class provides methods for generating XDAG addresses from public keys
 * using the hash160 algorithm (SHA-256 followed by RIPEMD-160) and for
 * converting between byte representations and Base58Check encoding.
 */
public final class AddressUtils {

    /** Standard XDAG address length in bytes (20 bytes for hash160). */
    public static final int ADDRESS_LENGTH = 20;

    private AddressUtils() {
        // Utility class - prevent instantiation
    }

    /**
     * Generate XDAG address bytes from a key pair.
     *
     * @param keyPair The key pair to generate the address from.
     * @return The 20-byte address as Bytes.
     */
    public static Bytes toBytesAddress(AsymmetricCipherKeyPair keyPair) {
        return toBytesAddress(keyPair.getPublic());
    }

    /**
     * Generate XDAG address bytes from a public key.
     *
     * @param publicKey The public key to generate the address from.
     * @return The 20-byte address as Bytes.
     */
    public static Bytes toBytesAddress(AsymmetricKeyParameter publicKey) {
        return toBytesAddress(publicKey, true);
    }

    /**
     * Generate XDAG address bytes from a public key, specifying the public key format.
     *
     * @param publicKey The public key to generate the address from.
     * @param compressed Whether to use the compressed public key format.
     * @return The 20-byte address as Bytes.
     */
    public static Bytes toBytesAddress(AsymmetricKeyParameter publicKey, boolean compressed) {
        ECPublicKeyParameters ecPublicKey = (ECPublicKeyParameters) publicKey;
        byte[] publicKeyBytes = ecPublicKey.getQ().getEncoded(compressed);
        return HashUtils.sha256hash160(Bytes.wrap(publicKeyBytes));
    }

    /**
     * Generate a Base58Check encoded address from a key pair.
     *
     * @param keyPair The key pair.
     * @return The Base58Check encoded address string.
     */
    public static String toBase58Address(AsymmetricCipherKeyPair keyPair) {
        return toBase58Address(keyPair, true);
    }

    /**
     * Generate a Base58Check encoded address from a key pair.
     *
     * @param keyPair The key pair.
     * @param compressed Whether to use the compressed public key format.
     * @return The Base58Check encoded address string.
     */
    public static String toBase58Address(AsymmetricCipherKeyPair keyPair, boolean compressed) {
        Bytes addressBytes = toBytesAddress(keyPair.getPublic(), compressed);
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