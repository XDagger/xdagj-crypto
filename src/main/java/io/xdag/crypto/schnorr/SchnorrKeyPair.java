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
package io.xdag.crypto.schnorr;

import io.xdag.crypto.core.CryptoProvider;
import io.xdag.crypto.exception.CryptoException;
import io.xdag.crypto.keys.ECKeyPair;
import io.xdag.crypto.keys.PrivateKey;
import io.xdag.crypto.keys.PublicKey;
import java.math.BigInteger;
import java.util.Objects;

/**
 * Represents a BIP340-compatible Schnorr key pair.
 *
 * <p>The stored private key is adjusted, if necessary, to ensure the associated public key has an
 * even y-coordinate as required by the Schnorr specification.</p>
 */
public final class SchnorrKeyPair {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private SchnorrKeyPair(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }

    /**
     * Generates a new random Schnorr key pair.
     *
     * @return a new {@link SchnorrKeyPair}
     * @throws CryptoException if key generation fails
     */
    public static SchnorrKeyPair generate() throws CryptoException {
        return fromPrivateKey(PrivateKey.generateRandom());
    }

    /**
     * Creates a Schnorr key pair from an existing private key.
     *
     * @param privateKey the private key
     * @return a Schnorr key pair with even-y public key
     * @throws CryptoException if adjustment fails
     */
    public static SchnorrKeyPair fromPrivateKey(PrivateKey privateKey) throws CryptoException {
        Objects.requireNonNull(privateKey, "privateKey cannot be null");

        PrivateKey adjustedPrivateKey = adjustPrivateKeyForEvenY(privateKey);
        return new SchnorrKeyPair(adjustedPrivateKey, adjustedPrivateKey.getPublicKey());
    }

    /**
     * Creates a Schnorr key pair from an existing {@link ECKeyPair}.
     *
     * @param ecKeyPair the EC key pair
     * @return a Schnorr key pair
     * @throws CryptoException if the EC key pair does not contain a private key or adjustment fails
     */
    public static SchnorrKeyPair fromECKeyPair(ECKeyPair ecKeyPair) throws CryptoException {
        Objects.requireNonNull(ecKeyPair, "ecKeyPair cannot be null");
        if (!ecKeyPair.hasPrivateKey()) {
            throw new IllegalStateException("ECKeyPair must contain a private key for Schnorr conversion");
        }
        return fromPrivateKey(ecKeyPair.getPrivateKey());
    }

    private static PrivateKey adjustPrivateKeyForEvenY(PrivateKey originalPrivateKey) throws CryptoException {
        PublicKey publicKey = originalPrivateKey.getPublicKey();
        if (publicKey.hasEvenY()) {
            return originalPrivateKey;
        }

        BigInteger privateValue = originalPrivateKey.toBigInteger();
        BigInteger adjusted = CryptoProvider.getCurve().getN().subtract(privateValue);
        return PrivateKey.fromBigInteger(adjusted);
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
}

