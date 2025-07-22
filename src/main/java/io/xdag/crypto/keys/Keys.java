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
import io.xdag.crypto.exception.CryptoException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Cryptographic key utility for SECP256K1 elliptic curve keys.
 *
 * <p>This class provides methods to create and manage elliptic curve key pairs
 * based on the SECP256K1 standard, which is widely used in cryptocurrencies.
 * 
 * <p>All methods in this class are static and thread-safe. The class cannot
 * be instantiated as it serves as a utility class. The private constructor
 * prevents instantiation and subclassing.
 */
public final class Keys {

    /**
     * Private constructor to prevent instantiation.
     * This class serves as a utility class with only static methods.
     */
    private Keys() {
        // Utility class - prevent instantiation
    }

    /**
     * Creates an EC key pair from the given private key.
     *
     * @param privateKey The private key.
     * @return The key pair.
     */
    public static AsymmetricCipherKeyPair fromPrivateKey(BigInteger privateKey) {
        ECDomainParameters curve = CryptoProvider.getCurve();
        ECPrivateKeyParameters privateKeyParams = new ECPrivateKeyParameters(privateKey, curve);
        ECPoint q = curve.getG().multiply(privateKey);
        ECPublicKeyParameters publicKeyParams = new ECPublicKeyParameters(q, curve);
        return new AsymmetricCipherKeyPair(publicKeyParams, privateKeyParams);
    }

    /**
     * Converts a JCA {@link KeyPair} to a Bouncy Castle {@link AsymmetricCipherKeyPair}.
     *
     * @param keyPair The JCA key pair.
     * @return The Bouncy Castle key pair.
     * @throws CryptoException if the key conversion fails.
     */
    public static AsymmetricCipherKeyPair fromJavaKeyPair(KeyPair keyPair) throws CryptoException {
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        ECDomainParameters curve = CryptoProvider.getCurve();
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(privateKey.getS(), curve);

        try {
            if (publicKey instanceof org.bouncycastle.jce.interfaces.ECPublicKey) {
                ECPoint q = ((org.bouncycastle.jce.interfaces.ECPublicKey) publicKey).getQ();
                ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(q, curve);
                return new AsymmetricCipherKeyPair(publicKeyParameters, privateKeyParameters);
            } else {
                byte[] encoded = publicKey.getEncoded();
                ECPoint q = curve.getCurve().decodePoint(encoded);
                ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(q, curve);
                return new AsymmetricCipherKeyPair(publicKeyParameters, privateKeyParameters);
            }
        } catch (Exception e) {
            throw new CryptoException("Failed to decode public key", e);
        }
    }


    /**
     * Extracts the private key from a Bouncy Castle {@link AsymmetricCipherKeyPair}.
     *
     * @param keyPair The key pair.
     * @return The private key as a {@link BigInteger}.
     */
    public static BigInteger getPrivateKey(AsymmetricCipherKeyPair keyPair) {
        return ((ECPrivateKeyParameters) keyPair.getPrivate()).getD();
    }

}