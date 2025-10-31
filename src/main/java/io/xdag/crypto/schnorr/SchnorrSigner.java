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
import io.xdag.crypto.hash.HashUtils;
import io.xdag.crypto.keys.PrivateKey;
import io.xdag.crypto.keys.PublicKey;
import java.math.BigInteger;
import java.util.Objects;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Implements BIP340 Schnorr signing and verification for the secp256k1 curve.
 */
public final class SchnorrSigner {

    private static final BigInteger CURVE_ORDER = CryptoProvider.getCurve().getN();
    private static final BigInteger FIELD_PRIME = CryptoProvider.getCurve().getCurve().getField().getCharacteristic();

    private SchnorrSigner() {
        // Utility class
    }

    /**
     * Signs a message using the provided Schnorr key pair and freshly generated auxiliary randomness.
     *
     * @param message the message to sign
     * @param keyPair the Schnorr key pair
     * @return the Schnorr signature
     * @throws CryptoException if signing fails
     */
    public static SchnorrSignature sign(Bytes message, SchnorrKeyPair keyPair) throws CryptoException {
        Objects.requireNonNull(message, "message cannot be null");
        Objects.requireNonNull(keyPair, "keyPair cannot be null");

        byte[] aux = CryptoProvider.nextBytes(32);
        try {
            return sign(message, keyPair, Bytes32.wrap(aux));
        } finally {
            java.util.Arrays.fill(aux, (byte) 0);
        }
    }

    /**
     * Signs a message using the provided Schnorr key pair and optional auxiliary randomness.
     *
     * @param message the message to sign
     * @param keyPair the Schnorr key pair
     * @param auxRand32 optional 32-byte auxiliary randomness (if null, treated as zero)
     * @return the Schnorr signature
     * @throws CryptoException if signing fails
     */
    public static SchnorrSignature sign(Bytes message, SchnorrKeyPair keyPair, Bytes32 auxRand32)
            throws CryptoException {
        Objects.requireNonNull(message, "message cannot be null");
        Objects.requireNonNull(keyPair, "keyPair cannot be null");

        PrivateKey privateKey = keyPair.getPrivateKey();
        PublicKey publicKey = keyPair.getPublicKey();

        Bytes32 privateKeyBytes = privateKey.toBytes();
        Bytes32 publicKeyX = publicKey.toXOnlyBytes();

        Bytes32 auxRand = auxRand32 != null ? auxRand32 : Bytes32.ZERO;
        Bytes32 hashAux = HashUtils.taggedHash("BIP0340/aux", auxRand);

        byte[] tArray = privateKeyBytes.toArrayUnsafe().clone();
        byte[] hashAuxArray = hashAux.toArrayUnsafe().clone();
        for (int i = 0; i < tArray.length; i++) {
            tArray[i] ^= hashAuxArray[i];
        }

        Bytes32 t = Bytes32.wrap(tArray);
        try {
            Bytes32 nonceHash = HashUtils.taggedHash("BIP0340/nonce", Bytes.concatenate(t, publicKeyX, message));
            BigInteger k0 = nonceHash.toUnsignedBigInteger().mod(CURVE_ORDER);
            if (k0.equals(BigInteger.ZERO)) {
                throw new CryptoException("Failed to generate valid nonce for Schnorr signature");
            }

            ECPoint rPoint = CryptoProvider.getCurve().getG().multiply(k0).normalize();
            if (rPoint.getAffineYCoord().toBigInteger().testBit(0)) {
                k0 = CURVE_ORDER.subtract(k0);
                rPoint = CryptoProvider.getCurve().getG().multiply(k0).normalize();
            }

            Bytes32 rBytes = bytesFromFieldElement(rPoint.getAffineXCoord().toBigInteger());
            Bytes32 eBytes = HashUtils.taggedHash("BIP0340/challenge", Bytes.concatenate(rBytes, publicKeyX, message));
            BigInteger e = eBytes.toUnsignedBigInteger().mod(CURVE_ORDER);

            BigInteger d = privateKey.toBigInteger();
            BigInteger s = k0.add(e.multiply(d)).mod(CURVE_ORDER);
            if (s.signum() == 0) {
                throw new CryptoException("Computed Schnorr signature scalar is zero");
            }

            return SchnorrSignature.create(rBytes, bytesFromScalar(s));
        } finally {
            java.util.Arrays.fill(tArray, (byte) 0);
            java.util.Arrays.fill(hashAuxArray, (byte) 0);
        }
    }

    /**
     * Verifies a Schnorr signature against the provided public key.
     *
     * @param message the signed message
     * @param signature the Schnorr signature
     * @param publicKey the public key
     * @return true if the signature is valid, false otherwise
     */
    public static boolean verify(Bytes message, SchnorrSignature signature, PublicKey publicKey) {
        Objects.requireNonNull(message, "message cannot be null");
        Objects.requireNonNull(signature, "signature cannot be null");
        Objects.requireNonNull(publicKey, "publicKey cannot be null");

        BigInteger r = signature.getRAsBigInteger();
        BigInteger s = signature.getSAsBigInteger();

        if (r.signum() <= 0 || r.compareTo(FIELD_PRIME) >= 0) {
            return false;
        }
        if (s.signum() <= 0 || s.compareTo(CURVE_ORDER) >= 0) {
            return false;
        }

        ECPoint publicPoint = publicKey.getPoint();
        if (!publicKey.hasEvenY()) {
            publicPoint = publicPoint.negate();
        }

        Bytes32 publicKeyX = bytesFromFieldElement(publicPoint.getAffineXCoord().toBigInteger());
        Bytes32 rBytes = bytesFromFieldElement(r);
        Bytes eHashInput = Bytes.concatenate(rBytes, publicKeyX, message);
        BigInteger e = HashUtils.taggedHash("BIP0340/challenge", eHashInput).toUnsignedBigInteger().mod(CURVE_ORDER);

        ECPoint sG = CryptoProvider.getCurve().getG().multiply(s);
        ECPoint eP = publicPoint.multiply(e);
        ECPoint rPoint = sG.subtract(eP).normalize();

        if (rPoint.isInfinity()) {
            return false;
        }
        if (rPoint.getAffineYCoord().toBigInteger().testBit(0)) {
            return false;
        }

        Bytes32 computedRx = bytesFromFieldElement(rPoint.getAffineXCoord().toBigInteger());
        return HashUtils.constantTimeEquals(computedRx, signature.getR());
    }

    private static Bytes32 bytesFromFieldElement(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == 32) {
            return Bytes32.wrap(bytes);
        } else if (bytes.length > 32) {
            return Bytes32.wrap(java.util.Arrays.copyOfRange(bytes, bytes.length - 32, bytes.length));
        } else {
            byte[] padded = new byte[32];
            System.arraycopy(bytes, 0, padded, 32 - bytes.length, bytes.length);
            return Bytes32.wrap(padded);
        }
    }

    private static Bytes32 bytesFromScalar(BigInteger value) {
        return bytesFromFieldElement(value);
    }

}

