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
import java.math.BigInteger;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Provides ECDSA signature operations based on the SECP256K1 curve.
 *
 * <p>This class implements signing, verification, and public key recovery from signatures, using a
 * pure Bouncy Castle implementation. It ensures that signatures are canonical and compliant with
 * standards used in major cryptocurrencies. All cryptographic data is handled using {@link
 * org.apache.tuweni.bytes.Bytes32} for performance and type safety.
 */
public final class Sign {

    private static final ECDomainParameters CURVE = CryptoProvider.getCurve();
    static final BigInteger HALF_CURVE_ORDER = CURVE.getN().shiftRight(1);

    /**
     * The recovery ID offset used in ECDSA signatures.
     * This value is added to the recovery ID (0 or 1) to produce the 'v' component.
     */
    public static final int RECOVERY_ID_OFFSET = 27;

    private Sign() {
        // Utility class - prevent instantiation
    }

    /**
     * Signs a 32-byte message hash using the provided key pair.
     *
     * @param messageHash The 32-byte hash to sign.
     * @param keyPair The key pair to use for signing.
     * @return The canonical {@link SignatureData}, including the recovery ID.
     */
    public static SignatureData sign(Bytes32 messageHash, AsymmetricCipherKeyPair keyPair) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        ECPrivateKeyParameters privateKeyParams = (ECPrivateKeyParameters) keyPair.getPrivate();
        signer.init(true, privateKeyParams);
        BigInteger[] components = signer.generateSignature(messageHash.toArrayUnsafe());

        BigInteger r = components[0];
        BigInteger s = components[1];

        // Ensure canonical signature
        if (s.compareTo(HALF_CURVE_ORDER) > 0) {
            s = CURVE.getN().subtract(s);
        }

        // Determine recovery ID
        ECPoint publicKeyPoint = ((ECPublicKeyParameters) keyPair.getPublic()).getQ();
        int recId = -1;
        for (int i = 0; i < 4; i++) {
            ECPoint recovered = recoverPublicKeyFromSignature(i, r, s, messageHash);
            if (recovered != null && recovered.equals(publicKeyPoint)) {
                recId = i;
                break;
            }
        }

        if (recId == -1) {
            throw new RuntimeException("Could not construct a recoverable signature.");
        }

        byte v = (byte) (recId + RECOVERY_ID_OFFSET);
        return new SignatureData(v, r, s);
    }

    /**
     * Verifies an ECDSA signature.
     *
     * @param messageHash The hash that was signed.
     * @param signature The signature to verify.
     * @param publicKey The public key to use for verification.
     * @return {@code true} if the signature is valid and canonical, {@code false} otherwise.
     */
    public static boolean verify(Bytes32 messageHash, SignatureData signature, ECPoint publicKey) {
        if (!signature.isCanonical()) {
            return false;
        }

        ECDSASigner signer = new ECDSASigner();
        signer.init(false, new ECPublicKeyParameters(publicKey, CURVE));
        return signer.verifySignature(
                messageHash.toArrayUnsafe(),
                new BigInteger(1, signature.r().toArrayUnsafe()),
                new BigInteger(1, signature.s().toArrayUnsafe()));
    }


    /**
     * Recovers the public key from an ECDSA signature.
     *
     * @param recId The recovery ID (0-3).
     * @param r The r-component of the signature.
     * @param s The s-component of the signature.
     * @param messageHash The hash of the message that was signed.
     * @return The recovered public key point, or null if recovery is not possible.
     */
    static ECPoint recoverPublicKeyFromSignature(
            int recId, BigInteger r, BigInteger s, Bytes32 messageHash) {
        if (recId < 0 || recId > 3) {
            throw new IllegalArgumentException("Invalid recovery ID.");
        }
        if (r.signum() < 1 || s.signum() < 1) {
            return null;
        }

        BigInteger n = CURVE.getN();
        BigInteger i = BigInteger.valueOf(recId / 2);
        BigInteger x = r.add(i.multiply(n));

        if (x.compareTo(CURVE.getCurve().getField().getCharacteristic()) >= 0) {
            return null;
        }

        ECPoint R = decompressKey(x, (recId & 1) == 1);
        if (!R.multiply(n).isInfinity()) {
            return null;
        }

        BigInteger e = messageHash.toUnsignedBigInteger();
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
        BigInteger rInv = r.modInverse(n);
        BigInteger srInv = s.multiply(rInv).mod(n);
        BigInteger eInvRInv = eInv.multiply(rInv).mod(n);

        ECPoint Q = ECAlgorithms.sumOfTwoMultiplies(CURVE.getG(), eInvRInv, R, srInv);
        return Q.getEncoded(false).length == 0 ? null : Q;
    }

    /**
     * Decompresses a public key point from its x-coordinate and y-bit.
     *
     * @param x The x-coordinate.
     * @param yBit The low bit of the y-coordinate.
     * @return The decompressed ECPoint.
     */
    private static ECPoint decompressKey(BigInteger x, boolean yBit) {
        byte[] xBytes = org.bouncycastle.util.BigIntegers.asUnsignedByteArray(32, x);
        byte[] encoded = new byte[33];
        encoded[0] = (byte) (yBit ? 0x03 : 0x02);
        System.arraycopy(xBytes, 0, encoded, 1, xBytes.length);
        return CURVE.getCurve().decodePoint(encoded);
    }

    /**
     * Derives the public key point from a private key.
     *
     * @param privateKey The private key.
     * @return The corresponding public key as an ECPoint.
     */
    public static ECPoint publicKeyFromPrivate(BigInteger privateKey) {
        return CURVE.getG().multiply(privateKey);
    }
} 