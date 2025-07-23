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
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECPoint;

/**
 * ECDSA signature operations for the secp256k1 curve.
 * 
 * <p>This class provides cryptographic signing, verification, and public key recovery
 * operations using the secp256k1 elliptic curve. All signatures are canonical and 
 * compliant with Bitcoin/Ethereum standards.
 * 
 * <p>Key features:
 * <ul>
 *   <li><strong>Type Safety</strong> - Uses {@link PrivateKey}, {@link PublicKey}, and {@link ECKeyPair} instead of raw types</li>
 *   <li><strong>Canonical Signatures</strong> - Ensures s-values are in the lower half of curve order</li>
 *   <li><strong>Recovery Support</strong> - Signatures include recovery ID for public key recovery</li>
 *   <li><strong>Thread Safety</strong> - All methods are stateless and thread-safe</li>
 * </ul>
 * 
 * <p>Example usage:
 * <pre>{@code
 * // Sign a message
 * ECKeyPair keyPair = ECKeyPair.generate();
 * Bytes32 messageHash = Bytes32.fromHexString("0x...");
 * Signature signature = Signer.sign(messageHash, keyPair);
 * 
 * // Verify the signature
 * boolean isValid = Signer.verify(messageHash, signature, keyPair.getPublicKey());
 * 
 * // Recover public key from signature
 * PublicKey recoveredKey = Signer.recoverPublicKey(messageHash, signature);
 * }</pre>
 * 
 * @see Signature
 * @see ECKeyPair
 * @see PrivateKey
 * @see PublicKey
 */
public final class Signer {

    /** Half of the curve order, used for canonical signature validation. */
    static final BigInteger HALF_CURVE_ORDER = CryptoProvider.getCurve().getN().shiftRight(1);

    private Signer() {
        // Utility class - prevent instantiation
    }

    /**
     * Signs a message hash using an ECKeyPair.
     * 
     * <p>This method creates a canonical ECDSA signature that includes a recovery ID,
     * allowing the public key to be recovered from the signature alone.
     * 
     * @param messageHash the 32-byte message hash to sign
     * @param keyPair the key pair to use for signing
     * @return a canonical signature with recovery capability
     * @throws CryptoException if signing fails or keyPair lacks a private key
     */
    public static Signature sign(Bytes32 messageHash, ECKeyPair keyPair) throws CryptoException {
        if (keyPair.getPrivateKey() == null) {
            throw new CryptoException("Key pair must contain a private key for signing");
        }
        return sign(messageHash, keyPair.getPrivateKey());
    }

    /**
     * Signs a message hash using a private key.
     * 
     * <p>This is a convenience method that creates the signature using only the private key.
     * The corresponding public key is derived automatically for signature recovery.
     * 
     * @param messageHash the 32-byte message hash to sign
     * @param privateKey the private key to use for signing
     * @return a canonical signature with recovery capability
     */
    public static Signature sign(Bytes32 messageHash, PrivateKey privateKey) {
        return signInternal(messageHash, privateKey.toBigInteger(), privateKey.getPublicKey().getPoint());
    }

    /**
     * Verifies an ECDSA signature using a public key.
     * 
     * <p>This method verifies that the signature was created by the holder of the
     * corresponding private key for the given message hash.
     * 
     * @param messageHash the original message hash that was signed
     * @param signature the signature to verify
     * @param publicKey the public key to verify against
     * @return true if the signature is valid, false otherwise
     */
    public static boolean verify(Bytes32 messageHash, Signature signature, PublicKey publicKey) {
        if (!signature.isCanonical()) {
            return false;
        }

        ECDSASigner signer = new ECDSASigner();
        ECPublicKeyParameters publicKeyParams = new ECPublicKeyParameters(
            publicKey.getPoint(), CryptoProvider.getCurve());
        signer.init(false, publicKeyParams);
        
        return signer.verifySignature(
            messageHash.toArrayUnsafe(),
            signature.getR(),
            signature.getS());
    }

    /**
     * Verifies an ECDSA signature using an ECKeyPair.
     * 
     * <p>This is a convenience method that extracts the public key from the key pair.
     * 
     * @param messageHash the original message hash that was signed
     * @param signature the signature to verify
     * @param keyPair the key pair containing the public key to verify against
     * @return true if the signature is valid, false otherwise
     */
    public static boolean verify(Bytes32 messageHash, Signature signature, ECKeyPair keyPair) {
        return verify(messageHash, signature, keyPair.getPublicKey());
    }

    /**
     * Recovers the public key from a signature.
     * 
     * <p>This method uses the recovery ID embedded in the signature to recover
     * the public key that was used to create the signature.
     * 
     * @param messageHash the original message hash that was signed
     * @param signature the signature containing the recovery information
     * @return the recovered public key
     * @throws CryptoException if recovery fails
     */
    public static PublicKey recoverPublicKey(Bytes32 messageHash, Signature signature) throws CryptoException {
        ECPoint point = recoverPublicKeyPoint(
            signature.getRecoveryId(),
            signature.getR(),
            signature.getS(),
            messageHash);
        
        if (point == null) {
            throw new CryptoException("Failed to recover public key from signature");
        }
        
        return PublicKey.fromPoint(point);
    }

    /**
     * Derives a public key from a private key.
     * 
     * <p>This is a convenience method for public key derivation.
     * 
     * @param privateKey the private key
     * @return the corresponding public key
     */
    public static PublicKey derivePublicKey(PrivateKey privateKey) {
        return privateKey.getPublicKey();
    }

    /**
     * Internal signature creation method.
     */
    private static Signature signInternal(Bytes32 messageHash, BigInteger privateKey, ECPoint publicKeyPoint) {
        ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
        ECPrivateKeyParameters privateKeyParams = new ECPrivateKeyParameters(privateKey, CryptoProvider.getCurve());
        signer.init(true, privateKeyParams);
        BigInteger[] components = signer.generateSignature(messageHash.toArrayUnsafe());

        BigInteger r = components[0];
        BigInteger s = components[1];

        // Ensure canonical signature (s in lower half of curve order)
        if (s.compareTo(HALF_CURVE_ORDER) > 0) {
            s = CryptoProvider.getCurve().getN().subtract(s);
        }

        // Determine recovery ID
        int recoveryId = -1;
        for (int i = 0; i < 4; i++) {
            ECPoint recovered = recoverPublicKeyPoint(i, r, s, messageHash);
            if (recovered != null && recovered.equals(publicKeyPoint)) {
                recoveryId = i;
                break;
            }
        }

        if (recoveryId == -1) {
            throw new RuntimeException("Could not construct a recoverable signature");
        }

        byte v = (byte) (recoveryId + Signature.RECOVERY_ID_OFFSET);
        return new Signature(v, r, s);
    }

    /**
     * Recovers public key point from signature components.
     */
    private static ECPoint recoverPublicKeyPoint(int recoveryId, BigInteger r, BigInteger s, Bytes32 messageHash) {
        if (recoveryId < 0 || recoveryId > 3) {
            return null;
        }

        BigInteger x = r;
        if ((recoveryId & 2) != 0) {
            x = r.add(CryptoProvider.getCurve().getN());
        }

        if (x.compareTo(CryptoProvider.getCurve().getCurve().getField().getCharacteristic()) >= 0) {
            return null;
        }

        ECPoint R = decompressKey(x, (recoveryId & 1) == 1);
        if (!R.multiply(CryptoProvider.getCurve().getN()).isInfinity()) {
            return null;
        }

        BigInteger e = new BigInteger(1, messageHash.toArrayUnsafe());
        BigInteger eInv = BigInteger.ZERO.subtract(e).mod(CryptoProvider.getCurve().getN());
        BigInteger rInv = r.modInverse(CryptoProvider.getCurve().getN());
        BigInteger srInv = rInv.multiply(s).mod(CryptoProvider.getCurve().getN());
        BigInteger eInvRInv = rInv.multiply(eInv).mod(CryptoProvider.getCurve().getN());

        ECPoint Q = ECAlgorithms.sumOfTwoMultiplies(CryptoProvider.getCurve().getG(), eInvRInv, R, srInv);
        return Q.isInfinity() ? null : Q;
    }

    /**
     * Decompresses a public key point from x-coordinate and y-bit.
     */
    private static ECPoint decompressKey(BigInteger x, boolean yBit) {
        byte[] encoded = new byte[33];
        encoded[0] = (byte) (yBit ? 0x03 : 0x02);
        byte[] xBytes = x.toByteArray();
        int srcPos = xBytes.length > 32 ? 1 : 0;  // Skip sign byte if present
        int copyLen = Math.min(32, xBytes.length);
        System.arraycopy(xBytes, srcPos, encoded, 33 - copyLen, copyLen);
        return CryptoProvider.getCurve().getCurve().decodePoint(encoded);
    }
} 