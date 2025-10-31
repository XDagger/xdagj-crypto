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
package io.xdag.crypto.postquantum.dilithium;

import io.xdag.crypto.exception.CryptoException;
import java.util.Objects;
import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;

/**
 * High-level Dilithium signing and verification utilities.
 */
public final class DilithiumSigner {

    private DilithiumSigner() {
        // Utility class
    }

    public static DilithiumKeyPair generate(DilithiumParameter parameter) throws CryptoException {
        return DilithiumKeyPair.generate(parameter);
    }

    public static DilithiumKeyPair generate() throws CryptoException {
        return DilithiumKeyPair.generate(DilithiumParameter.DEFAULT);
    }

    public static DilithiumKeyPair fromSeed(Bytes seed, DilithiumParameter parameter) throws CryptoException {
        return DilithiumKeyPair.fromSeed(seed, parameter);
    }

    public static DilithiumSignature sign(Bytes message, DilithiumKeyPair keyPair) throws CryptoException {
        Objects.requireNonNull(message, "message cannot be null");
        Objects.requireNonNull(keyPair, "keyPair cannot be null");

        try {
            org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner signer =
                    new org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner();
            signer.init(true, keyPair.getPrivateKeyParameters());
            byte[] signature = signer.generateSignature(message.toArrayUnsafe());
            return DilithiumSignature.fromBytes(Bytes.wrap(signature));
        } catch (Exception e) {
            throw new CryptoException("Failed to generate Dilithium signature", e);
        }
    }

    public static boolean verify(Bytes message, DilithiumSignature signature, DilithiumKeyPair keyPair)
            throws CryptoException {
        return verify(message, signature, keyPair.getPublicKeyParameters(), keyPair.getParameter());
    }

    public static boolean verify(
            Bytes message, DilithiumSignature signature, Bytes publicKey, DilithiumParameter parameter)
            throws CryptoException {
        DilithiumPublicKeyParameters publicKeyParameters;
        try {
            publicKeyParameters = new DilithiumPublicKeyParameters(parameter.getParameters(), publicKey.toArrayUnsafe());
        } catch (Exception e) {
            throw new CryptoException("Invalid Dilithium public key", e);
        }
        return verify(message, signature, publicKeyParameters, parameter);
    }

    private static boolean verify(
            Bytes message,
            DilithiumSignature signature,
            DilithiumPublicKeyParameters publicKeyParameters,
            DilithiumParameter parameter)
            throws CryptoException {
        Objects.requireNonNull(message, "message cannot be null");
        Objects.requireNonNull(signature, "signature cannot be null");
        Objects.requireNonNull(publicKeyParameters, "publicKeyParameters cannot be null");
        Objects.requireNonNull(parameter, "parameter cannot be null");

        try {
            org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner verifier =
                    new org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner();
            verifier.init(false, publicKeyParameters);
            return verifier.verifySignature(message.toArrayUnsafe(), signature.toBytes().toArrayUnsafe());
        } catch (Exception e) {
            throw new CryptoException("Failed to verify Dilithium signature", e);
        }
    }

    public static DilithiumSignature sign(Bytes message, DilithiumPrivateKeyParameters privateKey) throws CryptoException {
        Objects.requireNonNull(message, "message cannot be null");
        Objects.requireNonNull(privateKey, "privateKey cannot be null");

        try {
            org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner signer =
                    new org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumSigner();
            signer.init(true, privateKey);
            byte[] signature = signer.generateSignature(message.toArrayUnsafe());
            return DilithiumSignature.fromBytes(Bytes.wrap(signature));
        } catch (Exception e) {
            throw new CryptoException("Failed to generate Dilithium signature", e);
        }
    }
}

