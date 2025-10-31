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

import io.xdag.crypto.core.CryptoProvider;
import io.xdag.crypto.exception.CryptoException;
import io.xdag.crypto.hash.HashUtils;
import java.security.SecureRandom;
import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.prng.FixedSecureRandom;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumPublicKeyParameters;

/**
 * Represents a Dilithium post-quantum key pair.
 */
public final class DilithiumKeyPair {

    private final DilithiumParameter parameter;
    private final DilithiumPublicKeyParameters publicKeyParameters;
    private final DilithiumPrivateKeyParameters privateKeyParameters;

    private DilithiumKeyPair(
            DilithiumParameter parameter,
            DilithiumPublicKeyParameters publicKeyParameters,
            DilithiumPrivateKeyParameters privateKeyParameters) {
        this.parameter = parameter;
        this.publicKeyParameters = publicKeyParameters;
        this.privateKeyParameters = privateKeyParameters;
    }

    public DilithiumParameter getParameter() {
        return parameter;
    }

    public DilithiumPublicKeyParameters getPublicKeyParameters() {
        return publicKeyParameters;
    }

    public DilithiumPrivateKeyParameters getPrivateKeyParameters() {
        return privateKeyParameters;
    }

    public Bytes getPublicKey() {
        return Bytes.wrap(publicKeyParameters.getEncoded());
    }

    public Bytes getPrivateKey() {
        return Bytes.wrap(privateKeyParameters.getEncoded());
    }

    /**
     * Generates a new random Dilithium key pair using the library's secure random source.
     */
    public static DilithiumKeyPair generate(DilithiumParameter parameter) throws CryptoException {
        return generate(parameter, CryptoProvider.getSecureRandom());
    }

    /**
     * Derives a deterministic Dilithium key pair from arbitrary seed material.
     *
     * @param seed seed material (e.g. BIP39 seed)
     * @param parameter Dilithium parameter set
     * @return deterministically derived key pair
     */
    public static DilithiumKeyPair fromSeed(Bytes seed, DilithiumParameter parameter) throws CryptoException {
        if (seed == null) {
            throw new CryptoException("Seed cannot be null");
        }

        Bytes domainSeparatedSeed = HashUtils.taggedHash(
                "XDAG-Dilithium-Seed", Bytes.concatenate(seed, Bytes.of((byte) parameter.getSecurityLevel())));
        byte[] shakeSeed = HashUtils.shake256(domainSeparatedSeed, 4096).toArrayUnsafe();
        try {
            SecureRandom deterministicRandom = new FixedSecureRandom(shakeSeed);
            return generate(parameter, deterministicRandom);
        } finally {
            java.util.Arrays.fill(shakeSeed, (byte) 0);
        }
    }

    private static DilithiumKeyPair generate(DilithiumParameter parameter, SecureRandom secureRandom)
            throws CryptoException {
        try {
            DilithiumKeyPairGenerator generator = new DilithiumKeyPairGenerator();
            generator.init(new DilithiumKeyGenerationParameters(secureRandom, parameter.getParameters()));
            AsymmetricCipherKeyPair pair = generator.generateKeyPair();
            return new DilithiumKeyPair(
                    parameter,
                    (DilithiumPublicKeyParameters) pair.getPublic(),
                    (DilithiumPrivateKeyParameters) pair.getPrivate());
        } catch (Exception e) {
            throw new CryptoException("Failed to generate Dilithium key pair", e);
        }
    }
}

