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

import static org.assertj.core.api.Assertions.assertThat;

import io.xdag.crypto.core.CryptoProvider;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import java.security.spec.ECGenParameterSpec;
import io.xdag.crypto.core.SecureRandomProvider;
import io.xdag.crypto.exception.CryptoException;

class SignTest {

    private static AsymmetricCipherKeyPair testKeyPair;
    private static ECPoint testPublicKeyPoint;
    private static Bytes32 sampleMessageHash;

    @BeforeAll
    static void setUp() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CryptoException {
        CryptoProvider.install();
        // Generate a reusable keypair for tests
        java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(CryptoProvider.CURVE_NAME);
        keyPairGenerator.initialize(ecSpec, SecureRandomProvider.getSecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        testKeyPair = Keys.fromJavaKeyPair(keyPair);
        testPublicKeyPoint = ((ECPublicKeyParameters) testKeyPair.getPublic()).getQ();

        // Create a sample message hash
        sampleMessageHash = Bytes32.fromHexString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    }

    @Test
    void shouldSignAndVerifySuccessfully() {
        SignatureData signature = Sign.sign(sampleMessageHash, testKeyPair);
        assertThat(signature).isNotNull();

        boolean valid = Sign.verify(sampleMessageHash, signature, testPublicKeyPoint);
        assertThat(valid).isTrue();
    }

    @Test
    void testSignatureIsCanonical() {
        SignatureData signature = Sign.sign(sampleMessageHash, testKeyPair);
        assertThat(signature.isCanonical()).isTrue();
    }

    @Test
    void shouldFailToVerifyWithWrongPublicKey()
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, CryptoException {
        SignatureData signature = Sign.sign(sampleMessageHash, testKeyPair);

        // Create a different key pair
        java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        ECGenParameterSpec ecSpec = new ECGenParameterSpec(CryptoProvider.CURVE_NAME);
        keyPairGenerator.initialize(ecSpec, SecureRandomProvider.getSecureRandom());
        AsymmetricCipherKeyPair wrongKeyPair = Keys.fromJavaKeyPair(keyPairGenerator.generateKeyPair());
        ECPoint wrongPublicKeyPoint = ((ECPublicKeyParameters) wrongKeyPair.getPublic()).getQ();

        boolean valid = Sign.verify(sampleMessageHash, signature, wrongPublicKeyPoint);
        assertThat(valid).isFalse();
    }

    @Test
    void shouldFailToVerifyWithTamperedMessage() {
        SignatureData signature = Sign.sign(sampleMessageHash, testKeyPair);
        Bytes32 tamperedMessage = Bytes32.fromHexString("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        boolean valid = Sign.verify(tamperedMessage, signature, testPublicKeyPoint);
        assertThat(valid).isFalse();
    }

    @Test
    void testPublicKeyRecovery() {
        SignatureData signature = Sign.sign(sampleMessageHash, testKeyPair);

        ECPoint recoveredKey = Sign.recoverPublicKeyFromSignature(
                signature.v() - Sign.RECOVERY_ID_OFFSET,
                new BigInteger(1, signature.r().toArrayUnsafe()),
                new BigInteger(1, signature.s().toArrayUnsafe()),
                sampleMessageHash
        );

        assertThat(recoveredKey).isNotNull();
        assertThat(recoveredKey).isEqualTo(testPublicKeyPoint);
    }

    @Test
    void testPublicKeyFromPrivate() {
        BigInteger privateKey = Keys.getPrivateKey(testKeyPair);
        ECPoint derivedPublicKey = Sign.publicKeyFromPrivate(privateKey);
        assertThat(derivedPublicKey).isEqualTo(testPublicKeyPoint);
    }
} 