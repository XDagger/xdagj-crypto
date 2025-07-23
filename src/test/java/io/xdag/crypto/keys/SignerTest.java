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

import static org.junit.jupiter.api.Assertions.*;

import io.xdag.crypto.core.CryptoProvider;
import io.xdag.crypto.exception.CryptoException;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class SignerTest {

    private static ECKeyPair testKeyPair;
    private static Bytes32 testMessageHash;

    @BeforeAll
    static void setUp() throws CryptoException {

        testKeyPair = ECKeyPair.generate();
        testMessageHash = Bytes32.fromHexString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    }

    @Test
    void shouldSignAndVerifyWithECKeyPair() throws CryptoException {
        Signature signature = Signer.sign(testMessageHash, testKeyPair);

        assertNotNull(signature);
        assertTrue(signature.isCanonical());

        // Verify with public key
        assertTrue(Signer.verify(testMessageHash, signature, testKeyPair.getPublicKey()));

        // Verify with ECKeyPair
        assertTrue(Signer.verify(testMessageHash, signature, testKeyPair));
    }

    @Test
    void shouldSignAndVerifyWithPrivateKey() throws CryptoException {
        Signature signature = Signer.sign(testMessageHash, testKeyPair.getPrivateKey());

        assertNotNull(signature);
        assertTrue(signature.isCanonical());

        // Verify signature
        assertTrue(Signer.verify(testMessageHash, signature, testKeyPair.getPublicKey()));
    }

    @Test
    void shouldRecoverPublicKeyFromSignature() throws CryptoException {
        Signature signature = Signer.sign(testMessageHash, testKeyPair);

        PublicKey recoveredKey = Signer.recoverPublicKey(testMessageHash, signature);

        assertEquals(testKeyPair.getPublicKey(), recoveredKey);
    }

    @Test
    void shouldFailVerificationWithWrongMessage() throws CryptoException {
        Signature signature = Signer.sign(testMessageHash, testKeyPair);
        Bytes32 wrongMessage = Bytes32.fromHexString("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");

        assertFalse(Signer.verify(wrongMessage, signature, testKeyPair.getPublicKey()));
    }

    @Test
    void shouldFailVerificationWithWrongPublicKey() throws CryptoException {
        Signature signature = Signer.sign(testMessageHash, testKeyPair);
        ECKeyPair wrongKeyPair = ECKeyPair.generate();

        assertFalse(Signer.verify(testMessageHash, signature, wrongKeyPair.getPublicKey()));
    }

    @Test
    void shouldDerivePublicKeyFromPrivateKey() {
        PublicKey derivedKey = Signer.derivePublicKey(testKeyPair.getPrivateKey());

        assertEquals(testKeyPair.getPublicKey(), derivedKey);
    }

    @Test
    void shouldCreateCanonicalSignatures() throws CryptoException {
        // Generate multiple signatures and ensure they're all canonical
        for (int i = 0; i < 10; i++) {
            ECKeyPair keyPair = ECKeyPair.generate();
            Bytes32 messageHash = Bytes32.random();
            Signature signature = Signer.sign(messageHash, keyPair);

            assertTrue(signature.isCanonical());
            assertTrue(Signer.verify(messageHash, signature, keyPair.getPublicKey()));
        }
    }

    @Test
    void shouldProduceDeterministicSignatures() throws CryptoException {
        // Same message and key should produce same signature (deterministic signing)
        Signature signature1 = Signer.sign(testMessageHash, testKeyPair);
        Signature signature2 = Signer.sign(testMessageHash, testKeyPair);

        assertEquals(signature2, signature1);
    }

    @Test
    void shouldWorkWithDifferentKeyPairs() throws CryptoException {
        ECKeyPair keyPair1 = ECKeyPair.generate();
        ECKeyPair keyPair2 = ECKeyPair.generate();

        Signature sig1 = Signer.sign(testMessageHash, keyPair1);
        Signature sig2 = Signer.sign(testMessageHash, keyPair2);

        // Different keys should produce different signatures
        assertNotEquals(sig2, sig1);

        // Each signature should verify with its own key
        assertTrue(Signer.verify(testMessageHash, sig1, keyPair1.getPublicKey()));
        assertTrue(Signer.verify(testMessageHash, sig2, keyPair2.getPublicKey()));

        // Cross-verification should fail
        assertFalse(Signer.verify(testMessageHash, sig1, keyPair2.getPublicKey()));
        assertFalse(Signer.verify(testMessageHash, sig2, keyPair1.getPublicKey()));
    }
} 