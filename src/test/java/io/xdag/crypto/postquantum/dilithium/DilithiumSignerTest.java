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

import static org.junit.jupiter.api.Assertions.*;

import io.xdag.crypto.bip.Bip44Wallet;
import io.xdag.crypto.exception.CryptoException;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

class DilithiumSignerTest {

    private static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    @Test
    void shouldGenerateAndVerifyDilithiumSignature() throws CryptoException {
        DilithiumKeyPair keyPair = DilithiumSigner.generate(DilithiumParameter.DILITHIUM2);
        Bytes message = Bytes.fromHexString("0x48656c6c6f20584f53");

        DilithiumSignature signature = DilithiumSigner.sign(message, keyPair);
        assertNotNull(signature);
        assertTrue(DilithiumSigner.verify(message, signature, keyPair));

        byte[] tampered = signature.toBytes().toArrayUnsafe().clone();
        tampered[0] ^= 0x01;
        DilithiumSignature invalidSignature = DilithiumSignature.fromBytes(Bytes.wrap(tampered));
        assertFalse(DilithiumSigner.verify(message, invalidSignature, keyPair));
    }

    @Test
    void shouldDeriveDeterministicKeyPairFromMnemonic() throws CryptoException {
        DilithiumKeyPair keyPair1 = Bip44Wallet.createDilithiumKeyPairFromMnemonic(TEST_MNEMONIC);
        DilithiumKeyPair keyPair2 = Bip44Wallet.createDilithiumKeyPairFromMnemonic(TEST_MNEMONIC);

        assertEquals(keyPair1.getPublicKey(), keyPair2.getPublicKey());
        assertEquals(keyPair1.getPrivateKey(), keyPair2.getPrivateKey());

        Bytes message = Bytes.fromHexString("0x74657374206d657373616765");
        DilithiumSignature signature = DilithiumSigner.sign(message, keyPair1);
        assertTrue(DilithiumSigner.verify(message, signature, keyPair2));
        assertTrue(DilithiumSigner.verify(message, signature, keyPair1.getPublicKey(), keyPair1.getParameter()));
    }
}

