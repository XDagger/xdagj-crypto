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

import static org.junit.jupiter.api.Assertions.*;

import io.xdag.crypto.bip.Bip44Wallet;
import io.xdag.crypto.exception.CryptoException;
import io.xdag.crypto.keys.PrivateKey;
import io.xdag.crypto.keys.PublicKey;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

class SchnorrSignerTest {

    private static final String TEST_MNEMONIC =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    @Test
    void shouldSignBip340Vector0() throws CryptoException {
        PrivateKey privateKey = PrivateKey.fromHex(
                "0x0000000000000000000000000000000000000000000000000000000000000003");
        SchnorrKeyPair keyPair = SchnorrKeyPair.fromPrivateKey(privateKey);

        Bytes message = Bytes.fromHexString(
                "0x0000000000000000000000000000000000000000000000000000000000000000");
        Bytes32 auxRand = Bytes32.fromHexString(
                "0x0000000000000000000000000000000000000000000000000000000000000000");

        SchnorrSignature signature = SchnorrSigner.sign(message, keyPair, auxRand);

        assertEquals(
                "0xe907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
                signature.toBytes().toHexString());
        assertTrue(SchnorrSigner.verify(message, signature, keyPair.getPublicKey()));
    }

    @Test
    void shouldSignBip340Vector1() throws CryptoException {
        PrivateKey privateKey = PrivateKey.fromHex(
                "0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
        SchnorrKeyPair keyPair = SchnorrKeyPair.fromPrivateKey(privateKey);

        Bytes message = Bytes.fromHexString(
                "0x243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");
        Bytes32 auxRand = Bytes32.fromHexString(
                "0x0000000000000000000000000000000000000000000000000000000000000001");

        SchnorrSignature signature = SchnorrSigner.sign(message, keyPair, auxRand);

        assertEquals(
                "0x6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a",
                signature.toBytes().toHexString());
        assertTrue(SchnorrSigner.verify(message, signature, keyPair.getPublicKey()));
    }

    @Test
    void shouldVerifyVectorWithPublicKeyOnly() throws CryptoException {
        PublicKey publicKey = PublicKey.fromXCoordinate(
                Bytes32.fromHexString("0xD69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9"),
                false);
        Bytes message = Bytes.fromHexString(
                "0x4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703");
        Bytes signatureBytes = Bytes.fromHexString(
                "0x00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4");
        SchnorrSignature signature = SchnorrSignature.fromBytes(signatureBytes);

        assertTrue(SchnorrSigner.verify(message, signature, publicKey));
    }

    @Test
    void shouldRejectInvalidSignatureFromVectors() throws CryptoException {
        PublicKey publicKey = PublicKey.fromXCoordinate(
                Bytes32.fromHexString("0xDFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659"),
                false);
        Bytes message = Bytes.fromHexString(
                "0x243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89");
        SchnorrSignature signature = SchnorrSignature.fromBytes(Bytes.fromHexString(
                "0xFFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2"));

        assertFalse(SchnorrSigner.verify(message, signature, publicKey));
    }

    @Test
    void shouldDeriveSchnorrKeyPairFromMnemonic() throws CryptoException {
        SchnorrKeyPair schnorrKeyPair = Bip44Wallet.createSchnorrKeyPairFromMnemonic(TEST_MNEMONIC);
        assertNotNull(schnorrKeyPair.getPrivateKey());
        assertNotNull(schnorrKeyPair.getPublicKey());
        assertTrue(schnorrKeyPair.getPublicKey().hasEvenY());
    }
}

