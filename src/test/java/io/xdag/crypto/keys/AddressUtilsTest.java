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
import io.xdag.crypto.exception.AddressFormatException;
import io.xdag.crypto.exception.CryptoException;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class AddressUtilsTest {

    private static ECKeyPair testKeyPair;
    private static PublicKey testPublicKey;

    @BeforeAll
    static void setUp() throws CryptoException {
        testKeyPair = ECKeyPair.generate();
        testPublicKey = testKeyPair.getPublicKey();
    }

    @Test
    void shouldReturnSameAddressFromPublicKeyAndECKeyPair() {
        Bytes publicKeyAddress = AddressUtils.toBytesAddress(testPublicKey);
        Bytes keyPairAddress = AddressUtils.toBytesAddress(testKeyPair);

        assertEquals(keyPairAddress, publicKeyAddress);

        String publicKeyBase58 = AddressUtils.toBase58Address(testPublicKey);
        String keyPairBase58 = AddressUtils.toBase58Address(testKeyPair);

        assertEquals(keyPairBase58, publicKeyBase58);
    }

    @Test
    void shouldReturnDifferentAddressesForCompressedAndUncompressed() {
        Bytes compressedAddress = AddressUtils.toBytesAddress(testPublicKey, true);
        Bytes uncompressedAddress = AddressUtils.toBytesAddress(testPublicKey, false);

        assertNotEquals(uncompressedAddress, compressedAddress);
    }

    @Test
    void shouldReturnValidAddress() {
        Bytes address = AddressUtils.toBytesAddress(testPublicKey);

        assertEquals(20, address.size());
        assertNotNull(address);
    }

    @Test
    void shouldReturnSameAddressForSamePublicKey() {
        Bytes address1 = AddressUtils.toBytesAddress(testPublicKey);
        Bytes address2 = AddressUtils.toBytesAddress(testPublicKey);

        assertEquals(address2, address1);
    }

    @Test
    void shouldReturnValidBase58Address() {
        String base58Address = AddressUtils.toBase58Address(testPublicKey);

        assertFalse(base58Address.isEmpty());
        assertNotNull(base58Address);
    }

    @Test
    void shouldValidateValidBase58Address() throws AddressFormatException {
        String validAddress = AddressUtils.toBase58Address(testPublicKey);

        assertTrue(AddressUtils.isLegacyValidAddress(validAddress));

        // Test that we can decode it without exception
        Bytes decoded = AddressUtils.fromBase58Address(validAddress);
        assertNotNull(decoded);
        assertEquals(20, decoded.size());
    }

    @Test
    void shouldRejectInvalidBase58Addresses() {
        assertFalse(AddressUtils.isLegacyValidAddress(null));
        assertFalse(AddressUtils.isLegacyValidAddress(""));
        assertFalse(AddressUtils.isLegacyValidAddress("invalid"));

        assertThrows(AddressFormatException.class, () ->
            AddressUtils.fromBase58Address("invalid"));
    }
} 