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
package io.xdag.crypto.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.junit.jupiter.api.Test;

public class CryptoProviderTest {

    // CryptoProvider is automatically initialized via static block

    @Test
    void testIsInitialized() {
        assertTrue(CryptoProvider.isInstalled(), "CryptoProvider should be initialized");
    }

    @Test
    void testGetCurve() {
        ECDomainParameters curve = CryptoProvider.getCurve();
        assertNotNull(curve, "Curve parameters should not be null");

        // Sanity check some of the secp256k1 parameters
        BigInteger expectedN = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
        assertEquals(expectedN, curve.getN(), "Curve's N value does not match secp256k1");
        
        assertNotNull(curve.getG(), "Curve's generator point G should not be null");
    }

    @Test
    void testConstants() {
        assertEquals("ECDSA", CryptoProvider.ALGORITHM);
        assertEquals("BC", CryptoProvider.BOUNCY_CASTLE_PROVIDER);
        assertEquals("secp256k1", CryptoProvider.CURVE_NAME);
    }

    @Test
    void shouldInitializeCryptoProvider() {
        CryptoProvider.initialize();
        
        assertTrue(CryptoProvider.isInstalled(), "CryptoProvider should be initialized");
    }


} 