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
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;

/**
 * Test for point-at-infinity validation in PublicKey constructor.
 *
 * <p>The point at infinity is a valid ECPoint but must NOT be accepted as a public key
 * because it represents the identity element in elliptic curve arithmetic and has no
 * valid cryptographic use as a public key.
 */
public class PublicKeyInfinityTest {

    @Test
    void shouldRejectPointAtInfinity() {
        // Get the point at infinity from the curve
        ECPoint infinity = CryptoProvider.getCurve().getCurve().getInfinity();

        // Verify it's recognized as infinity
        assertTrue(infinity.isInfinity(), "Point should be recognized as infinity");

        // Verify it passes isValid() check (this is why explicit infinity check is needed)
        assertTrue(infinity.isValid(), "Infinity point is technically valid");

        // PublicKey.fromPoint should reject the point at infinity
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> PublicKey.fromPoint(infinity),
            "PublicKey.fromPoint should reject point at infinity"
        );

        // Verify the exception message
        assertNotNull(exception.getMessage());
        assertTrue(
            exception.getMessage().contains("Invalid EC point") ||
            exception.getMessage().contains("infinity"),
            "Exception message should indicate invalid point or infinity"
        );
    }
}
