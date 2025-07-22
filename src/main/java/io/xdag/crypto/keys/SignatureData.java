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

import java.math.BigInteger;
import org.apache.tuweni.bytes.Bytes32;

/**
 * Represents the components of an ECDSA signature (v, r, s).
 *
 * <p>The 'v' component is the recovery ID, used to recover the public key from the signature. 'r'
 * and 's' are the two 32-byte components of the signature. This record uses {@link Bytes32} for
 * performance and type safety.
 *
 * @param v The recovery ID (typically 27 or 28, or 0/1 for EIP-155).
 * @param r The r-component of the signature (32 bytes).
 * @param s The s-component of the signature (32 bytes).
 */
public record SignatureData(byte v, Bytes32 r, Bytes32 s) {

    /**
     * Constructs a SignatureData object from BigIntegers, converting them to Bytes32.
     *
     * @param v The recovery ID.
     * @param r The r-component as a BigInteger.
     * @param s The s-component as a BigInteger.
     */
    public SignatureData(byte v, BigInteger r, BigInteger s) {
        this(v,
                Bytes32.wrap(org.bouncycastle.util.BigIntegers.asUnsignedByteArray(32, r)),
                Bytes32.wrap(org.bouncycastle.util.BigIntegers.asUnsignedByteArray(32, s)));
    }


    /**
     * Checks if the s-component of the signature is canonical (i.e., less than or equal to
     * half the curve order). This is a security measure to prevent transaction malleability.
     *
     * @return {@code true} if the s-value is canonical, {@code false} otherwise.
     */
    public boolean isCanonical() {
        return new BigInteger(1, s.toArrayUnsafe()).compareTo(Sign.HALF_CURVE_ORDER) <= 0;
    }
} 