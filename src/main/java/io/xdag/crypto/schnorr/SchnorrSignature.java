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

import io.xdag.crypto.core.CryptoProvider;
import java.math.BigInteger;
import java.util.Objects;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/**
 * Represents a BIP340 Schnorr signature (64 bytes: 32-byte x-coordinate and 32-byte scalar).
 */
public final class SchnorrSignature {

    /** Size of a Schnorr signature in bytes. */
    public static final int SIGNATURE_SIZE = 64;

    private final Bytes32 r;
    private final Bytes32 s;

    private SchnorrSignature(Bytes32 r, Bytes32 s) {
        this.r = r;
        this.s = s;
    }

    /**
     * Creates a Schnorr signature from its components.
     *
     * @param r the x-only R component (32 bytes)
     * @param s the scalar component (32 bytes)
     * @return a new {@link SchnorrSignature}
     * @throws IllegalArgumentException if components are out of range
     */
    public static SchnorrSignature create(Bytes32 r, Bytes32 s) {
        Objects.requireNonNull(r, "r cannot be null");
        Objects.requireNonNull(s, "s cannot be null");

        BigInteger rInt = r.toUnsignedBigInteger();
        BigInteger fieldPrime = CryptoProvider.getCurve().getCurve().getField().getCharacteristic();
        if (rInt.compareTo(fieldPrime) >= 0) {
            throw new IllegalArgumentException("R component must be less than field prime");
        }

        BigInteger sInt = s.toUnsignedBigInteger();
        if (sInt.signum() <= 0 || sInt.compareTo(CryptoProvider.getCurve().getN()) >= 0) {
            throw new IllegalArgumentException("S component must be in the range [1, n-1]");
        }

        return new SchnorrSignature(r, s);
    }

    /**
     * Parses a Schnorr signature from its 64-byte encoded form (r || s).
     *
     * @param encoded the encoded signature
     * @return the decoded {@link SchnorrSignature}
     */
    public static SchnorrSignature fromBytes(Bytes encoded) {
        Objects.requireNonNull(encoded, "encoded signature cannot be null");
        if (encoded.size() != SIGNATURE_SIZE) {
            throw new IllegalArgumentException("Encoded Schnorr signature must be 64 bytes, got " + encoded.size());
        }

        Bytes32 r = Bytes32.wrap(encoded.slice(0, 32).toArrayUnsafe());
        Bytes32 s = Bytes32.wrap(encoded.slice(32, 32).toArrayUnsafe());
        return create(r, s);
    }

    /**
     * Returns the signature encoded as 64 bytes (r || s).
     *
     * @return encoded signature bytes
     */
    public Bytes toBytes() {
        return Bytes.concatenate(r, s);
    }

    /**
     * Returns the R component as {@link Bytes32}.
     */
    public Bytes32 getR() {
        return r;
    }

    /**
     * Returns the S component as {@link Bytes32}.
     */
    public Bytes32 getS() {
        return s;
    }

    /**
     * Returns the R component as an unsigned {@link BigInteger}.
     */
    public BigInteger getRAsBigInteger() {
        return r.toUnsignedBigInteger();
    }

    /**
     * Returns the S component as an unsigned {@link BigInteger}.
     */
    public BigInteger getSAsBigInteger() {
        return s.toUnsignedBigInteger();
    }
}

