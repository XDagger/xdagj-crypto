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

import io.xdag.crypto.core.CryptoProvider;
import java.math.BigInteger;
import java.util.Objects;
import lombok.Getter;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.bytes.MutableBytes;
import org.apache.tuweni.units.bigints.UInt256;

/**
 * Represents an ECDSA signature with recovery capability for XDAG cryptographic operations.
 * 
 * <p>This class encapsulates the three parts of an ECDSA signature:
 * <ul>
 *   <li><strong>r</strong> - The r component of the signature</li>
 *   <li><strong>s</strong> - The s component of the signature</li>
 *   <li><strong>recId</strong> - The recovery ID (0 or 1)</li>
 * </ul>
 * 
 * <p>The signature follows Bitcoin's canonical format where s-values are normalized
 * to the lower half of the curve order to prevent signature malleability.
 * 
 * <p>This implementation is compatible with Hyperledger Besu's SECPSignature format
 * while providing additional XDAG-specific functionality.
 * 
 * <p>This class is immutable and thread-safe.
 * 
 * @see Signer
 */
public final class Signature {

    /** The constant bytes required for encoded signature. */
    public static final int BYTES_REQUIRED = 65;

    /**
     * The recovery id to reconstruct the public key used to create the signature.
     *
     * <p>The recId is an index from 0 to 1 that indicates which of the 2 possible keys is the
     * correct one. Because the key recovery operation yields multiple potential keys, the correct key
     * must either be stored alongside the signature, or you must be willing to try each recId in turn
     * until you find one that outputs the key you are expecting.
     *
     */
    @Getter
    private final byte recId;

    @Getter
    private final BigInteger r;

    @Getter
    private final BigInteger s;

    private volatile Bytes encodedCache;

    /**
     * Instantiates a new Signature.
     *
     * @param r the r component
     * @param s the s component  
     * @param recId the recovery id (0 or 1)
     */
    public Signature(final BigInteger r, final BigInteger s, final byte recId) {
        this.r = r;
        this.s = s;
        this.recId = recId;
    }

    /**
     * Creates a new signature object given its parameters.
     *
     * @param r the 'r' part of the signature.
     * @param s the 's' part of the signature.
     * @param recId the recovery id part of the signature (0 or 1).
     * @return the created {@link Signature} object.
     * @throws NullPointerException if {@code r} or {@code s} are {@code null}.
     * @throws IllegalArgumentException if any argument is invalid.
     */
    public static Signature create(final BigInteger r, final BigInteger s, final byte recId) {
        Objects.requireNonNull(r, "r cannot be null");
        Objects.requireNonNull(s, "s cannot be null");
        
        BigInteger curveOrder = CryptoProvider.getCurve().getN();
        checkInBounds("r", r, curveOrder);
        checkInBounds("s", s, curveOrder);
        
        if (recId != 0 && recId != 1) {
            throw new IllegalArgumentException(
                "Invalid 'recId' value, should be 0 or 1 but got " + recId);
        }
        
        return new Signature(r, s, recId);
    }

    private static void checkInBounds(
        final String name, final BigInteger i, final BigInteger curveOrder) {
        if (i.compareTo(BigInteger.ONE) < 0) {
            throw new IllegalArgumentException(
                String.format("Invalid '%s' value, should be >= 1 but got %s", name, i));
        }

        if (i.compareTo(curveOrder) >= 0) {
            throw new IllegalArgumentException(
                String.format("Invalid '%s' value, should be < %s but got %s", name, i, curveOrder));
        }
    }

    /**
     * Decode signature from bytes.
     *
     * @param bytes the 65-byte encoded signature
     * @return the decoded signature
     * @throws IllegalArgumentException if bytes' length is not 65
     */
    public static Signature decode(final Bytes bytes) {
        if (bytes.size() != BYTES_REQUIRED) {
            throw new IllegalArgumentException(
                String.format("encoded ECDSA signature must be 65 bytes long, got %s", bytes.size()));
        }

        final BigInteger r = bytes.slice(0, 32).toUnsignedBigInteger();
        final BigInteger s = bytes.slice(32, 32).toUnsignedBigInteger();
        final byte recId = bytes.get(64);
        return Signature.create(r, s, recId);
    }

    /**
     * Decode signature from a byte array.
     *
     * @param bytes the 65-byte encoded signature
     * @return the decoded signature
     */
    public static Signature decode(final byte[] bytes) {
        return decode(Bytes.wrap(bytes));
    }

    /**
     * Returns the encoded bytes of this signature.
     *
     * @return the 65-byte encoded signature
     */
    public Bytes encodedBytes() {
        if (encodedCache == null) {
            synchronized (this) {
                if (encodedCache == null) {
                    encodedCache = _encodedBytes();
                }
            }
        }
        return encodedCache;
    }

    private Bytes _encodedBytes() {
        final MutableBytes bytes = MutableBytes.create(BYTES_REQUIRED);
        UInt256.valueOf(r).copyTo(bytes, 0);
        UInt256.valueOf(s).copyTo(bytes, 32);
        bytes.set(64, recId);
        return bytes;
    }

    /**
     * Gets the r component as a 32-byte array.
     * 
     * @return the r component as Bytes32
     */
    public Bytes32 getRBytes() {
        return toBytes32(r);
    }

    /**
     * Gets the s component as a 32-byte array.
     * 
     * @return the s component as Bytes32
     */
    public Bytes32 getSBytes() {
        return toBytes32(s);
    }

    /**
     * Converts a BigInteger to a 32-byte array, handling the sign byte correctly.
     */
    private static Bytes32 toBytes32(BigInteger value) {
        byte[] bytes = value.toByteArray();
        
        if (bytes.length == 32) {
            return Bytes32.wrap(bytes);
        } else if (bytes.length == 33 && bytes[0] == 0) {
            // Remove leading zero bytes
            byte[] trimmed = new byte[32];
            System.arraycopy(bytes, 1, trimmed, 0, 32);
            return Bytes32.wrap(trimmed);
        } else if (bytes.length < 32) {
            // Pad with leading zeros
            byte[] padded = new byte[32];
            System.arraycopy(bytes, 0, padded, 32 - bytes.length, bytes.length);
            return Bytes32.wrap(padded);
        } else {
            throw new IllegalArgumentException("BigInteger too large for 32 bytes");
        }
    }

    /**
     * Checks if this signature is canonical (s-value is in the lower half of curve order).
     * 
     * @return true if the signature is canonical
     */
    public boolean isCanonical() {
        BigInteger halfCurveOrder = CryptoProvider.getCurve().getN().shiftRight(1);
        return s.compareTo(halfCurveOrder) <= 0;
    }

    @Override
    public boolean equals(final Object other) {
        if (!(other instanceof Signature that)) {
            return false;
        }

      return this.r.equals(that.r) && this.s.equals(that.s) && this.recId == that.recId;
    }

    @Override
    public int hashCode() {
        return Objects.hash(r, s, recId);
    }

    @Override
    public String toString() {
      return "Signature" + "{"
          + "r=" + r.toString(16) + ", "
          + "s=" + s.toString(16) + ", "
          + "recId=" + recId
          + "}";
    }
} 