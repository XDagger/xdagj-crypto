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
import java.util.Objects;
import lombok.Getter;
import org.apache.tuweni.bytes.Bytes32;

/**
 * Represents an ECDSA signature with recovery capability.
 * 
 * <p>This class encapsulates the three components of an ECDSA signature:
 * <ul>
 *   <li><strong>r</strong> - The r component of the signature</li>
 *   <li><strong>s</strong> - The s component of the signature</li>
 *   <li><strong>v</strong> - The recovery ID (with offset)</li>
 * </ul>
 * 
 * <p>The signature follows Bitcoin's canonical format where s-values are normalized
 * to the lower half of the curve order to prevent signature malleability.
 * 
 * <p>This class is immutable and thread-safe.
 * 
 * @see Signer
 */
@Getter
public final class Signature {

    /** The recovery ID offset used in ECDSA signatures. */
    public static final int RECOVERY_ID_OFFSET = 27;

  /**
   *  Gets the recovery ID with offset.
   */
  private final byte v;

  /**
   *  Gets the r component of the signature.
   */
  private final BigInteger r;

  /**
   *  Gets the s component of the signature.
   */
  private final BigInteger s;

    /**
     * Creates a new Signature instance.
     * 
     * @param v the recovery ID (with offset)
     * @param r the r component of the signature
     * @param s the s component of the signature
     */
    public Signature(byte v, BigInteger r, BigInteger s) {
        this.v = v;
        this.r = Objects.requireNonNull(r, "r cannot be null");
        this.s = Objects.requireNonNull(s, "s cannot be null");
    }

    /**
     * Creates a Signature from byte components.
     * 
     * @param v the recovery ID (with offset)
     * @param r the r component as 32-byte array
     * @param s the s component as 32-byte array
     * @return a new Signature instance
     */
    public static Signature of(byte v, Bytes32 r, Bytes32 s) {
        return new Signature(v, 
            new BigInteger(1, r.toArrayUnsafe()),
            new BigInteger(1, s.toArrayUnsafe()));
    }

  /**
     * Gets the recovery ID without offset.
     * 
     * @return the recovery ID (0 or 1)
     */
    public int getRecoveryId() {
        return v - RECOVERY_ID_OFFSET;
    }

  /**
     * Gets the r component as a 32-byte array.
     * 
     * @return the r component as Bytes32
     */
    public Bytes32 getRBytes() {
        return Bytes32.leftPad(org.apache.tuweni.bytes.Bytes.of(r.toByteArray()));
    }

    /**
     * Gets the s component as a 32-byte array.
     * 
     * @return the s component as Bytes32
     */
    public Bytes32 getSBytes() {
        return Bytes32.leftPad(org.apache.tuweni.bytes.Bytes.of(s.toByteArray()));
    }

    /**
     * Checks if this signature is canonical (s-value is in lower half of curve order).
     * 
     * @return true if the signature is canonical
     */
    public boolean isCanonical() {
        return s.compareTo(Signer.HALF_CURVE_ORDER) <= 0;
    }

    /**
     * Converts this signature to DER format.
     * 
     * @return DER-encoded signature bytes
     */
    public byte[] toDER() {
        // DER encoding implementation
        byte[] rBytes = r.toByteArray();
        byte[] sBytes = s.toByteArray();
        
        int totalLength = 4 + rBytes.length + sBytes.length;
        byte[] result = new byte[totalLength + 2];
        
        result[0] = 0x30; // SEQUENCE
        result[1] = (byte) totalLength;
        result[2] = 0x02; // INTEGER (r)
        result[3] = (byte) rBytes.length;
        System.arraycopy(rBytes, 0, result, 4, rBytes.length);
        
        int sOffset = 4 + rBytes.length;
        result[sOffset] = 0x02; // INTEGER (s)
        result[sOffset + 1] = (byte) sBytes.length;
        System.arraycopy(sBytes, 0, result, sOffset + 2, sBytes.length);
        
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof Signature other)) return false;

      return v == other.v &&
               Objects.equals(r, other.r) && 
               Objects.equals(s, other.s);
    }

    @Override
    public int hashCode() {
        return Objects.hash(v, r, s);
    }

    @Override
    public String toString() {
        return String.format("Signature{v=%d, r=%s, s=%s}", v, r.toString(16), s.toString(16));
    }
} 