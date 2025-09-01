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
package io.xdag.crypto.hash;

import java.io.IOException;
import java.nio.ByteBuffer;
import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.io.DigestOutputStream;
import org.bouncycastle.util.Arrays;

/**
 * A custom SHA-256 digest implementation tailored for XDAG's specific hashing requirements.
 * 
 * <p>This implementation provides XDAG-specific hash behavior including
 * - Double SHA-256 hashing (hash of hash)
 * - Final byte reversal for endianness compatibility
 * - State extraction for interoperability with C implementations
 * 
 * <p>This class wraps Bouncy Castle's SHA256Digest to provide the exact
 * hash semantics required by the XDAG blockchain protocol.
 */
public class XdagSha256Digest {

    private SHA256Digest sha256Digest;
    private DigestOutputStream outputStream;

    /**
     * Default constructor that initializes the SHA-256 digest.
     */
    public XdagSha256Digest() {
        sha256Init();
    }

    /**
     * Copy constructor.
     * @param other The XdagSha256Digest instance to copy from.
     */
    public XdagSha256Digest(XdagSha256Digest other) {
        sha256Digest = new SHA256Digest(other.sha256Digest);
        outputStream = new DigestOutputStream(sha256Digest);
    }

    /**
     * Initializes or resets the SHA-256 digest and its output stream.
     */
    public void sha256Init() {
        sha256Digest = new SHA256Digest();
        outputStream = new DigestOutputStream(sha256Digest);
    }

    /**
     * Updates the digest with the given input bytes.
     * @param in Input bytes to update the digest with.
     * @throws IOException if an I/O error occurs.
     */
    public void sha256Update(Bytes in) throws IOException {
        outputStream.write(in.toArray());
    }

    /**
     * Finalizes the hash calculation by performing a double SHA-256 and reversing the result.
     * @param in The final input bytes to include in the hash.
     * @return A 32-byte array representing the reversed double SHA-256 hash.
     * @throws IOException if an I/O error occurs.
     */
    public byte[] sha256Final(Bytes in) throws IOException {
        outputStream.write(in.toArray());
        byte[] hash = outputStream.getDigest();
        sha256Digest.reset();
        outputStream.write(hash);
        byte[] origin = outputStream.getDigest();
        return Arrays.reverse(origin);
    }

    /**
     * Gets the internal state of the SHA-256 digest for interoperability with C implementations.
     * This method extracts a 32-byte portion of the encoded state and adjusts its endianness.
     * @return A 32-byte state array with corrected endianness.
     */
    public byte[] getState() {
        byte[] encodedState = sha256Digest.getEncodedState();
        byte[] state = new byte[32];
        System.arraycopy(encodedState, encodedState.length - 32 - 4, state, 0, 32);

        ByteBuffer buffer = ByteBuffer.wrap(state);
        for (int i = 0; i < 8; i++) {
            int original = buffer.getInt(i * 4);
            buffer.putInt(i * 4, Integer.reverseBytes(original));
        }
        return buffer.array();
    }
}
