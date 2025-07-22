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

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.util.Arrays;
import org.junit.jupiter.api.Test;

class XdagSha256DigestTest {

    @Test
    void shouldCalculateSha256FinalWithSingleInput() throws IOException {
        XdagSha256Digest digest = new XdagSha256Digest();
        Bytes input = Bytes.wrap("hello world".getBytes(StandardCharsets.UTF_8));

        // Manually calculate the expected result: reverse(sha256(sha256("hello world")))
        Bytes expected = Bytes.wrap(Arrays.reverse(HashUtils.doubleSha256(input).toArray()));

        byte[] actual = digest.sha256Final(input);

        assertThat(Bytes.wrap(actual)).isEqualTo(expected);
    }

    @Test
    void testSha256UpdateAndFinal() throws IOException {
        XdagSha256Digest digest = new XdagSha256Digest();
        Bytes input1 = Bytes.wrap("hello ".getBytes(StandardCharsets.UTF_8));
        Bytes input2 = Bytes.wrap("world".getBytes(StandardCharsets.UTF_8));
        Bytes fullInput = Bytes.concatenate(input1, input2);

        // Manually calculate the expected result
        Bytes expected = Bytes.wrap(Arrays.reverse(HashUtils.doubleSha256(fullInput).toArray()));

        digest.sha256Update(input1);
        digest.sha256Update(input2);
        byte[] actual = digest.sha256Final(Bytes.EMPTY); // Finalize with empty bytes

        assertThat(Bytes.wrap(actual)).isEqualTo(expected);
    }

    @Test
    void testSha256Init_resetsState() throws IOException {
        XdagSha256Digest digest = new XdagSha256Digest();
        Bytes input1 = Bytes.wrap("first pass".getBytes(StandardCharsets.UTF_8));
        Bytes input2 = Bytes.wrap("second pass".getBytes(StandardCharsets.UTF_8));

        // First hash
        digest.sha256Final(input1);

        // Reset the digest
        digest.sha256Init();

        // Second hash, should be independent of the first
        Bytes expected = Bytes.wrap(Arrays.reverse(HashUtils.doubleSha256(input2).toArray()));
        byte[] actual = digest.sha256Final(input2);

        assertThat(Bytes.wrap(actual)).isEqualTo(expected);
    }

    @Test
    void testCopyConstructor_isolatesState() throws IOException {
        XdagSha256Digest digest1 = new XdagSha256Digest();
        Bytes input1 = Bytes.wrap("hello".getBytes(StandardCharsets.UTF_8));
        digest1.sha256Update(input1);

        // Create a copy *after* updating the original
        XdagSha256Digest digest2 = new XdagSha256Digest(digest1);

        Bytes input2 = Bytes.wrap(" world".getBytes(StandardCharsets.UTF_8));
        digest2.sha256Update(input2);

        // Finalize both digests. They should be different.
        Bytes fullInput = Bytes.wrap("hello world".getBytes(StandardCharsets.UTF_8));
        Bytes expectedDigest2Result = Bytes.wrap(Arrays.reverse(HashUtils.doubleSha256(fullInput).toArray()));
        assertThat(Bytes.wrap(digest2.sha256Final(Bytes.EMPTY))).isEqualTo(expectedDigest2Result);

        // The original digest should remain unchanged by the update to the copy
        Bytes expectedDigest1Result = Bytes.wrap(Arrays.reverse(HashUtils.doubleSha256(input1).toArray()));
        assertThat(Bytes.wrap(digest1.sha256Final(Bytes.EMPTY))).isEqualTo(expectedDigest1Result);
    }

    @Test
    void testGetState_isDeterministic() throws IOException {
        XdagSha256Digest digest1 = new XdagSha256Digest();
        XdagSha256Digest digest2 = new XdagSha256Digest();
        Bytes input = Bytes.wrap("some consistent input data".getBytes(StandardCharsets.UTF_8));

        digest1.sha256Update(input);
        byte[] state1 = digest1.getState();

        digest2.sha256Update(input);
        byte[] state2 = digest2.getState();

        assertThat(state1).isNotNull().hasSize(32);
        assertThat(state1).isEqualTo(state2);
    }
} 