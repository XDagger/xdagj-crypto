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

import static org.junit.jupiter.api.Assertions.*;

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

        assertEquals(expected, Bytes.wrap(actual));
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

        assertEquals(expected, Bytes.wrap(actual));
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

        // The Second hash should be independent of the first
        Bytes expected = Bytes.wrap(Arrays.reverse(HashUtils.doubleSha256(input2).toArray()));
        byte[] actual = digest.sha256Final(input2);

        assertEquals(expected, Bytes.wrap(actual));
    }

    @Test
    void testSha256InitClearsState() throws IOException {
        XdagSha256Digest digest = new XdagSha256Digest();
        Bytes input = Bytes.wrap("test".getBytes(StandardCharsets.UTF_8));
        
        // Update with some data
        digest.sha256Update(input);
        
        // Reset the digest
        digest.sha256Init();
        
        // Finalize should give the same result as a fresh digest
        XdagSha256Digest freshDigest = new XdagSha256Digest();
        
        byte[] actualAfterReset = digest.sha256Final(Bytes.EMPTY);
        byte[] expectedFromFresh = freshDigest.sha256Final(Bytes.EMPTY);
        
        assertArrayEquals(expectedFromFresh, actualAfterReset);
    }

    @Test
    void testMultipleUpdatesAndFinal() throws IOException {
        XdagSha256Digest digest = new XdagSha256Digest();
        Bytes part1 = Bytes.wrap("The ".getBytes(StandardCharsets.UTF_8));
        Bytes part2 = Bytes.wrap("quick ".getBytes(StandardCharsets.UTF_8));
        Bytes part3 = Bytes.wrap("brown fox".getBytes(StandardCharsets.UTF_8));
        Bytes fullInput = Bytes.concatenate(part1, part2, part3);

        // Expected result using all inputs at once
        Bytes expected = Bytes.wrap(Arrays.reverse(HashUtils.doubleSha256(fullInput).toArray()));

        // Update in parts
        digest.sha256Update(part1);
        digest.sha256Update(part2);
        digest.sha256Update(part3);
        byte[] actual = digest.sha256Final(Bytes.EMPTY);

        assertArrayEquals(expected.toArrayUnsafe(), actual);
    }
} 