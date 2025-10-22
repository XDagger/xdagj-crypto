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
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

/**
 * Test for buffer underflow vulnerability in XdagSha256Digest.getState().
 *
 * <p>The getState() method has a potential buffer underflow when calculating:
 * encodedState.length - 32 - 4
 *
 * <p>If encodedState.length < 36, this results in a negative source position
 * for System.arraycopy, causing ArrayIndexOutOfBoundsException.
 */
public class XdagSha256DigestStateTest {

    @Test
    void shouldHandleGetStateAfterInitialization() {
        XdagSha256Digest digest = new XdagSha256Digest();

        // Try to get state immediately after initialization
        // This should work or throw a proper exception, not an ArrayIndexOutOfBoundsException
        assertDoesNotThrow(() -> {
            byte[] state = digest.getState();
            assertNotNull(state);
            assertEquals(32, state.length, "State should be 32 bytes");
        }, "getState() should not throw ArrayIndexOutOfBoundsException");
    }

    @Test
    void shouldHandleGetStateAfterUpdate() throws IOException {
        XdagSha256Digest digest = new XdagSha256Digest();

        // Update with some data
        digest.sha256Update(Bytes.fromHexString("0x0123456789abcdef"));

        // Get state should work
        assertDoesNotThrow(() -> {
            byte[] state = digest.getState();
            assertNotNull(state);
            assertEquals(32, state.length, "State should be 32 bytes");
        }, "getState() should not throw ArrayIndexOutOfBoundsException after update");
    }

    @Test
    void shouldHandleGetStateAfterReset() {
        XdagSha256Digest digest = new XdagSha256Digest();

        // Reset/init
        digest.sha256Init();

        // Get state after reset
        assertDoesNotThrow(() -> {
            byte[] state = digest.getState();
            assertNotNull(state);
            assertEquals(32, state.length, "State should be 32 bytes");
        }, "getState() should not throw ArrayIndexOutOfBoundsException after reset");
    }

    @Test
    void shouldHandleGetStateMultipleTimes() {
        XdagSha256Digest digest = new XdagSha256Digest();

        // Call getState multiple times
        assertDoesNotThrow(() -> {
            byte[] state1 = digest.getState();
            byte[] state2 = digest.getState();

            assertNotNull(state1);
            assertNotNull(state2);
            assertEquals(32, state1.length);
            assertEquals(32, state2.length);

            // States should be identical since digest hasn't changed
            assertArrayEquals(state1, state2, "Multiple getState() calls should return same state");
        });
    }

    @Test
    void shouldHandleGetStateFromCopyConstructor() {
        XdagSha256Digest original = new XdagSha256Digest();
        XdagSha256Digest copy = new XdagSha256Digest(original);

        // Get state from copied digest
        assertDoesNotThrow(() -> {
            byte[] state = copy.getState();
            assertNotNull(state);
            assertEquals(32, state.length);
        }, "getState() should work on digest created from copy constructor");
    }
}
