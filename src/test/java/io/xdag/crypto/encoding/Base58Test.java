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
package io.xdag.crypto.encoding;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.xdag.crypto.core.CryptoProvider;
import io.xdag.crypto.exception.AddressFormatException;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

public class Base58Test {

    @Test
    void testEncodeDecode() {
        byte[] testBytes = "Hello World".getBytes();
        String encoded = Base58.encode(testBytes);
        assertEquals("JxF12TrwUP45BMd", encoded);
        assertArrayEquals(testBytes, Base58.decodeToArray(encoded));
    }

    @Test
    void testEncodeDecodeBytes() {
        Bytes testBytes = Bytes.wrap("Hello World".getBytes());
        String encoded = Base58.encode(testBytes);
        assertEquals("JxF12TrwUP45BMd", encoded);
        assertEquals(testBytes, Base58.decode(encoded));
    }

    @Test
    void testEncodeDecodeCheck() {
        byte[] testBytes = CryptoProvider.getRandomBytes(20); // Example payload
        String encoded = Base58.encodeCheck(testBytes);
        assertArrayEquals(testBytes, Base58.decodeCheckToArray(encoded));
    }

    @Test
    void testEncodeDecodeCheckBytes() {
        Bytes testBytes = Bytes.wrap(CryptoProvider.getRandomBytes(20));
        String encoded = Base58.encodeCheck(testBytes);
        assertEquals(testBytes, Base58.decodeCheck(encoded));
    }

    @Test
    void testDecodeInvalidCharacter() {
        assertThrows(AddressFormatException.InvalidCharacter.class, () -> Base58.decode("JxF12TrwUP45BMdO")); // Contains 'O'
    }

    @Test
    void testDecodeCheckInvalidChecksum() {
        String validBase58 = "JxF12TrwUP45BMd"; // Valid base58, but not a valid check encoding
        assertThrows(AddressFormatException.InvalidChecksum.class, () -> Base58.decodeCheck(validBase58));
    }
    
    @Test
    void testIsValid() {
        assertTrue(Base58.isValid("JxF12TrwUP45BMd"));
        assertTrue(!Base58.isValid("JxF12TrwUP45BMdO"));
    }
} 