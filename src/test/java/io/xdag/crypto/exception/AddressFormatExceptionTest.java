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
package io.xdag.crypto.exception;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class AddressFormatExceptionTest {

    @Test
    void testAddressFormatExceptionConstructors() {
        AddressFormatException e1 = new AddressFormatException();
        assertNull(e1.getMessage());

        String msg = "Invalid address";
        AddressFormatException e2 = new AddressFormatException(msg);
        assertEquals(msg, e2.getMessage());
    }

    @Test
    void testInvalidCharacter() {
        char c = 'Z';
        int pos = 10;
        AddressFormatException.InvalidCharacter e = new AddressFormatException.InvalidCharacter(c, pos);
        assertEquals(c, e.character);
        assertEquals(pos, e.position);
        assertTrue(e.getMessage().contains(String.valueOf(c)));
        assertTrue(e.getMessage().contains(String.valueOf(pos)));
    }

    @Test
    void testInvalidDataLength() {
        AddressFormatException.InvalidDataLength e1 = new AddressFormatException.InvalidDataLength();
        assertNull(e1.getMessage());

        String msg = "Invalid data length";
        AddressFormatException.InvalidDataLength e2 = new AddressFormatException.InvalidDataLength(msg);
        assertEquals(msg, e2.getMessage());
    }

    @Test
    void testInvalidChecksum() {
        AddressFormatException.InvalidChecksum e1 = new AddressFormatException.InvalidChecksum();
        assertEquals("Checksum does not validate", e1.getMessage());

        String msg = "Custom checksum message";
        AddressFormatException.InvalidChecksum e2 = new AddressFormatException.InvalidChecksum(msg);
        assertEquals(msg, e2.getMessage());
    }
} 