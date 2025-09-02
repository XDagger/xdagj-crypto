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

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

public class AddressFormatExceptionTest {

    @Test
    void testAddressFormatExceptionConstructors() {
        // Test default constructor
        AddressFormatException e1 = new AddressFormatException();
        assertEquals("Invalid address format", e1.getMessage());
        assertNull(e1.getCause());

        // Test message constructor
        String msg = "Custom error message";
        AddressFormatException e2 = new AddressFormatException(msg);
        assertEquals(msg, e2.getMessage());
        assertNull(e2.getCause());

        // Test message and cause constructor
        RuntimeException cause = new RuntimeException("root cause");
        AddressFormatException e3 = new AddressFormatException(msg, cause);
        assertEquals(msg, e3.getMessage());
        assertEquals(cause, e3.getCause());

        // Test cause constructor
        AddressFormatException e4 = new AddressFormatException(cause);
        assertEquals(cause, e4.getCause());
    }

    @Test
    void testInvalidCharacterFactoryMethod() {
        char c = 'O';
        int pos = 5;
        AddressFormatException e = AddressFormatException.invalidCharacter(c, pos);
        
        assertEquals("Invalid character 'O' at position 5", e.getMessage());
        assertNull(e.getCause());
        assertInstanceOf(AddressFormatException.class, e);
    }

    @Test
    void testInvalidDataLengthFactoryMethod() {
        String message = "too short";
        AddressFormatException e = AddressFormatException.invalidDataLength(message);
        
        assertEquals("Invalid data length: too short", e.getMessage());
        assertNull(e.getCause());
        assertInstanceOf(AddressFormatException.class, e);
    }

    @Test
    void testInvalidChecksumFactoryMethods() {
        // Test default checksum error
        AddressFormatException e1 = AddressFormatException.invalidChecksum();
        assertEquals("Checksum validation failed", e1.getMessage());
        assertNull(e1.getCause());

        // Test custom checksum error message
        String message = "hash mismatch";
        AddressFormatException e2 = AddressFormatException.invalidChecksum(message);
        assertEquals("Checksum validation failed: hash mismatch", e2.getMessage());
        assertNull(e2.getCause());
    }

    @Test
    void testExceptionInheritance() {
        AddressFormatException e = new AddressFormatException("test");
        
        // Should inherit from CryptoException
        assertInstanceOf(CryptoException.class, e);
        assertInstanceOf(Exception.class, e);
        
        // Verify it's a checked exception (not RuntimeException)
        assertNotNull(e.getMessage());
        assertTrue(CryptoException.class.isAssignableFrom(AddressFormatException.class));
    }

    @Test
    void testFactoryMethodsReturnCorrectType() {
        AddressFormatException e1 = AddressFormatException.invalidCharacter('X', 1);
        AddressFormatException e2 = AddressFormatException.invalidDataLength("test");
        AddressFormatException e3 = AddressFormatException.invalidChecksum();
        AddressFormatException e4 = AddressFormatException.invalidChecksum("test");

        assertSame(AddressFormatException.class, e1.getClass());
        assertSame(AddressFormatException.class, e2.getClass());
        assertSame(AddressFormatException.class, e3.getClass());
        assertSame(AddressFormatException.class, e4.getClass());
    }
} 