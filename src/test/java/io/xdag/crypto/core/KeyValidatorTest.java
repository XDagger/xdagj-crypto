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
package io.xdag.crypto.core;

import static org.junit.jupiter.api.Assertions.*;

import io.xdag.crypto.exception.CryptoException;
import java.math.BigInteger;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;

/**
 * Tests for KeyValidator utility functions.
 */
class KeyValidatorTest {

    // CryptoProvider is automatically initialized via static block

    @Test
    void shouldValidatePrivateKeyRange() {
        // Test valid private key
        BigInteger validKey = BigInteger.valueOf(12345);
        assertDoesNotThrow(() -> KeyValidator.validatePrivateKeyRange(validKey));

        // Test null
        CryptoException exception1 = assertThrows(CryptoException.class, () -> KeyValidator.validatePrivateKeyRange(null));
        assertTrue(exception1.getMessage().contains("null"));

        // Test zero
        CryptoException exception2 = assertThrows(CryptoException.class, () -> KeyValidator.validatePrivateKeyRange(BigInteger.ZERO));
        assertTrue(exception2.getMessage().contains("positive"));

        // Test negative
        BigInteger negativeKey = BigInteger.valueOf(-1);
        CryptoException exception3 = assertThrows(CryptoException.class, () -> KeyValidator.validatePrivateKeyRange(negativeKey));
        assertTrue(exception3.getMessage().contains("positive"));

        // Test curve order
        BigInteger curveOrder = CryptoProvider.getCurve().getN();
        CryptoException exception4 = assertThrows(CryptoException.class, () -> KeyValidator.validatePrivateKeyRange(curveOrder));
        assertTrue(exception4.getMessage().contains("curve order"));

        // Test above curve order
        BigInteger aboveCurveOrder = curveOrder.add(BigInteger.ONE);
        CryptoException exception5 = assertThrows(CryptoException.class, () -> KeyValidator.validatePrivateKeyRange(aboveCurveOrder));
        assertTrue(exception5.getMessage().contains("curve order"));
    }

    @Test
    void shouldValidateDerivedKeyRange() {
        assertTrue(KeyValidator.isValidDerivedKeyRange(BigInteger.valueOf(12345)));
        assertFalse(KeyValidator.isValidDerivedKeyRange(null));
        assertFalse(KeyValidator.isValidDerivedKeyRange(BigInteger.ZERO));
        assertFalse(KeyValidator.isValidDerivedKeyRange(CryptoProvider.getCurve().getN()));
    }

    @Test
    void shouldValidateHex32Bytes() {
        // Valid 32-byte hex
        String validHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assertDoesNotThrow(() -> KeyValidator.validateHex32Bytes(validHex, "test field"));

        // Invalid length
        String invalidLengthHex = "0123456789abcdef";
        CryptoException exception1 = assertThrows(CryptoException.class, () -> KeyValidator.validateHex32Bytes(invalidLengthHex, "test field"));
        assertTrue(exception1.getMessage().contains("64 characters"));

        // Invalid characters
        String invalidCharHex = "0123456789abcdefg123456789abcdef0123456789abcdef0123456789abcdef";
        CryptoException exception2 = assertThrows(CryptoException.class, () -> KeyValidator.validateHex32Bytes(invalidCharHex, "test field"));
        assertTrue(exception2.getMessage().contains("invalid characters"));

        // Empty string
        CryptoException exception3 = assertThrows(CryptoException.class, () -> KeyValidator.validateHex32Bytes("", "test field"));
        assertTrue(exception3.getMessage().contains("null or empty"));

        // Null string
        CryptoException exception4 = assertThrows(CryptoException.class, () -> KeyValidator.validateHex32Bytes(null, "test field"));
        assertTrue(exception4.getMessage().contains("null or empty"));
    }

    @Test
    void shouldValidateByteArray() {
        // Valid 32-byte array
        byte[] validBytes = new byte[32];
        assertDoesNotThrow(() -> KeyValidator.validate32Bytes(validBytes, "test field"));

        // Null array
        CryptoException exception1 = assertThrows(CryptoException.class, () -> KeyValidator.validate32Bytes(null, "test field"));
        assertTrue(exception1.getMessage().contains("null"));

        // Wrong size array
        byte[] wrongSize = new byte[31];
        CryptoException exception2 = assertThrows(CryptoException.class, () -> KeyValidator.validate32Bytes(wrongSize, "test field"));
        assertTrue(exception2.getMessage().contains("32 bytes"));
    }

    @Test
    void shouldValidateBytes32Object() {
        // Valid Bytes32
        Bytes32 validBytes32 = Bytes32.ZERO;
        assertDoesNotThrow(() -> KeyValidator.validateBytes32NotNull(validBytes32, "test field"));

        // Null Bytes32
        CryptoException exception1 = assertThrows(CryptoException.class, () -> KeyValidator.validateBytes32NotNull(null, "test field"));
        assertTrue(exception1.getMessage().contains("null"));
    }
} 