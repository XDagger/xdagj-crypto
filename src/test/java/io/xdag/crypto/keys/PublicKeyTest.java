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

import static org.junit.jupiter.api.Assertions.*;

import io.xdag.crypto.exception.CryptoException;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive tests for PublicKey class functionality.
 * 
 * <p>This test class covers PublicKey creation, validation, format conversion,
 * and address generation to ensure complete test coverage.
 */
class PublicKeyTest {

    private static ECKeyPair testKeyPair;
    private static PublicKey testPublicKey;
    
    @BeforeAll
    static void setUp() throws CryptoException {
        testKeyPair = ECKeyPair.generate();
        testPublicKey = testKeyPair.getPublicKey();
    }

    @Test
    void shouldCreateFromValidCompressedHex() throws CryptoException {
        // Use a known compressed public key (33 bytes = 66 hex chars)
        String compressedHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        PublicKey publicKey = PublicKey.fromHex(compressedHex);
        
        assertNotNull(publicKey);
        assertEquals(compressedHex, publicKey.toUnprefixedHex());
    }

    @Test
    void shouldCreateFromValidCompressedHexWithPrefix() throws CryptoException {
        String compressedHex = "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        PublicKey publicKey = PublicKey.fromHex(compressedHex);
        
        assertNotNull(publicKey);
        assertEquals(compressedHex, publicKey.toHex());
    }

    @Test
    void shouldCreateFromValidUncompressedHex() throws CryptoException {
        // Use a known uncompressed public key (65 bytes = 130 hex chars)
        String uncompressedHex = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
        PublicKey publicKey = PublicKey.fromHex(uncompressedHex);
        
        assertNotNull(publicKey);
    }

    @Test
    void shouldRejectNullHex() {
        CryptoException exception = assertThrows(CryptoException.class, () -> PublicKey.fromHex(null));
        assertEquals("Hex string cannot be null or empty", exception.getMessage());
    }

    @Test
    void shouldRejectEmptyHex() {
        CryptoException exception = assertThrows(CryptoException.class, () -> PublicKey.fromHex(""));
        assertEquals("Hex string cannot be null or empty", exception.getMessage());
    }

    @Test
    void shouldRejectWrongLengthHex() {
        String wrongLengthHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817"; // 64 chars instead of 66
        CryptoException exception = assertThrows(CryptoException.class, () -> PublicKey.fromHex(wrongLengthHex));
        assertEquals("Public key hex must be 66 characters (compressed) or 130 characters (uncompressed)", exception.getMessage());
    }

    @Test
    void shouldRejectInvalidHexCharacters() {
        String invalidHex = "g279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"; // 'g' is invalid
        CryptoException exception = assertThrows(CryptoException.class, () -> PublicKey.fromHex(invalidHex));
        assertEquals("Invalid hex string for public key", exception.getMessage());
    }

    @Test
    void shouldCreateFromValidCompressedBytes() throws CryptoException {
        Bytes compressedBytes = testPublicKey.toCompressedBytes();
        PublicKey recreated = PublicKey.fromBytes(compressedBytes);
        
        assertEquals(testPublicKey, recreated);
    }

    @Test
    void shouldCreateFromValidUncompressedBytes() throws CryptoException {
        Bytes uncompressedBytes = testPublicKey.toUncompressedBytes();
        PublicKey recreated = PublicKey.fromBytes(uncompressedBytes);
        
        assertEquals(testPublicKey, recreated);
    }

    @Test
    void shouldRejectNullBytesObject() {
        CryptoException exception = assertThrows(CryptoException.class, () -> PublicKey.fromBytes((Bytes) null));
        assertEquals("Public key bytes cannot be null", exception.getMessage());
    }

    @Test
    void shouldRejectNullByteArray() {
        CryptoException exception = assertThrows(CryptoException.class, () -> PublicKey.fromBytes((byte[]) null));
        assertEquals("Public key bytes cannot be null", exception.getMessage());
    }

    @Test
    void shouldRejectWrongSizeBytes() {
        byte[] wrongSize = new byte[32]; // Should be 33 or 65
        CryptoException exception = assertThrows(CryptoException.class, () -> PublicKey.fromBytes(wrongSize));
        assertEquals("Public key must be 33 bytes (compressed) or 65 bytes (uncompressed), got 32", exception.getMessage());
    }

    @Test
    void shouldReturnCorrectCompressedFormat() {
        Bytes compressed = testPublicKey.toCompressedBytes();
        assertEquals(33, compressed.size());
        assertTrue(compressed.get(0) == (byte) 0x02 || compressed.get(0) == (byte) 0x03); // Compressed format prefix
    }

    @Test
    void shouldReturnCorrectUncompressedFormat() {
        Bytes uncompressed = testPublicKey.toUncompressedBytes();
        assertEquals(65, uncompressed.size());
        assertEquals((byte) 0x04, uncompressed.get(0)); // Uncompressed format prefix
    }

    @Test
    void shouldDefaultToCompressedFormat() {
        Bytes defaultBytes = testPublicKey.toBytes();
        Bytes compressedBytes = testPublicKey.toCompressedBytes();
        
        assertEquals(compressedBytes, defaultBytes);
    }

    @Test
    void shouldReturnCorrectHexFormats() {
        String hex = testPublicKey.toHex();
        String unprefixedHex = testPublicKey.toUnprefixedHex();
        String uncompressedHex = testPublicKey.toUncompressedHex();
        
        assertTrue(hex.startsWith("0x"));
        assertFalse(unprefixedHex.startsWith("0x"));
        assertEquals("0x" + unprefixedHex, hex);
        assertTrue(uncompressedHex.startsWith("0x"));
        assertEquals(132, uncompressedHex.length()); // 65 bytes * 2 + "0x"
    }

    @Test
    void shouldGenerateAddressesCorrectly() {
        Bytes address = testPublicKey.toAddress();
        Bytes addressCompressed = testPublicKey.toAddress(true);
        Bytes addressUncompressed = testPublicKey.toAddress(false);
        
        assertEquals(addressCompressed, address);
        assertEquals(20, address.size());
        assertEquals(20, addressUncompressed.size());
        assertNotEquals(addressUncompressed, addressCompressed); // Different formats give different addresses
    }

    @Test
    void shouldGenerateBase58AddressesCorrectly() {
        String address = testPublicKey.toBase58Address();
        String addressCompressed = testPublicKey.toBase58Address(true);
        String addressUncompressed = testPublicKey.toBase58Address(false);
        
        assertEquals(addressCompressed, address);
        assertFalse(address.isEmpty());
        assertFalse(addressUncompressed.isEmpty());
        assertNotEquals(addressUncompressed, addressCompressed); // Different formats give different addresses
    }

    @Test
    void shouldReturnIsCompressedTrue() {
        // Our implementation defaults to compressed format
        assertTrue(testPublicKey.isCompressed());
    }

    @Test
    void shouldReturnValidECPoint() {
        assertNotNull(testPublicKey.getPoint());
        assertTrue(testPublicKey.getPoint().isValid());
    }

    @Test
    void shouldHandleEqualsCorrectly() throws CryptoException {
        PublicKey sameKey = PublicKey.fromBytes(testPublicKey.toCompressedBytes());
        PublicKey differentKey = ECKeyPair.generate().getPublicKey();
        
        assertEquals(testPublicKey, testPublicKey);
        assertEquals(sameKey, testPublicKey);
        assertNotEquals(differentKey, testPublicKey);
        assertNotEquals(null, testPublicKey);
        assertNotEquals("not a public key", testPublicKey);
    }

    @Test
    void shouldReturnConsistentHashCode() throws CryptoException {
        PublicKey sameKey = PublicKey.fromBytes(testPublicKey.toCompressedBytes());
        
        assertEquals(sameKey.hashCode(), testPublicKey.hashCode());
    }

    @Test
    void shouldReturnMeaningfulToString() {
        String toString = testPublicKey.toString();
        
        assertTrue(toString.contains("PublicKey{"));
        assertTrue(toString.contains(testPublicKey.toUnprefixedHex()));
    }

    @Test
    void shouldCreateFromPointSuccessfully() {
        PublicKey recreated = PublicKey.fromPoint(testPublicKey.getPoint());
        
        assertEquals(testPublicKey, recreated);
    }

    @Test
    void shouldThrowOnInvalidPoint() {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> PublicKey.fromPoint(null));
        assertInstanceOf(CryptoException.class, exception.getCause());
    }

    @Test
    void shouldRoundTripThroughAllFormats() throws CryptoException {
        // Test round-trip through compressed format
        Bytes compressedBytes = testPublicKey.toCompressedBytes();
        PublicKey fromCompressed = PublicKey.fromBytes(compressedBytes);
        assertEquals(testPublicKey, fromCompressed);
        
        // Test round-trip through uncompressed format
        Bytes uncompressedBytes = testPublicKey.toUncompressedBytes();
        PublicKey fromUncompressed = PublicKey.fromBytes(uncompressedBytes);
        assertEquals(testPublicKey, fromUncompressed);
        
        // Test round-trip through hex
        String hex = testPublicKey.toHex();
        PublicKey fromHex = PublicKey.fromHex(hex);
        assertEquals(testPublicKey, fromHex);
    }
} 