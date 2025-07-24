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

import io.xdag.crypto.core.CryptoProvider;
import io.xdag.crypto.exception.CryptoException;
import java.math.BigInteger;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive tests for Signature class functionality.
 * 
 * <p>This test class covers Signature creation, validation, format conversion,
 * encoding/decoding, and verification to ensure complete test coverage.
 */
class SignatureTest {

    private static ECKeyPair testKeyPair;
    private Signature testSignature;
    
    @BeforeAll
    static void setUp() throws CryptoException {
        testKeyPair = ECKeyPair.generate();
    }
    
    @BeforeEach
    void setUpEach() {
        Bytes32 messageHash = Bytes32.fromHexString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        testSignature = Signer.sign(messageHash, testKeyPair.getPrivateKey());
    }

    @Test
    void shouldReturnValidComponentRanges() {
        assertTrue(testSignature.getRecId() >= 0);
        assertTrue(testSignature.getRecId() <= 1);
        assertTrue(testSignature.getR().signum() > 0);
        assertTrue(testSignature.getS().signum() > 0);
    }

    @Test
    void shouldCreateSignatureWithCreateMethod() {
        BigInteger r = BigInteger.valueOf(123);
        BigInteger s = BigInteger.valueOf(456);
        byte recId = 0;
        
        Signature signature = Signature.create(r, s, recId);
        
        assertEquals(r, signature.getR());
        assertEquals(s, signature.getS());
        assertEquals(recId, signature.getRecId());
    }

    @Test
    void shouldThrowOnInvalidRecId() {
        BigInteger r = BigInteger.valueOf(123);
        BigInteger s = BigInteger.valueOf(456);
        byte invalidRecId = 2;
        
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, 
            () -> Signature.create(r, s, invalidRecId));
        assertTrue(exception.getMessage().contains("Invalid 'recId' value"));
    }

    @Test
    void shouldThrowOnNullComponents() {
        BigInteger r = BigInteger.valueOf(123);
        BigInteger s = BigInteger.valueOf(456);
        
        assertThrows(NullPointerException.class, () -> Signature.create(null, s, (byte) 0));
        assertThrows(NullPointerException.class, () -> Signature.create(r, null, (byte) 0));
    }

    @Test
    void shouldValidateCanonicalSignatures() {
        assertTrue(testSignature.isCanonical());
    }

    @Test
    void shouldEncodeAndDecodeCorrectly() {
        Bytes encoded = testSignature.encodedBytes();
        assertEquals(65, encoded.size());
        
        Signature decoded = Signature.decode(encoded);
        assertEquals(testSignature, decoded);
    }

    @Test
    void shouldDecodeFromByteArray() {
        Bytes encoded = testSignature.encodedBytes();
        byte[] encodedArray = encoded.toArrayUnsafe();
        
        Signature decoded = Signature.decode(encodedArray);
        assertEquals(testSignature, decoded);
    }

    @Test
    void shouldThrowOnInvalidEncodedLength() {
        byte[] invalidLength = new byte[64]; // Should be 65
        
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, 
            () -> Signature.decode(invalidLength));
        assertTrue(exception.getMessage().contains("must be 65 bytes long"));
    }

    @Test
    void shouldCacheEncodedBytes() {
        Bytes encoded1 = testSignature.encodedBytes();
        Bytes encoded2 = testSignature.encodedBytes();
        
        assertSame(encoded1, encoded2); // Should return same instance due to caching
    }

    @Test
    void shouldReturnCorrectByteRepresentations() {
        Bytes32 rBytes = testSignature.getRBytes();
        Bytes32 sBytes = testSignature.getSBytes();
        
        assertEquals(32, rBytes.size());
        assertEquals(32, sBytes.size());
        
        // Verify round-trip
        assertEquals(testSignature.getR(), new BigInteger(1, rBytes.toArrayUnsafe()));
        assertEquals(testSignature.getS(), new BigInteger(1, sBytes.toArrayUnsafe()));
    }



    @Test
    void shouldHandleEqualsCorrectly() {
        BigInteger r = testSignature.getR();
        BigInteger s = testSignature.getS();
        byte recId = testSignature.getRecId();
        
        Signature sameSignature = Signature.create(r, s, recId);
        
        assertEquals(testSignature, testSignature);
        assertEquals(sameSignature, testSignature);
        
        // Test different signatures
        Signature differentSignature = Signature.create(BigInteger.valueOf(1), BigInteger.valueOf(2), (byte) 0);
        assertNotEquals(differentSignature, testSignature);
        assertNotEquals(null, testSignature);
        assertNotEquals("not a signature", testSignature);
    }

    @Test
    void shouldReturnConsistentHashCode() {
        BigInteger r = testSignature.getR();
        BigInteger s = testSignature.getS();
        byte recId = testSignature.getRecId();
        
        Signature sameSignature = Signature.create(r, s, recId);
        assertEquals(sameSignature.hashCode(), testSignature.hashCode());
    }

    @Test
    void shouldReturnMeaningfulToString() {
        String toString = testSignature.toString();
        assertTrue(toString.contains("Signature{"));
        assertTrue(toString.contains("r="));
        assertTrue(toString.contains("s="));
        assertTrue(toString.contains("recId="));
    }

    @Test
    void shouldValidateSignatureProperties() throws CryptoException {
        assertNotNull(testSignature);
        assertTrue(testSignature.isCanonical());
        
        // Test recovery
        Bytes32 messageHash = Bytes32.fromHexString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        PublicKey recoveredKey = Signer.recoverPublicKey(messageHash, testSignature);
        assertEquals(testKeyPair.getPublicKey(), recoveredKey);
    }

    @Test
    void shouldVerifySignature() {
        Bytes32 messageHash = Bytes32.fromHexString("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        assertTrue(Signer.verify(messageHash, testSignature, testKeyPair.getPublicKey()));
        
        // Test with wrong message
        Bytes32 wrongMessageHash = Bytes32.fromHexString("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890");
        assertFalse(Signer.verify(wrongMessageHash, testSignature, testKeyPair.getPublicKey()));
    }

    @Test
    void shouldRoundTripThroughAllFormats() {
        // Test encode/decode round-trip
        Bytes encoded = testSignature.encodedBytes();
        Signature decoded = Signature.decode(encoded);
        assertEquals(testSignature, decoded);
        
        // Test that decoded signature also encodes correctly
        Bytes reencoded = decoded.encodedBytes();
        assertEquals(encoded, reencoded);
    }

    @Test
    void shouldBeCompatibleWithBesuFormat() {
        // Test that our 65-byte format matches expected structure
        Bytes encoded = testSignature.encodedBytes();
        assertEquals(65, encoded.size());
        
        // First 32 bytes should be r
        BigInteger r = encoded.slice(0, 32).toUnsignedBigInteger();
        assertEquals(testSignature.getR(), r);
        
        // Next 32 bytes should be s  
        BigInteger s = encoded.slice(32, 32).toUnsignedBigInteger();
        assertEquals(testSignature.getS(), s);
        
        // Last byte should be recId
        byte recId = encoded.get(64);
        assertEquals(testSignature.getRecId(), recId);
    }
} 