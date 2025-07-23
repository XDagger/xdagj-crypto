package io.xdag.crypto.keys;

import static org.junit.jupiter.api.Assertions.*;

import io.xdag.crypto.core.CryptoProvider;
import io.xdag.crypto.exception.CryptoException;
import java.math.BigInteger;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive tests for PrivateKey class functionality.
 * 
 * <p>This test class covers PrivateKey creation, validation, format conversion,
 * and key derivation to ensure complete test coverage.
 */
class PrivateKeyTest {

    private static PrivateKey testPrivateKey;
    
    @BeforeAll
    static void setUp() throws CryptoException {
        testPrivateKey = PrivateKey.generateRandom();
    }

    @Test
    void shouldGenerateRandomPrivateKeys() throws CryptoException {
        PrivateKey key1 = PrivateKey.generateRandom();
        PrivateKey key2 = PrivateKey.generateRandom();
        
        assertNotNull(key1);
        assertNotNull(key2);
        assertNotEquals(key2, key1); // Should be very unlikely to generate same key
        
        // Both keys should be in valid range
        assertTrue(key1.toBigInteger().signum() > 0);
        assertTrue(key2.toBigInteger().signum() > 0);
        assertTrue(key1.toBigInteger().compareTo(CryptoProvider.getCurve().getN()) < 0);
        assertTrue(key2.toBigInteger().compareTo(CryptoProvider.getCurve().getN()) < 0);
    }

    @Test
    void shouldCreateFromValidBigInteger() throws CryptoException {
        BigInteger validValue = BigInteger.valueOf(12345);
        PrivateKey privateKey = PrivateKey.fromBigInteger(validValue);
        
        assertEquals(validValue, privateKey.toBigInteger());
    }

    @Test
    void shouldRejectInvalidBigInteger() {
        BigInteger zero = BigInteger.ZERO;
        BigInteger negative = BigInteger.valueOf(-1);
        BigInteger tooLarge = CryptoProvider.getCurve().getN();
        
        CryptoException exception1 = assertThrows(CryptoException.class, () -> PrivateKey.fromBigInteger(zero));
        assertEquals("Private key must be positive", exception1.getMessage());
            
        CryptoException exception2 = assertThrows(CryptoException.class, () -> PrivateKey.fromBigInteger(negative));
        assertEquals("Private key must be positive", exception2.getMessage());
            
        CryptoException exception3 = assertThrows(CryptoException.class, () -> PrivateKey.fromBigInteger(tooLarge));
        assertEquals("Private key must be less than curve order", exception3.getMessage());
    }

    @Test
    void shouldReturnCorrectByteArray() {
        byte[] byteArray = testPrivateKey.toByteArray();
        Bytes32 bytes32 = testPrivateKey.toBytes();
        
        assertEquals(32, byteArray.length);
        assertArrayEquals(bytes32.toArrayUnsafe(), byteArray);
    }

    @Test
    void shouldReturnCorrectHexFormats() {
        String hex = testPrivateKey.toHex();
        String unprefixedHex = testPrivateKey.toUnprefixedHex();
        
        assertTrue(hex.startsWith("0x"));
        assertFalse(unprefixedHex.startsWith("0x"));
        assertEquals("0x" + unprefixedHex, hex);
        assertEquals(64, unprefixedHex.length()); // 32 bytes * 2
    }

    @Test
    void shouldConvertToECKeyPair() {
        ECKeyPair keyPair = testPrivateKey.toECKeyPair();
        
        assertNotNull(keyPair);
        assertEquals(testPrivateKey, keyPair.getPrivateKey());
        assertTrue(keyPair.hasPrivateKey());
    }

    @Test
    void shouldDeriveConsistentPublicKey() {
        PublicKey publicKey1 = testPrivateKey.getPublicKey();
        PublicKey publicKey2 = testPrivateKey.getPublicKey();
        
        assertEquals(publicKey2, publicKey1);
        assertNotNull(publicKey1);
    }

    @Test
    void shouldHandleBytesToBigIntegerConversion() throws CryptoException {
        // Test with different byte array scenarios
        
        // Normal 32-byte case
        byte[] normalBytes = new byte[32];
        normalBytes[31] = 1; // Set last byte to 1
        PrivateKey normalKey = PrivateKey.fromBytes(normalBytes);
        assertEquals(BigInteger.ONE, normalKey.toBigInteger());
        assertEquals(32, normalKey.toBytes().size());
        
        // Test with maximum valid value (curve order - 1)
        BigInteger maxValid = CryptoProvider.getCurve().getN().subtract(BigInteger.ONE);
        PrivateKey maxKey = PrivateKey.fromBigInteger(maxValid);
        assertEquals(32, maxKey.toBytes().size());
        assertEquals(maxValid, maxKey.toBigInteger());
    }

    @Test
    void shouldHandleEqualsCorrectly() throws CryptoException {
        PrivateKey sameKey = PrivateKey.fromBigInteger(testPrivateKey.toBigInteger());
        PrivateKey differentKey = PrivateKey.generateRandom();
        
        assertEquals(testPrivateKey, testPrivateKey);
        assertEquals(sameKey, testPrivateKey);
        assertNotEquals(differentKey, testPrivateKey);
        assertNotEquals(null, testPrivateKey);
        assertNotEquals("not a private key", testPrivateKey);
    }

    @Test
    void shouldReturnConsistentHashCode() throws CryptoException {
        PrivateKey sameKey = PrivateKey.fromBigInteger(testPrivateKey.toBigInteger());
        
        assertEquals(sameKey.hashCode(), testPrivateKey.hashCode());
    }

    @Test
    void shouldNotExposeValueInToString() {
        String toString = testPrivateKey.toString();
        
        assertEquals("PrivateKey{length=32 bytes}", toString);
        assertFalse(toString.contains(testPrivateKey.toUnprefixedHex()));
        assertFalse(toString.contains(testPrivateKey.toBigInteger().toString()));
    }

    @Test
    void shouldRoundTripThroughAllFormats() throws CryptoException {
        // Test round-trip through BigInteger
        BigInteger bigInt = testPrivateKey.toBigInteger();
        PrivateKey fromBigInt = PrivateKey.fromBigInteger(bigInt);
        assertEquals(testPrivateKey, fromBigInt);
        
        // Test round-trip through bytes
        Bytes32 bytes = testPrivateKey.toBytes();
        PrivateKey fromBytes = PrivateKey.fromBytes(bytes);
        assertEquals(testPrivateKey, fromBytes);
        
        // Test round-trip through byte array
        byte[] byteArray = testPrivateKey.toByteArray();
        PrivateKey fromByteArray = PrivateKey.fromBytes(byteArray);
        assertEquals(testPrivateKey, fromByteArray);
        
        // Test round-trip through hex
        String hex = testPrivateKey.toHex();
        PrivateKey fromHex = PrivateKey.fromHex(hex);
        assertEquals(testPrivateKey, fromHex);
    }

    @Test
    void shouldCreateFromMinimumValidValue() throws CryptoException {
        PrivateKey minKey = PrivateKey.fromBigInteger(BigInteger.ONE);
        
        assertEquals(BigInteger.ONE, minKey.toBigInteger());
        assertEquals(32, minKey.toBytes().size());
        assertNotNull(minKey.getPublicKey());
    }

    @Test
    void shouldCreateFromMaximumValidValue() throws CryptoException {
        BigInteger maxValue = CryptoProvider.getCurve().getN().subtract(BigInteger.ONE);
        PrivateKey maxKey = PrivateKey.fromBigInteger(maxValue);
        
        assertEquals(maxValue, maxKey.toBigInteger());
        assertEquals(32, maxKey.toBytes().size());
        assertNotNull(maxKey.getPublicKey());
    }

    @Test
    void shouldHandlePaddingInByteConversion() throws CryptoException {
        // Test with a small value that would be less than 32 bytes
        BigInteger smallValue = BigInteger.valueOf(255); // 0xFF - 1 byte
        PrivateKey smallKey = PrivateKey.fromBigInteger(smallValue);
        
        Bytes32 bytes = smallKey.toBytes();
        assertEquals(32, bytes.size());
        
        // Verify the value is preserved
        PrivateKey reconstructed = PrivateKey.fromBytes(bytes);
        assertEquals(smallValue, reconstructed.toBigInteger());
    }

    @Test
    void shouldGenerateValidRandomKeysConsistently() throws CryptoException {
        // Generate multiple keys and verify they're all valid
        for (int i = 0; i < 10; i++) {
            PrivateKey randomKey = PrivateKey.generateRandom();
            
            assertTrue(randomKey.toBigInteger().signum() > 0);
            assertTrue(randomKey.toBigInteger().compareTo(CryptoProvider.getCurve().getN()) < 0);
            assertEquals(32, randomKey.toBytes().size());
            
            // Should be able to derive public key
            PublicKey publicKey = randomKey.getPublicKey();
            assertNotNull(publicKey);
            assertTrue(publicKey.getPoint().isValid());
        }
    }

    @Test
    void shouldThrowOnNullValues() {
        CryptoException exception1 = assertThrows(CryptoException.class, () -> PrivateKey.fromBigInteger(null));
        assertEquals("Private key value cannot be null", exception1.getMessage());
            
        CryptoException exception2 = assertThrows(CryptoException.class, () -> PrivateKey.fromBytes((Bytes32) null));
        assertEquals("Private key bytes cannot be null", exception2.getMessage());
            
        CryptoException exception3 = assertThrows(CryptoException.class, () -> PrivateKey.fromBytes((byte[]) null));
        assertEquals("Private key cannot be null", exception3.getMessage());
    }
} 