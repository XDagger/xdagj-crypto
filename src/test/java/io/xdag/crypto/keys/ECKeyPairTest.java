package io.xdag.crypto.keys;

import static org.junit.jupiter.api.Assertions.*;

import io.xdag.crypto.core.CryptoProvider;
import io.xdag.crypto.exception.CryptoException;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive tests for ECKeyPair class functionality.
 * 
 * <p>This test class covers ECKeyPair creation, validation, format conversion,
 * address generation, edge cases, and error handling to ensure complete test coverage.
 */
class ECKeyPairTest {

    // CryptoProvider is automatically initialized via static block

    // =========================== Creation Tests ===========================

    @Test
    void shouldCreateFromPrivateKeyInstance() throws CryptoException {
        PrivateKey privateKey = PrivateKey.generateRandom();
        ECKeyPair keyPair = ECKeyPair.fromPrivateKey(privateKey);
        
        assertEquals(privateKey, keyPair.getPrivateKey());
        assertTrue(keyPair.hasPrivateKey());
        assertFalse(keyPair.isPublicKeyOnly());
    }

    @Test
    void shouldCreateFromPublicKeyInstance() throws CryptoException {
        PrivateKey privateKey = PrivateKey.generateRandom();
        PublicKey publicKey = privateKey.getPublicKey();
        ECKeyPair keyPair = ECKeyPair.fromPublicKey(publicKey);
        
        assertEquals(publicKey, keyPair.getPublicKey());
        assertFalse(keyPair.hasPrivateKey());
        assertTrue(keyPair.isPublicKeyOnly());
        
        // Should throw when trying to access private key
        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> keyPair.getPrivateKey());
        assertEquals("This is a public-key-only instance", exception.getMessage());
    }

    @Test
    void shouldGenerateRandomKeyPairs() throws CryptoException {
        ECKeyPair keyPair1 = ECKeyPair.generate();
        ECKeyPair keyPair2 = ECKeyPair.generate();
        
        assertNotEquals(keyPair2, keyPair1);
        assertNotEquals(keyPair2.getPrivateKey(), keyPair1.getPrivateKey());
        assertNotEquals(keyPair2.getPublicKey(), keyPair1.getPublicKey());
    }

    @Test
    void shouldCreateFromVariousFormats() throws CryptoException {
        // Test fromHex
        String hexKey = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        ECKeyPair fromHex = ECKeyPair.fromHex(hexKey);
        assertTrue(fromHex.hasPrivateKey());
        assertEquals(hexKey, fromHex.getPrivateKey().toUnprefixedHex());
        
        // Test fromBytes with byte array
        byte[] keyBytes = fromHex.getPrivateKey().toByteArray();
        ECKeyPair fromBytes = ECKeyPair.fromBytes(keyBytes);
        assertEquals(fromHex, fromBytes);
        
        // Test fromBytes with Bytes32
        Bytes32 keyBytes32 = fromHex.getPrivateKey().toBytes();
        ECKeyPair fromBytes32 = ECKeyPair.fromBytes(keyBytes32);
        assertEquals(fromHex, fromBytes32);
    }

    // =========================== Validation Tests ===========================

    @Test
    void shouldCreateECKeyPairFromValidHex() throws CryptoException {
        String validHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        ECKeyPair keyPair = ECKeyPair.fromHex(validHex);
        
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivateKey());
        assertNotNull(keyPair.getPublicKey());
    }

    @Test
    void shouldCreateECKeyPairFromValidHexWithPrefix() throws CryptoException {
        String validHexWithPrefix = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        ECKeyPair keyPair = ECKeyPair.fromHex(validHexWithPrefix);
        
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivateKey());
        assertNotNull(keyPair.getPublicKey());
    }

    @Test
    void shouldRejectNullHex() {
        CryptoException exception = assertThrows(CryptoException.class, () -> ECKeyPair.fromHex(null));
        assertEquals("Private key hex cannot be null or empty", exception.getMessage());
    }

    @Test
    void shouldRejectEmptyHex() {
        CryptoException exception = assertThrows(CryptoException.class, () -> ECKeyPair.fromHex(""));
        assertEquals("Private key hex cannot be null or empty", exception.getMessage());
    }

    @Test
    void shouldRejectInvalidHexLength() {
        String wrongLengthHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"; // 62 chars instead of 64
        CryptoException exception = assertThrows(CryptoException.class, () -> ECKeyPair.fromHex(wrongLengthHex));
        assertEquals("Private key hex must be 64 characters (32 bytes), got 62", exception.getMessage());
    }

    @Test
    void shouldRejectInvalidHexCharacters() {
        String invalidHex = "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"; // 'g' is invalid
        CryptoException exception = assertThrows(CryptoException.class, () -> ECKeyPair.fromHex(invalidHex));
        assertEquals("Private key hex contains invalid characters", exception.getMessage());
    }

    @Test
    void shouldCreateFromMaxValidPrivateKey() throws CryptoException {
        // Maximum valid private key: curve order - 1
        String maxValidHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140";
        ECKeyPair keyPair = ECKeyPair.fromHex(maxValidHex);
        
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivateKey());
        assertNotNull(keyPair.getPublicKey());
    }

    @Test
    void shouldRejectZeroPrivateKey() {
        String zeroHex = "0000000000000000000000000000000000000000000000000000000000000000";
        assertThrows(CryptoException.class, () -> ECKeyPair.fromHex(zeroHex));
    }

    @Test
    void shouldRejectPrivateKeyAtCurveOrder() {
        // The order of secp256k1 curve
        String curveOrderHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
        assertThrows(CryptoException.class, () -> ECKeyPair.fromHex(curveOrderHex));
    }

    @Test
    void shouldRejectNullBytes32() {
        CryptoException exception = assertThrows(CryptoException.class, () -> ECKeyPair.fromBytes((Bytes32) null));
        assertEquals("Private key bytes cannot be null", exception.getMessage());
    }

    @Test
    void shouldRejectNullByteArray() {
        CryptoException exception = assertThrows(CryptoException.class, () -> ECKeyPair.fromBytes((byte[]) null));
        assertEquals("Private key cannot be null", exception.getMessage());
    }

    @Test
    void shouldRejectWrongSizeByteArray() {
        byte[] wrongSize = new byte[31]; // Should be 32 bytes
        CryptoException exception = assertThrows(CryptoException.class, () -> ECKeyPair.fromBytes(wrongSize));
        assertEquals("Private key must be exactly 32 bytes, got 31", exception.getMessage());
    }

    @Test
    void shouldCreateFromEdgeCaseValidBytes() throws CryptoException {
        // Test with bytes that equal 1 (minimum valid private key)
        byte[] minBytes = new byte[32];
        minBytes[31] = 1; // Set the least significant byte to 1
        
        ECKeyPair keyPair = ECKeyPair.fromBytes(minBytes);
        assertNotNull(keyPair);
        assertEquals(1, keyPair.getPrivateKey().toBigInteger().intValue());
    }

    // =========================== Address Generation Tests ===========================

    @Test
    void shouldGenerateValidAddresses() throws CryptoException {
        ECKeyPair keyPair = ECKeyPair.generate();
        
        // Test default address generation (compressed)
        Bytes defaultAddress = keyPair.toAddress();
        assertEquals(20, defaultAddress.size());
        
        // Test compressed address generation
        Bytes compressedAddress = keyPair.toAddress(true);
        assertEquals(defaultAddress, compressedAddress);
        
        // Test uncompressed address generation
        Bytes uncompressedAddress = keyPair.toAddress(false);
        assertEquals(20, uncompressedAddress.size());
        assertNotEquals(compressedAddress, uncompressedAddress);
    }

    @Test
    void shouldGenerateValidBase58Addresses() throws CryptoException {
        ECKeyPair keyPair = ECKeyPair.generate();
        
        // Test default Base58 address generation (compressed)
        String defaultAddress = keyPair.toBase58Address();
        assertFalse(defaultAddress.isEmpty());
        
        // Test compressed Base58 address generation
        String compressedAddress = keyPair.toBase58Address(true);
        assertEquals(defaultAddress, compressedAddress);
        
        // Test uncompressed Base58 address generation
        String uncompressedAddress = keyPair.toBase58Address(false);
        assertFalse(uncompressedAddress.isEmpty());
        assertNotEquals(compressedAddress, uncompressedAddress);
    }

    @Test
    void shouldHandlePublicKeyOnlyAddressGeneration() throws CryptoException {
        ECKeyPair fullKeyPair = ECKeyPair.generate();
        ECKeyPair publicOnlyKeyPair = ECKeyPair.fromPublicKey(fullKeyPair.getPublicKey());
        
        // Should generate same addresses despite being public-key-only
        assertEquals(fullKeyPair.toAddress(), publicOnlyKeyPair.toAddress());
        assertEquals(fullKeyPair.toAddress(true), publicOnlyKeyPair.toAddress(true));
        assertEquals(fullKeyPair.toAddress(false), publicOnlyKeyPair.toAddress(false));
        assertEquals(fullKeyPair.toBase58Address(), publicOnlyKeyPair.toBase58Address());
        assertEquals(fullKeyPair.toBase58Address(true), publicOnlyKeyPair.toBase58Address(true));
        assertEquals(fullKeyPair.toBase58Address(false), publicOnlyKeyPair.toBase58Address(false));
    }

    // =========================== Consistency Tests ===========================

    @Test
    void shouldHandleVariousValidFormats() throws CryptoException {
        String hexWithoutPrefix = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        ECKeyPair keyPair1 = ECKeyPair.fromHex(hexWithoutPrefix);
        
        // Test that the same hex string produces consistent results
        ECKeyPair keyPair2 = ECKeyPair.fromHex(hexWithoutPrefix);
        
        assertEquals(keyPair2.getPrivateKey().toBigInteger(), keyPair1.getPrivateKey().toBigInteger());
        assertEquals(keyPair2.getPublicKey(), keyPair1.getPublicKey());
    }

    @Test
    void shouldGenerateValidKeyPairsConsistently() throws CryptoException {
        // Generate multiple key pairs and ensure they're all valid
        for (int i = 0; i < 10; i++) {
            ECKeyPair keyPair = ECKeyPair.generate();
            
            assertNotNull(keyPair.getPrivateKey());
            assertNotNull(keyPair.getPublicKey());
            
            // Private key should be in valid range
            assertTrue(keyPair.getPrivateKey().toBigInteger().signum() > 0);
            assertTrue(keyPair.getPrivateKey().toBigInteger().compareTo(CryptoProvider.getCurve().getN()) < 0);
            
            // Should be able to derive the same public key from private key
            PublicKey derivedPublicKey = keyPair.getPrivateKey().getPublicKey();
            assertEquals(keyPair.getPublicKey().toCompressedBytes(), derivedPublicKey.toCompressedBytes());
        }
    }

    @Test
    void shouldValidateConsistentKeyDerivation() throws CryptoException {
        // Ensure that the same private key always produces the same public key
        String hexKey = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        
        ECKeyPair keyPair1 = ECKeyPair.fromHex(hexKey);
        ECKeyPair keyPair2 = ECKeyPair.fromHex(hexKey);
        
        assertEquals(keyPair2.getPublicKey(), keyPair1.getPublicKey());
        assertEquals(keyPair2.toAddress(), keyPair1.toAddress());
        assertEquals(keyPair2.toBase58Address(), keyPair1.toBase58Address());
    }

    // =========================== Equals and HashCode Tests ===========================

    @Test
    void shouldHandleEqualsAndHashCodeCorrectly() throws CryptoException {
        PrivateKey privateKey = PrivateKey.generateRandom();
        ECKeyPair keyPair1 = ECKeyPair.fromPrivateKey(privateKey);
        ECKeyPair keyPair2 = ECKeyPair.fromPrivateKey(privateKey);
        ECKeyPair differentKeyPair = ECKeyPair.generate();
        
        // Test equals
        assertEquals(keyPair1, keyPair1);
        assertEquals(keyPair2, keyPair1);
        assertNotEquals(differentKeyPair, keyPair1);
        assertNotEquals(null, keyPair1);
        assertNotEquals("not a key pair", keyPair1);
        
        // Test hashCode consistency
        assertEquals(keyPair2.hashCode(), keyPair1.hashCode());
        
        // Test public-key-only instances
        PublicKey publicKey = privateKey.getPublicKey();
        ECKeyPair publicOnlyKeyPair1 = ECKeyPair.fromPublicKey(publicKey);
        ECKeyPair publicOnlyKeyPair2 = ECKeyPair.fromPublicKey(publicKey);
        
        assertEquals(publicOnlyKeyPair2, publicOnlyKeyPair1);
        assertEquals(publicOnlyKeyPair2.hashCode(), publicOnlyKeyPair1.hashCode());
        
        // Mixed comparison (full key pair vs public-only)
        assertNotEquals(publicOnlyKeyPair1, keyPair1);
    }

    @Test
    void shouldReturnCorrectToString() throws CryptoException {
        ECKeyPair keyPair = ECKeyPair.generate();
        String toString = keyPair.toString();
        
        assertTrue(toString.contains("ECKeyPair{"));
        assertTrue(toString.contains("publicKey="));
        assertTrue(toString.contains("hasPrivateKey=true"));
        assertTrue(toString.contains(keyPair.getPublicKey().toUnprefixedHex()));
        
        // Test public-key-only instance
        ECKeyPair publicOnlyKeyPair = ECKeyPair.fromPublicKey(keyPair.getPublicKey());
        String publicOnlyToString = publicOnlyKeyPair.toString();
        
        assertTrue(publicOnlyToString.contains("hasPrivateKey=false"));
    }
} 