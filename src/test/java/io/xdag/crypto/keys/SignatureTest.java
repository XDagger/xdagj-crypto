package io.xdag.crypto.keys;

import static org.junit.jupiter.api.Assertions.*;

import io.xdag.crypto.core.CryptoProvider;
import io.xdag.crypto.exception.CryptoException;
import java.math.BigInteger;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Comprehensive tests for Signature class functionality.
 * 
 * <p>This test class covers Signature creation, validation, format conversion,
 * and verification to ensure complete test coverage.
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
        assertTrue(testSignature.getV() >= (byte) 27);
        assertTrue(testSignature.getV() <= (byte) 30);
        assertTrue(testSignature.getR().signum() > 0);
        assertTrue(testSignature.getS().signum() > 0);
        assertTrue(testSignature.getRecoveryId() >= 0 && testSignature.getRecoveryId() <= 3);
    }

    @Test
    void shouldCreateSignatureCorrectly() {
        assertTrue(testSignature.isCanonical());
        assertTrue(testSignature.getS().compareTo(CryptoProvider.getCurve().getN().divide(BigInteger.valueOf(2))) <= 0);
    }

    @Test
    void shouldValidateCanonicalSignatures() {
        assertTrue(testSignature.isCanonical());
    }

    @Test
    void shouldCreateSignatureWithCorrectRecoveryId() {
        assertTrue(testSignature.getRecoveryId() >= 0);
        assertTrue(testSignature.getRecoveryId() <= 3);
    }

    @Test
    void shouldReturnCorrectRecoveryId() {
        byte[] validVValues = {27, 28, 29, 30}; // Standard recovery ID values
        
        for (byte v : validVValues) {
            BigInteger r = BigInteger.valueOf(12345);
            BigInteger s = BigInteger.valueOf(67890);
            Signature signature = new Signature(v, r, s);
            
            assertEquals(v - Signature.RECOVERY_ID_OFFSET, signature.getRecoveryId());
        }
    }

    @Test
    void shouldGenerateValidDerEncoding() {
        byte[] derBytes = testSignature.toDER();
        assertNotNull(derBytes);
        assertTrue(derBytes.length > 0);
    }

    @Test
    void shouldCreateWithStaticOfMethod() {
        // Create test Bytes32 values for r and s components
        byte[] rArray = new byte[32];
        byte[] sArray = new byte[32];
        rArray[31] = 1; // Set last byte to create valid r
        sArray[31] = 2; // Set last byte to create valid s
        
        Bytes32 rBytes = Bytes32.wrap(rArray);
        Bytes32 sBytes = Bytes32.wrap(sArray);
        byte v = 27;
        
        Signature created = Signature.of(v, rBytes, sBytes);
        
        assertNotNull(created);
        assertEquals(v, created.getV());
        assertEquals(new BigInteger(1, rArray), created.getR());
        assertEquals(new BigInteger(1, sArray), created.getS());
    }

    @Test
    void shouldHandleEqualsCorrectly() {
        // Create identical signature
        Signature sameSignature = new Signature(testSignature.getV(), testSignature.getR(), testSignature.getS());
        
        assertEquals(testSignature, testSignature);
        assertEquals(sameSignature, testSignature);
        
        // Create different signature
        Signature differentSignature = new Signature((byte) 27, BigInteger.valueOf(1), BigInteger.valueOf(2));
        assertNotEquals(differentSignature, testSignature);
        assertNotEquals(null, testSignature);
        assertNotEquals("not a signature", testSignature);
    }

    @Test
    void shouldReturnConsistentHashCode() {
        Signature sameSignature = new Signature(testSignature.getV(), testSignature.getR(), testSignature.getS());
        assertEquals(sameSignature.hashCode(), testSignature.hashCode());
    }

    @Test
    void shouldReturnMeaningfulToString() {
        String toString = testSignature.toString();
        assertTrue(toString.contains("Signature{"));
        assertTrue(toString.contains("v="));
        assertTrue(toString.contains("r="));
        assertTrue(toString.contains("s="));
    }

    @Test
    void shouldValidateSignatureProperties() throws CryptoException {
        // Test that signature was created correctly
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
} 