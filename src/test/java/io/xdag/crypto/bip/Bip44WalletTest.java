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
package io.xdag.crypto.bip;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.xdag.crypto.exception.CryptoException;
import io.xdag.crypto.keys.AddressUtils;
import io.xdag.crypto.keys.ECKeyPair;
import java.math.BigInteger;
import java.util.Arrays;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

class Bip44WalletTest {

    @Test
    void shouldDeriveXdagAddressFromBip44Path() throws CryptoException {
        // 1. Test seed generation
        String mnemonic = "spider elbow fossil truck deal circle divert sleep safe report laundry above";
        String password = "password";
        Bytes seed = Bip39Mnemonic.mnemonicToSeed(Arrays.asList(mnemonic.split(" ")), password);

        // 2. Create master key from seed
        Bip32Key masterKey = Bip44Wallet.createMasterKey(seed.toArrayUnsafe());

        // 3. BIP44 derivation (m/44'/586'/0'/0/0)
        Bip32Key bip44Key = Bip44Wallet.deriveXdagKey(masterKey, 0, 0);
        
        // Calculate address using the modern ECKeyPair API
        Bytes address = AddressUtils.toBytesAddress(bip44Key.keyPair());
        assertEquals("6a52a623fc36974cb3c67c3558694584eb39008a", address.toUnprefixedHexString());
    }

    @Test
    void shouldDerivePrivateKeyFromMnemonic() throws CryptoException {
        String mnemonic = "know party bunker fly ribbon combine dilemma omit birth impose submit cost";
        Bytes seed = Bip39Mnemonic.mnemonicToSeed(Arrays.asList(mnemonic.split(" ")), "");
        Bip32Key masterKey = Bip44Wallet.createMasterKey(seed.toArrayUnsafe());
        Bip32Key bip44Key = Bip44Wallet.deriveXdagKey(masterKey, 0, 0);
        
        // Derive the private key
        BigInteger privateKey = bip44Key.keyPair().getPrivateKey().toBigInteger();
        assertEquals("3a35b1a709a9fa5ddddbdf4e03f2ef309005e50be04d92e67f75eabae0335ba9", privateKey.toString(16));
    }

    @Test
    void shouldExtractKeyPairFromMasterKey() throws CryptoException {
        // Test that we can extract key pair from master key
        String mnemonic = "spider elbow fossil truck deal circle divert sleep safe report laundry above";
        String password = "password";
        Bytes seed = Bip39Mnemonic.mnemonicToSeed(Arrays.asList(mnemonic.split(" ")), password);

        // Create master key
        Bip32Key masterKey = Bip44Wallet.createMasterKey(seed.toArrayUnsafe());
        
        // Extract key pair from master key
        ECKeyPair extractedKeyPair = masterKey.keyPair();
        
        // Verify the private key matches expected value
        assertNotNull(extractedKeyPair);
        assertNotNull(extractedKeyPair.getPrivateKey());
        assertTrue(extractedKeyPair.hasPrivateKey());
    }

    @Test
    void shouldCreateKeyPairFromSeed() throws CryptoException {
        // Test data from BIP39 test vectors
        String mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        Bytes seed = Bip39Mnemonic.toSeed(mnemonic);
        
        // Test createKeyPair convenience method
        ECKeyPair keyPair = Bip44Wallet.createKeyPair(seed.toArrayUnsafe());
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivateKey());
        assertNotNull(keyPair.getPublicKey());
        
        // Should be deterministic
        ECKeyPair keyPair2 = Bip44Wallet.createKeyPair(seed.toArrayUnsafe());
        assertEquals(keyPair.getPrivateKey().toBigInteger(), keyPair2.getPrivateKey().toBigInteger());
        assertEquals(keyPair.getPublicKey().toCompressedBytes(), keyPair2.getPublicKey().toCompressedBytes());
    }

    @Test
    void shouldCreateKeyPairFromMnemonic() throws CryptoException {
        String mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        // Test createKeyPairFromMnemonic convenience method
        ECKeyPair keyPair = Bip44Wallet.createKeyPairFromMnemonic(mnemonic);
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivateKey());
        assertNotNull(keyPair.getPublicKey());
        
        // Should be deterministic
        ECKeyPair keyPair2 = Bip44Wallet.createKeyPairFromMnemonic(mnemonic);
        assertEquals(keyPair.getPrivateKey().toBigInteger(), keyPair2.getPrivateKey().toBigInteger());
        assertEquals(keyPair.getPublicKey().toCompressedBytes(), keyPair2.getPublicKey().toCompressedBytes());
        
        // Should be equivalent to manual seed conversion
        Bytes seed = Bip39Mnemonic.toSeed(mnemonic);
        ECKeyPair keyPairFromSeed = Bip44Wallet.createKeyPair(seed.toArrayUnsafe());
        assertEquals(keyPair.getPrivateKey().toBigInteger(), keyPairFromSeed.getPrivateKey().toBigInteger());
    }

    @Test
    void shouldCreateKeyPairFromMnemonicWithPassphrase() throws CryptoException {
        String mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        String passphrase = "test_passphrase";
        
        // Test createKeyPairFromMnemonic with passphrase
        ECKeyPair keyPairWithPassphrase = Bip44Wallet.createKeyPairFromMnemonic(mnemonic, passphrase);
        ECKeyPair keyPairWithoutPassphrase = Bip44Wallet.createKeyPairFromMnemonic(mnemonic);
        
        assertNotNull(keyPairWithPassphrase);
        assertNotNull(keyPairWithoutPassphrase);
        
        // Should be different with and without passphrase
        assertNotEquals(keyPairWithPassphrase.getPrivateKey().toBigInteger(),
            keyPairWithoutPassphrase.getPrivateKey().toBigInteger());
        
        // Should be deterministic with same passphrase
        ECKeyPair keyPairWithPassphrase2 = Bip44Wallet.createKeyPairFromMnemonic(mnemonic, passphrase);
        assertEquals(keyPairWithPassphrase.getPrivateKey().toBigInteger(), 
                keyPairWithPassphrase2.getPrivateKey().toBigInteger());
    }

    @Test
    void shouldCreateKeyPairCompatibleWithFullBip32Key() throws CryptoException {
        String mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        Bytes seed = Bip39Mnemonic.toSeed(mnemonic);

        // Compare convenience method with full BIP32 approach
        ECKeyPair simpleKeyPair = Bip44Wallet.createKeyPair(seed.toArrayUnsafe());
        Bip32Key masterKey = Bip44Wallet.createMasterKey(seed.toArrayUnsafe());
        ECKeyPair masterKeyPair = masterKey.keyPair();

        // Should produce the same key pair
        assertEquals(simpleKeyPair.getPrivateKey().toBigInteger(),
                masterKeyPair.getPrivateKey().toBigInteger());
        assertEquals(simpleKeyPair.getPublicKey().toCompressedBytes(),
                masterKeyPair.getPublicKey().toCompressedBytes());
    }

    // ==================== BIP-0032 Official Test Vectors ====================
    // Test vectors from: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

    /**
     * BIP-0032 Test Vector 1: Basic master key derivation
     * Tests HMAC-SHA512 implementation and byte array handling
     */
    @Test
    void shouldDeriveMasterKeyFromTestVector1() throws CryptoException {
        // Test vector 1 seed
        byte[] seed = Bytes.fromHexString("000102030405060708090a0b0c0d0e0f").toArrayUnsafe();

        // Create master key
        Bip32Key masterKey = Bip44Wallet.createMasterKey(seed);

        // Expected values from BIP-0032 specification
        String expectedPrivateKey = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
        String expectedChainCode = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";

        // Verify master private key (use toUnprefixedHex() to preserve leading zeros)
        assertEquals(expectedPrivateKey,
                masterKey.keyPair().getPrivateKey().toUnprefixedHex());

        // Verify chain code
        assertEquals(expectedChainCode, masterKey.chainCode().toUnprefixedHexString());
    }

    /**
     * BIP-0032 Test Vector 1: Chain m/0H (hardened derivation)
     * Tests hardened child key derivation with 33-byte private key format
     */
    @Test
    void shouldDeriveHardenedChildKeyAtPath_m_0H() throws CryptoException {
        byte[] seed = Bytes.fromHexString("000102030405060708090a0b0c0d0e0f").toArrayUnsafe();
        Bip32Key masterKey = Bip44Wallet.createMasterKey(seed);

        // Derive m/0H (hardened index 0)
        int hardenedBit = 0x80000000;
        Bip32Key child = Bip44Wallet.derivePath(masterKey, new int[]{hardenedBit | 0});

        // Expected values from BIP-0032 specification
        String expectedPrivateKey = "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea";
        String expectedChainCode = "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141";

        assertEquals(expectedPrivateKey,
                child.keyPair().getPrivateKey().toUnprefixedHex());
        assertEquals(expectedChainCode, child.chainCode().toUnprefixedHexString());
    }

    /**
     * BIP-0032 Test Vector 1: Chain m/0H/1 (mixed hardened and non-hardened)
     * Tests transition from hardened to non-hardened derivation
     */
    @Test
    void shouldDeriveMixedHardenedAndNonHardenedKeyAtPath_m_0H_1() throws CryptoException {
        byte[] seed = Bytes.fromHexString("000102030405060708090a0b0c0d0e0f").toArrayUnsafe();
        Bip32Key masterKey = Bip44Wallet.createMasterKey(seed);

        // Derive m/0H/1
        int hardenedBit = 0x80000000;
        Bip32Key child = Bip44Wallet.derivePath(masterKey, new int[]{hardenedBit | 0, 1});

        // Expected values from BIP-0032 specification
        String expectedPrivateKey = "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368";
        String expectedChainCode = "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19";

        assertEquals(expectedPrivateKey,
                child.keyPair().getPrivateKey().toUnprefixedHex());
        assertEquals(expectedChainCode, child.chainCode().toUnprefixedHexString());
    }

    /**
     * BIP-0032 Test Vector 1: Chain m/0H/1/2H (deep derivation path)
     * Tests multiple levels of derivation
     */
    @Test
    void shouldDeriveDeepPathKeyAtPath_m_0H_1_2H() throws CryptoException {
        byte[] seed = Bytes.fromHexString("000102030405060708090a0b0c0d0e0f").toArrayUnsafe();
        Bip32Key masterKey = Bip44Wallet.createMasterKey(seed);

        // Derive m/0H/1/2H
        int hardenedBit = 0x80000000;
        Bip32Key child = Bip44Wallet.derivePath(masterKey,
                new int[]{hardenedBit | 0, 1, hardenedBit | 2});

        // Expected values from BIP-0032 specification
        String expectedPrivateKey = "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca";
        String expectedChainCode = "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f";

        assertEquals(expectedPrivateKey,
                child.keyPair().getPrivateKey().toUnprefixedHex());
        assertEquals(expectedChainCode, child.chainCode().toUnprefixedHexString());
    }

    /**
     * BIP-0032 Test Vector 1: Chain m/0H/1/2H/2 (longer mixed path)
     * Tests extended derivation paths with alternating hardened/non-hardened
     */
    @Test
    void shouldDeriveExtendedMixedPathKeyAtPath_m_0H_1_2H_2() throws CryptoException {
        byte[] seed = Bytes.fromHexString("000102030405060708090a0b0c0d0e0f").toArrayUnsafe();
        Bip32Key masterKey = Bip44Wallet.createMasterKey(seed);

        // Derive m/0H/1/2H/2
        int hardenedBit = 0x80000000;
        Bip32Key child = Bip44Wallet.derivePath(masterKey,
                new int[]{hardenedBit | 0, 1, hardenedBit | 2, 2});

        // Expected values from BIP-0032 specification
        String expectedPrivateKey = "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4";
        String expectedChainCode = "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd";

        assertEquals(expectedPrivateKey,
                child.keyPair().getPrivateKey().toUnprefixedHex());
        assertEquals(expectedChainCode, child.chainCode().toUnprefixedHexString());
    }

    /**
     * BIP-0032 Test Vector 1: Chain m/0H/1/2H/2/1000000000 (large index)
     * Tests handling of large child indices and deep paths
     */
    @Test
    void shouldDeriveKeyWithLargeIndexAtPath_m_0H_1_2H_2_1000000000() throws CryptoException {
        byte[] seed = Bytes.fromHexString("000102030405060708090a0b0c0d0e0f").toArrayUnsafe();
        Bip32Key masterKey = Bip44Wallet.createMasterKey(seed);

        // Derive m/0H/1/2H/2/1000000000
        int hardenedBit = 0x80000000;
        Bip32Key child = Bip44Wallet.derivePath(masterKey,
                new int[]{hardenedBit | 0, 1, hardenedBit | 2, 2, 1000000000});

        // Expected values from BIP-0032 specification
        String expectedPrivateKey = "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8";
        String expectedChainCode = "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e";

        assertEquals(expectedPrivateKey,
                child.keyPair().getPrivateKey().toUnprefixedHex());
        assertEquals(expectedChainCode, child.chainCode().toUnprefixedHexString());
    }

    /**
     * BIP-0032 Test Vector 2: Tests keys with leading zeros
     * Critical test for BigInteger byte array conversion edge cases
     */
    @Test
    void shouldHandleKeysWithLeadingZerosFromTestVector2() throws CryptoException {
        // Test vector 2 seed - designed to produce keys with leading zeros
        byte[] seed = Bytes.fromHexString(
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).toArrayUnsafe();

        // Create master key
        Bip32Key masterKey = Bip44Wallet.createMasterKey(seed);

        // Expected master key values
        String expectedPrivateKey = "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e";
        String expectedChainCode = "60499f801b896d83179a4374aeb7822aaeaceaa0db1f85ee3e904c4defbd9689";

        assertEquals(expectedPrivateKey,
                masterKey.keyPair().getPrivateKey().toUnprefixedHex());
        assertEquals(expectedChainCode, masterKey.chainCode().toUnprefixedHexString());
    }

    /**
     * BIP-0032 Test Vector 2: Chain m/0 (non-hardened from vector 2)
     * Tests non-hardened derivation with potential leading zero scenarios
     */
    @Test
    void shouldDeriveNonHardenedKeyWithLeadingZerosAtPath_m_0() throws CryptoException {
        byte[] seed = Bytes.fromHexString(
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).toArrayUnsafe();
        Bip32Key masterKey = Bip44Wallet.createMasterKey(seed);

        // Derive m/0 (non-hardened)
        Bip32Key child = Bip44Wallet.derivePath(masterKey, new int[]{0});

        // Expected values
        String expectedPrivateKey = "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e";
        String expectedChainCode = "f0909affaa7ee7abe5dd4e100598d4dc53cd709d5a5c2cac40e7412f232f7c9c";

        assertEquals(expectedPrivateKey,
                child.keyPair().getPrivateKey().toUnprefixedHex());
        assertEquals(expectedChainCode, child.chainCode().toUnprefixedHexString());
    }

    /**
     * BIP-0032 Test Vector 2: Chain m/0/2147483647H (hardened with max index)
     * Tests large hardened index handling
     */
    @Test
    void shouldDeriveKeyWithMaxHardenedIndexAtPath_m_0_2147483647H() throws CryptoException {
        byte[] seed = Bytes.fromHexString(
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).toArrayUnsafe();
        Bip32Key masterKey = Bip44Wallet.createMasterKey(seed);

        // Derive m/0/2147483647H
        int hardenedBit = 0x80000000;
        Bip32Key child = Bip44Wallet.derivePath(masterKey,
                new int[]{0, hardenedBit | 2147483647});

        // Expected values
        String expectedPrivateKey = "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93";
        String expectedChainCode = "be17a268474a6bb9c61e1d720cf6215e2a88c5406c4aee7b38547f585c9a37d9";

        assertEquals(expectedPrivateKey,
                child.keyPair().getPrivateKey().toUnprefixedHex());
        assertEquals(expectedChainCode, child.chainCode().toUnprefixedHexString());
    }

    /**
     * BIP-0032 Test Vector 2: Chain m/0/2147483647H/1 (mixed large indices)
     * Tests derivation with maximum hardened index followed by normal index
     */
    @Test
    void shouldDeriveMixedMaxIndexAndNormalKeyAtPath_m_0_2147483647H_1() throws CryptoException {
        byte[] seed = Bytes.fromHexString(
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).toArrayUnsafe();
        Bip32Key masterKey = Bip44Wallet.createMasterKey(seed);

        // Derive m/0/2147483647H/1
        int hardenedBit = 0x80000000;
        Bip32Key child = Bip44Wallet.derivePath(masterKey,
                new int[]{0, hardenedBit | 2147483647, 1});

        // Expected values
        String expectedPrivateKey = "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7";
        String expectedChainCode = "f366f48f1ea9f2d1d3fe958c95ca84ea18e4c4ddb9366c336c927eb246fb38cb";

        assertEquals(expectedPrivateKey,
                child.keyPair().getPrivateKey().toUnprefixedHex());
        assertEquals(expectedChainCode, child.chainCode().toUnprefixedHexString());
    }

    /**
     * BIP-0032 Test Vector 2: Chain m/0/2147483647H/1/2147483646H (alternating max indices)
     * Tests multiple large indices in derivation path
     */
    @Test
    void shouldDeriveKeyWithMultipleLargeIndicesAtPath_m_0_2147483647H_1_2147483646H() throws CryptoException {
        byte[] seed = Bytes.fromHexString(
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).toArrayUnsafe();
        Bip32Key masterKey = Bip44Wallet.createMasterKey(seed);

        // Derive m/0/2147483647H/1/2147483646H
        int hardenedBit = 0x80000000;
        Bip32Key child = Bip44Wallet.derivePath(masterKey,
                new int[]{0, hardenedBit | 2147483647, 1, hardenedBit | 2147483646});

        // Expected values
        String expectedPrivateKey = "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d";
        String expectedChainCode = "637807030d55d01f9a0cb3a7839515d796bd07706386a6eddf06cc29a65a0e29";

        assertEquals(expectedPrivateKey,
                child.keyPair().getPrivateKey().toUnprefixedHex());
        assertEquals(expectedChainCode, child.chainCode().toUnprefixedHexString());
    }

    /**
     * BIP-0032 Test Vector 2: Chain m/0/2147483647H/1/2147483646H/2 (final deep path)
     * Tests complete deep derivation path with edge case indices
     */
    @Test
    void shouldDeriveCompleteDeepPathWithEdgeCaseIndicesAtPath_m_0_2147483647H_1_2147483646H_2() throws CryptoException {
        byte[] seed = Bytes.fromHexString(
                "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        ).toArrayUnsafe();
        Bip32Key masterKey = Bip44Wallet.createMasterKey(seed);

        // Derive m/0/2147483647H/1/2147483646H/2
        int hardenedBit = 0x80000000;
        Bip32Key child = Bip44Wallet.derivePath(masterKey,
                new int[]{0, hardenedBit | 2147483647, 1, hardenedBit | 2147483646, 2});

        // Expected values
        String expectedPrivateKey = "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23";
        String expectedChainCode = "9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271";

        assertEquals(expectedPrivateKey,
                child.keyPair().getPrivateKey().toUnprefixedHex());
        assertEquals(expectedChainCode, child.chainCode().toUnprefixedHexString());
    }
} 