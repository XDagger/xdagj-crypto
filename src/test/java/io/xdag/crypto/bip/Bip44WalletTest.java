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
    void bip44AddressTest() throws CryptoException {
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
    void getPrivateKeyFromMnemonic() throws CryptoException {
        String mnemonic = "know party bunker fly ribbon combine dilemma omit birth impose submit cost";
        Bytes seed = Bip39Mnemonic.mnemonicToSeed(Arrays.asList(mnemonic.split(" ")), "");
        Bip32Key masterKey = Bip44Wallet.createMasterKey(seed.toArrayUnsafe());
        Bip32Key bip44Key = Bip44Wallet.deriveXdagKey(masterKey, 0, 0);
        
        // Derive the private key
        BigInteger privateKey = bip44Key.keyPair().getPrivateKey().toBigInteger();
        assertEquals("3a35b1a709a9fa5ddddbdf4e03f2ef309005e50be04d92e67f75eabae0335ba9", privateKey.toString(16));
    }

    @Test
    void keyPairExtractionTest() throws CryptoException {
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
        assertTrue(!keyPairWithPassphrase.getPrivateKey().toBigInteger()
                .equals(keyPairWithoutPassphrase.getPrivateKey().toBigInteger()));
        
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
} 