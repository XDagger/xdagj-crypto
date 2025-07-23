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
} 