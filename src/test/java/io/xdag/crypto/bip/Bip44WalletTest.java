package io.xdag.crypto.bip;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.xdag.crypto.exception.CryptoException;
import io.xdag.crypto.keys.AddressUtils;
import java.math.BigInteger;
import java.util.Arrays;
import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.junit.jupiter.api.Test;

class Bip44WalletTest {

    @Test
    void bip44AddressTest() throws CryptoException {
        // 1. Test seed generation
        String mnemonic = "spider elbow fossil truck deal circle divert sleep safe report laundry above";
        String password = "password";
        Bytes seed = Bip39Mnemonic.mnemonicToSeed(Arrays.asList(mnemonic.split(" ")), password);

        // 2. Create master key from seed
        Bip32Node masterNode = Bip44Wallet.createMasterKeyPair(seed.toArrayUnsafe());

        // 3. BIP44 derivation (m/44'/586'/0'/0/0)
        Bip32Node bip44Node = Bip44Wallet.deriveXdagKeyPair(masterNode, 0, 0);
        assertEquals("6a52a623fc36974cb3c67c3558694584eb39008a", AddressUtils.toBytesAddress(bip44Node.keyPair()).toUnprefixedHexString());
    }

    @Test
    void getPrivateKeyFromMnemonic() throws CryptoException {
        String mnemonic = "know party bunker fly ribbon combine dilemma omit birth impose submit cost";
        Bytes seed = Bip39Mnemonic.mnemonicToSeed(Arrays.asList(mnemonic.split(" ")), "");
        Bip32Node masterNode = Bip44Wallet.createMasterKeyPair(seed.toArrayUnsafe());
        Bip32Node bip44Node = Bip44Wallet.deriveXdagKeyPair(masterNode, 0, 0);
        
        // Derive the private key
        BigInteger privateKey = ((ECPrivateKeyParameters) bip44Node.keyPair().getPrivate()).getD();
        assertEquals("3a35b1a709a9fa5ddddbdf4e03f2ef309005e50be04d92e67f75eabae0335ba9", privateKey.toString(16));
    }
} 