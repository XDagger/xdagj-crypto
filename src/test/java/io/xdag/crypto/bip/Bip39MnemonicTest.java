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

import static org.junit.jupiter.api.Assertions.*;

import io.xdag.crypto.exception.CryptoException;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

class Bip39MnemonicTest {

    @Test
    void shouldGenerateMnemonicString() throws CryptoException {
        String mnemonic = Bip39Mnemonic.generateString();
        
        assertNotNull(mnemonic);
        String[] words = mnemonic.split(" ");
        assertEquals(12, words.length);
        assertTrue(Bip39Mnemonic.isValid(mnemonic));
    }

    @Test
    void shouldValidateKnownMnemonic() {
        String validMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assertTrue(Bip39Mnemonic.isValid(validMnemonic));
        
        String invalidMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assertFalse(Bip39Mnemonic.isValid(invalidMnemonic));
    }

    @Test
    void shouldGenerateSeedFromMnemonic() throws CryptoException {
        String mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        Bytes seed = Bip39Mnemonic.toSeed(mnemonic);
        assertNotNull(seed);
        assertEquals(64, seed.size());
        
        // Should be deterministic
        Bytes seed2 = Bip39Mnemonic.toSeed(mnemonic);
        assertEquals(seed, seed2);
    }

    @Test
    void shouldGenerateSeedWithPassphrase() throws CryptoException {
        String mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        
        Bytes seedWithoutPassphrase = Bip39Mnemonic.toSeed(mnemonic);
        Bytes seedWithPassphrase = Bip39Mnemonic.toSeed(mnemonic, "password");
        
        assertNotNull(seedWithPassphrase);
        assertEquals(64, seedWithPassphrase.size());
        assertNotEquals(seedWithoutPassphrase, seedWithPassphrase);
    }

    @Test
    void shouldRejectInvalidWordCount() {
        // Too few words
        assertFalse(Bip39Mnemonic.isValid("abandon abandon abandon"));
        
        // Too many words
        String tooMany = "abandon ".repeat(24).trim();
        assertFalse(Bip39Mnemonic.isValid(tooMany));
    }

    @Test
    void shouldRejectInvalidWords() {
        String invalidWord = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalid";
        assertFalse(Bip39Mnemonic.isValid(invalidWord));
    }

    @Test
    void shouldRejectInvalidChecksum() {
        String invalidChecksum = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assertFalse(Bip39Mnemonic.isValid(invalidChecksum));
    }

    @Test
    void shouldRejectNullOrEmpty() {
        assertFalse(Bip39Mnemonic.isValid(null));
        assertFalse(Bip39Mnemonic.isValid(""));
        assertFalse(Bip39Mnemonic.isValid("   "));
    }

    @Test
    void shouldHandleWhitespace() {
        String mnemonicWithExtraSpaces = "  abandon   abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon about  ";
        assertTrue(Bip39Mnemonic.isValid(mnemonicWithExtraSpaces));
    }

    @Test
    void shouldGenerateRandomMnemonics() throws CryptoException {
        // Generate multiple mnemonics and ensure they're different
        String mnemonic1 = Bip39Mnemonic.generateString();
        String mnemonic2 = Bip39Mnemonic.generateString();
        
        assertNotEquals(mnemonic1, mnemonic2);
        assertTrue(Bip39Mnemonic.isValid(mnemonic1));
        assertTrue(Bip39Mnemonic.isValid(mnemonic2));
    }

    @Test
    void shouldThrowExceptionForInvalidSeed() {
        String invalidMnemonic = "invalid mnemonic phrase";
        assertThrows(CryptoException.class, () -> Bip39Mnemonic.toSeed(invalidMnemonic));
    }

    @Test
    void shouldThrowExceptionForNullSeed() {
        assertThrows(CryptoException.class, () -> Bip39Mnemonic.toSeed(null));
    }

    // ==================== BIP-0039 Official Test Vectors ====================
    // Test vectors from: https://github.com/trezor/python-mnemonic/blob/master/vectors.json

    /**
     * BIP-0039 Test Vector: Standard mnemonic with "TREZOR" passphrase
     * Tests PBKDF2 implementation with passphrase
     */
    @Test
    void shouldGenerateSeedFromMnemonicWithTrezorPassphrase() throws CryptoException {
        String mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        String passphrase = "TREZOR";

        Bytes seed = Bip39Mnemonic.toSeed(mnemonic, passphrase);

        // Expected seed from BIP-0039 specification
        String expectedSeed = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";

        assertEquals(expectedSeed, seed.toUnprefixedHexString());
    }

    /**
     * BIP-0039 Test Vector: Same mnemonic without passphrase
     * Tests that empty passphrase produces different seed
     */
    @Test
    void shouldGenerateSeedFromMnemonicWithoutPassphrase() throws CryptoException {
        String mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        Bytes seed = Bip39Mnemonic.toSeed(mnemonic);

        // Expected seed without passphrase
        String expectedSeed = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

        assertEquals(expectedSeed, seed.toUnprefixedHexString());
    }

    /**
     * BIP-0039 Test Vector: Different mnemonic with passphrase
     * Tests entropy generation and PBKDF2 with different inputs
     */
    @Test
    void shouldGenerateSeedFromLegalWinnerMnemonic() throws CryptoException {
        String mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        String passphrase = "TREZOR";

        Bytes seed = Bip39Mnemonic.toSeed(mnemonic, passphrase);

        // Expected seed from BIP-0039 specification
        String expectedSeed = "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607";

        assertEquals(expectedSeed, seed.toUnprefixedHexString());
    }

    /**
     * BIP-0039 Test Vector: Complex mnemonic
     * Tests handling of more complex word combinations
     */
    @Test
    void shouldGenerateSeedFromLetterAdviceMnemonic() throws CryptoException {
        String mnemonic = "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
        String passphrase = "TREZOR";

        Bytes seed = Bip39Mnemonic.toSeed(mnemonic, passphrase);

        // Expected seed from BIP-0039 specification
        String expectedSeed = "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8";

        assertEquals(expectedSeed, seed.toUnprefixedHexString());
    }

    /**
     * BIP-0039 Test Vector: Another variation
     * Tests consistency across different mnemonic patterns
     */
    @Test
    void shouldGenerateSeedFromZooWrongMnemonic() throws CryptoException {
        String mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
        String passphrase = "TREZOR";

        Bytes seed = Bip39Mnemonic.toSeed(mnemonic, passphrase);

        // Expected seed from BIP-0039 specification
        String expectedSeed = "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069";

        assertEquals(expectedSeed, seed.toUnprefixedHexString());
    }
} 