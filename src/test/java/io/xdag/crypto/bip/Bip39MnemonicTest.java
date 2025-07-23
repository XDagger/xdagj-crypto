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
} 