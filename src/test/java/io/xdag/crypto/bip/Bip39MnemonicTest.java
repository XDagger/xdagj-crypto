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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.xdag.crypto.exception.CryptoException;
import java.util.Arrays;
import java.util.List;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

class Bip39MnemonicTest {

    private static final String VALID_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    private static final List<String> VALID_MNEMONIC_WORDS = Arrays.asList(VALID_MNEMONIC.split(" "));

    @Test
    void shouldGenerateValidRandomMnemonic() throws CryptoException {
        List<String> mnemonic = Bip39Mnemonic.generateMnemonic(128);
        assertThat(mnemonic).hasSize(12);
        assertTrue(Bip39Mnemonic.validateMnemonic(mnemonic));
    }

    @Test
    void shouldGenerateMnemonicFromEntropy() throws CryptoException {
        byte[] entropy = new byte[16];
        entropy[0] = 0x00;
        List<String> actualMnemonic = Bip39Mnemonic.generateMnemonic(entropy);
        
        assertEquals(VALID_MNEMONIC_WORDS, actualMnemonic);
    }

    @Test
    void shouldConvertMnemonicToEntropy() throws CryptoException {
        Bytes actualEntropy = Bip39Mnemonic.mnemonicToEntropy(VALID_MNEMONIC_WORDS);
        
        // Expected entropy for the "abandon..." mnemonic
        String expectedHex = "00000000000000000000000000000000";
        assertEquals(expectedHex, actualEntropy.toUnprefixedHexString());
    }

    @Test
    void shouldValidateValidMnemonic() {
        assertTrue(Bip39Mnemonic.validateMnemonic(VALID_MNEMONIC_WORDS));
    }

    @Test
    void shouldRejectInvalidMnemonic() {
        List<String> invalidMnemonic = Arrays.asList("invalid", "words", "that", "are", "not", "in", "wordlist", "at", "all", "please", "reject", "this");
        assertFalse(Bip39Mnemonic.validateMnemonic(invalidMnemonic));
    }

    @Test
    void shouldGenerateSeedFromMnemonic() throws CryptoException {
        Bytes seed = Bip39Mnemonic.mnemonicToSeed(VALID_MNEMONIC_WORDS, "TREZOR");
        
        // Expected seed for the "abandon..." mnemonic with "TREZOR" passphrase
        String expectedSeed = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
        assertEquals(expectedSeed, seed.toUnprefixedHexString());
    }

    @Test
    void shouldGenerateSeedFromMnemonicWithoutPassphrase() throws CryptoException {
        Bytes seed = Bip39Mnemonic.mnemonicToSeed(VALID_MNEMONIC_WORDS);
        
        // Expected seed for the "abandon..." mnemonic with empty passphrase
        String expectedSeed = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";
        assertEquals(expectedSeed, seed.toUnprefixedHexString());
    }

    @Test
    void shouldCheckValidWords() {
        assertTrue(Bip39Mnemonic.isValidWord("abandon"));
        assertTrue(Bip39Mnemonic.isValidWord("about"));
        assertFalse(Bip39Mnemonic.isValidWord("invalid"));
        assertFalse(Bip39Mnemonic.isValidWord(""));
        assertFalse(Bip39Mnemonic.isValidWord(null));
    }

    @Test
    void shouldProvideWordList() {
        List<String> wordList = Bip39Mnemonic.getWordList();
        assertThat(wordList).hasSize(2048);
        assertThat(wordList.get(0)).isEqualTo("abandon");
        assertThat(wordList.get(2047)).isEqualTo("zoo");
    }
} 