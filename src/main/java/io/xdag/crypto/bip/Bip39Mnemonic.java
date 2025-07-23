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

import io.xdag.crypto.core.CryptoProvider;
import io.xdag.crypto.exception.CryptoException;
import io.xdag.crypto.hash.HashUtils;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collections;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * BIP39 mnemonic code generator and seed derivation with simplified, developer-friendly API.
 * 
 * <p>This class implements the BIP39 specification focused on the most common use case:
 * 12-word mnemonics (128 bits of entropy). It provides a clean, string-based API for
 * generating, validating, and converting mnemonics to seeds.
 * 
 * <p>Key features:
 * - Generate 12-word mnemonics (128-bit entropy)
 * - Simple string-based API (no List&lt;String&gt; handling required)
 * - Validate mnemonic checksums
 * - Convert mnemonics to seeds using PBKDF2
 * - Support for passphrases
 * - Zero-copy operations using Tuweni Bytes
 * 
 * <p>Example usage:
 * <pre>{@code
 * // Generate new mnemonic
 * String mnemonic = Bip39Mnemonic.generateString();
 * 
 * // Validate existing mnemonic
 * boolean valid = Bip39Mnemonic.isValid(mnemonic);
 * 
 * // Convert to seed
 * Bytes seed = Bip39Mnemonic.toSeed(mnemonic);
 * }</pre>
 * 
 * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki">BIP39 Specification</a>
 */
@Slf4j
public final class Bip39Mnemonic {

    /** Number of PBKDF2 iterations for seed generation */
    private static final int PBKDF2_ITERATIONS = 2048;
    
    /** Expected seed length in bytes */
    private static final int SEED_LENGTH = 64;
    
    /** Mnemonic passphrase prefix for PBKDF2 */
    private static final String MNEMONIC_PASSPHRASE_PREFIX = "mnemonic";

    private static final List<String> WORD_LIST;
    
    static {
        try {
            WORD_LIST = loadWordList();
        } catch (IOException e) {
            throw new RuntimeException("Failed to load BIP39 word list", e);
        }
    }

    private Bip39Mnemonic() {
        // Utility class - prevent instantiation
    }

    // ============================= Simple String API =============================
    
    /**
     * Generate a random 12-word mnemonic as a space-separated string.
     * 
     * @return 12-word mnemonic as "word1 word2 word3..."
     * @throws CryptoException if generation fails
     */
    public static String generateString() throws CryptoException {
        return String.join(" ", generateMnemonic());
    }
    
    /**
     * Validate mnemonic checksum.
     * 
     * @param mnemonic space-separated mnemonic string
     * @return true if valid
     */
    public static boolean isValid(String mnemonic) {
        try {
            List<String> words = parseMnemonic(mnemonic);
            return validateMnemonic(words);
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Convert mnemonic to seed.
     * 
     * @param mnemonic space-separated mnemonic string
     * @return 64-byte seed
     * @throws CryptoException if invalid mnemonic
     */
    public static Bytes toSeed(String mnemonic) throws CryptoException {
        return toSeed(mnemonic, null);
    }
    
    /**
     * Convert mnemonic to seed with passphrase.
     * 
     * @param mnemonic space-separated mnemonic string
     * @param passphrase optional passphrase (can be null)
     * @return 64-byte seed
     * @throws CryptoException if invalid mnemonic
     */
    public static Bytes toSeed(String mnemonic, String passphrase) throws CryptoException {
        List<String> words = parseMnemonic(mnemonic);
        return mnemonicToSeed(words, passphrase);
    }

    // ============================= Internal Methods =============================
    
    /**
     * Generate a random 12-word mnemonic.
     * Internal method for generating mnemonics.
     * 
     * @return 12-word mnemonic as a list
     * @throws CryptoException if generation fails
     */
    private static List<String> generateMnemonic() throws CryptoException {
        byte[] entropy = CryptoProvider.getRandomBytes(16); // 128 bits = 16 bytes
        return generateMnemonic(Bytes.wrap(entropy));
    }
    
    /**
     * Parse mnemonic string into word list.
     * Internal method for parsing mnemonic strings.
     * 
     * @param mnemonic space-separated mnemonic string
     * @return list of words
     * @throws CryptoException if invalid format
     */
    private static List<String> parseMnemonic(String mnemonic) throws CryptoException {
        if (mnemonic == null || mnemonic.trim().isEmpty()) {
            throw new CryptoException("Mnemonic cannot be null or empty");
        }
        
        String[] words = mnemonic.trim().toLowerCase().split("\\s+");
        if (words.length != 12) {
            throw new CryptoException("Mnemonic must have exactly 12 words, got: " + words.length);
        }
        
        List<String> result = new ArrayList<>();
        for (String word : words) {
            if (!isValidWord(word)) {
                throw new CryptoException("Invalid word: " + word);
            }
            result.add(word);
        }
        
        return result;
    }
    
    /**
     * Validate a mnemonic by checking its checksum.
     * Internal method for validating mnemonic word lists.
     *
     * @param mnemonic the mnemonic words
     * @return true if the mnemonic is valid, false otherwise
     */
    private static boolean validateMnemonic(List<String> mnemonic) {
        if (mnemonic == null || mnemonic.isEmpty()) {
            return false;
        }

        try {
            // Check word count
            int wordCount = mnemonic.size();
            if (wordCount % 3 != 0 || wordCount < 12 || wordCount > 24) {
                return false;
            }

            // Convert words to indices
            int[] indices = new int[wordCount];
            for (int i = 0; i < wordCount; i++) {
                int index = WORD_LIST.indexOf(mnemonic.get(i));
                if (index == -1) {
                    return false;
                }
                indices[i] = index;
            }

            // Convert to bit array
            BitSet bits = new BitSet();
            for (int i = 0; i < wordCount; i++) {
                for (int j = 0; j < 11; j++) {
                    if ((indices[i] & (1 << (10 - j))) != 0) {
                        bits.set(i * 11 + j);
                    }
                }
            }

            // Split entropy and checksum
            int totalBits = wordCount * 11;
            int checksumLength = totalBits / 33;
            int entropyLength = totalBits - checksumLength;

            byte[] entropy = bitsToBytes(bits, entropyLength);
            
            // Calculate expected checksum with mask
            Bytes32 hash = HashUtils.sha256(Bytes.wrap(entropy));
            byte checksumMask = (byte) (0xff << (8 - checksumLength));
            byte expectedChecksum = (byte) (hash.get(0) & checksumMask);

            // Extract actual checksum
            byte actualChecksum = 0;
            for (int i = 0; i < checksumLength; i++) {
                if (bits.get(entropyLength + i)) {
                    actualChecksum |= (1 << (7 - i));
                }
            }

            // Compare checksums (constant time)
            return HashUtils.constantTimeEquals(
                new byte[]{expectedChecksum}, 
                new byte[]{actualChecksum}
            );

        } catch (Exception e) {
            log.debug("Mnemonic validation failed", e);
            return false;
        }
    }

    /**
     * Convert a mnemonic back to its original entropy.
     *
     * @param mnemonic the mnemonic words
     * @return the original entropy as Bytes
     * @throws CryptoException if the mnemonic is invalid
     */
    public static Bytes mnemonicToEntropy(List<String> mnemonic) throws CryptoException {
        if (!validateMnemonic(mnemonic)) {
            throw new CryptoException("Invalid mnemonic");
        }

        try {
            int wordCount = mnemonic.size();
            int[] indices = new int[wordCount];
            
            for (int i = 0; i < wordCount; i++) {
                indices[i] = WORD_LIST.indexOf(mnemonic.get(i));
            }

            BitSet bits = new BitSet();
            for (int i = 0; i < wordCount; i++) {
                for (int j = 0; j < 11; j++) {
                    if ((indices[i] & (1 << (10 - j))) != 0) {
                        bits.set(i * 11 + j);
                    }
                }
            }

            int totalBits = wordCount * 11;
            int checksumLength = totalBits / 33;
            int entropyLength = totalBits - checksumLength;

            byte[] entropy = bitsToBytes(bits, entropyLength);
            return Bytes.wrap(entropy);

        } catch (Exception e) {
            throw new CryptoException("Failed to convert mnemonic to entropy", e);
        }
    }

    /**
     * Generate a seed from a mnemonic and optional passphrase using PBKDF2.
     *
     * @param mnemonic the mnemonic words
     * @param passphrase the optional passphrase (empty string if none)
     * @return the derived seed as Bytes (64 bytes)
     * @throws CryptoException if seed generation fails
     */
    public static Bytes mnemonicToSeed(List<String> mnemonic, String passphrase) throws CryptoException {
        if (mnemonic == null || mnemonic.isEmpty()) {
            throw new CryptoException("Mnemonic cannot be null or empty");
        }
        
        if (passphrase == null) {
            passphrase = "";
        }

        try {
            // Normalize and prepare inputs
            String mnemonicString = String.join(" ", mnemonic);
            String normalizedMnemonic = Normalizer.normalize(mnemonicString, Normalizer.Form.NFKD);
            String normalizedPassphrase = Normalizer.normalize(
                MNEMONIC_PASSPHRASE_PREFIX + passphrase, 
                Normalizer.Form.NFKD
            );

            // Generate seed using PBKDF2
            PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA512Digest());
            generator.init(
                normalizedMnemonic.getBytes(StandardCharsets.UTF_8),
                normalizedPassphrase.getBytes(StandardCharsets.UTF_8),
                PBKDF2_ITERATIONS
            );

            KeyParameter key = (KeyParameter) generator.generateDerivedParameters(SEED_LENGTH * 8);
            return Bytes.wrap(key.getKey());

        } catch (Exception e) {
            throw new CryptoException("Failed to generate seed from mnemonic", e);
        }
    }

    /**
     * Generate a seed from a mnemonic without passphrase.
     *
     * @param mnemonic the mnemonic words
     * @return the derived seed as Bytes (64 bytes)
     * @throws CryptoException if seed generation fails
     */
    public static Bytes mnemonicToSeed(List<String> mnemonic) throws CryptoException {
        return mnemonicToSeed(mnemonic, "");
    }

    /**
     * Get the complete BIP39 word list.
     *
     * @return an unmodifiable list of all BIP39 words
     */
    public static List<String> getWordList() {
        return Collections.unmodifiableList(WORD_LIST);
    }

    /**
     * Check if a word exists in the BIP39 word list.
     *
     * @param word the word to check
     * @return true if the word exists, false otherwise
     */
    public static boolean isValidWord(String word) {
        return word != null && WORD_LIST.contains(word.toLowerCase());
    }

    // ======================
    // Private Helper Methods
    // ======================

    private static List<String> loadWordList() throws IOException {
        List<String> words = new ArrayList<>(2048);
        
        try (InputStream inputStream = Bip39Mnemonic.class.getResourceAsStream("/en-mnemonic-word-list.txt");
             BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    words.add(line);
                }
            }
        }

        if (words.size() != 2048) {
            throw new IOException("Expected 2048 words in BIP39 word list, found " + words.size());
        }

        return words;
    }

    private static BitSet bytesToBits(byte[] bytes) {
        BitSet bits = new BitSet();
        for (int i = 0; i < bytes.length; i++) {
            for (int j = 0; j < 8; j++) {
                if ((bytes[i] & (1 << (7 - j))) != 0) {
                    bits.set(i * 8 + j);
                }
            }
        }
        return bits;
    }

    private static byte[] bitsToBytes(BitSet bits, int bitLength) {
        int byteLength = (bitLength + 7) / 8;
        byte[] bytes = new byte[byteLength];
        
        for (int i = 0; i < bitLength; i++) {
            if (bits.get(i)) {
                bytes[i / 8] |= (1 << (7 - (i % 8)));
            }
        }
        
        return bytes;
    }

    /**
     * Generate a mnemonic from the given entropy.
     * Internal method for generating mnemonics from entropy bytes.
     *
     * @param entropy the entropy bytes
     * @return the generated mnemonic as a list of words
     * @throws CryptoException if entropy is invalid
     */
    private static List<String> generateMnemonic(Bytes entropy) throws CryptoException {
        if (entropy == null || entropy.size() < 16 || entropy.size() > 32 || entropy.size() % 4 != 0) {
            throw new CryptoException("Entropy must be 16-32 bytes and divisible by 4");
        }

        try {
            // Calculate checksum with mask
            int entropySize = entropy.size();
            Bytes32 hash = HashUtils.sha256(entropy);
            byte checksumMask = (byte) (0xff << (8 - entropySize / 4));
            byte checksumByte = (byte) (hash.get(0) & checksumMask);

            // Convert to bit array
            BitSet entropyBits = bytesToBits(entropy.toArrayUnsafe());
            BitSet checksumBits = new BitSet();
            
            int checksumLength = entropy.size() / 4;
            for (int i = 0; i < checksumLength; i++) {
                if ((checksumByte & (1 << (7 - i))) != 0) {
                    checksumBits.set(i);
                }
            }

            // Combine entropy and checksum
            BitSet combined = new BitSet();
            for (int i = 0; i < entropyBits.length(); i++) {
                if (entropyBits.get(i)) {
                    combined.set(i);
                }
            }
            
            int entropyBitLength = entropy.size() * 8;
            for (int i = 0; i < checksumLength; i++) {
                if (checksumBits.get(i)) {
                    combined.set(entropyBitLength + i);
                }
            }

            // Convert to word indices
            int totalBits = entropyBitLength + checksumLength;
            int wordCount = totalBits / 11;
            List<String> mnemonic = new ArrayList<>(wordCount);

            for (int i = 0; i < wordCount; i++) {
                int wordIndex = 0;
                for (int j = 0; j < 11; j++) {
                    if (combined.get(i * 11 + j)) {
                        wordIndex |= (1 << (10 - j));
                    }
                }
                mnemonic.add(WORD_LIST.get(wordIndex));
            }

            return mnemonic;

        } catch (Exception e) {
            throw new CryptoException("Failed to generate mnemonic", e);
        }
    }
} 