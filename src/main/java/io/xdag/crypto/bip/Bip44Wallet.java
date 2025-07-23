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
import io.xdag.crypto.core.KeyValidator;
import io.xdag.crypto.exception.CryptoException;
import io.xdag.crypto.hash.HashUtils;
import io.xdag.crypto.keys.ECKeyPair;
import io.xdag.crypto.keys.PrivateKey;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * BIP44 Hierarchical Deterministic (HD) Wallet implementation for XDAG.
 * 
 * <p>This class implements BIP32 hierarchical deterministic key derivation
 * specifically for XDAG cryptocurrency following the BIP44 standard. It provides 
 * methods for creating master keys from seeds and deriving child keys using the
 * standardized derivation path.
 * 
 * <p>The BIP44 standard defines a specific structure for HD wallets:
 * {@code m / purpose' / coin_type' / account' / change / address_index}
 * 
 * <p>For XDAG, the derivation path is:
 * {@code m / 44' / 586' / account' / 0 / address_index}
 * where 586 is XDAG's registered coin type.
 * 
 * <p><strong>Security Note:</strong> Seeds and private keys are handled securely with
 * constant-time operations where possible to prevent timing attacks.
 * 
 * <p><strong>Thread Safety:</strong> This class is stateless and thread-safe.
 * 
 * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">BIP32</a>
 * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki">BIP44</a>
 */
public final class Bip44Wallet {

    /** BIP44 purpose constant (44'). */
    public static final int PURPOSE = 0x8000002C; // 44'

    /** XDAG coin type constant (586'). */
    public static final int XDAG_COIN_TYPE = 0x8000024A; // 586'

    /** Hardened derivation bit. */
    private static final int HARDENED_BIT = 0x80000000;

    /** HMAC-SHA512 key for master key generation. */
    private static final String BITCOIN_SEED = "Bitcoin seed";

    private Bip44Wallet() {
        // Utility class - prevent instantiation
    }

    /**
     * Creates a master key from a seed according to BIP32 specification.
     * 
     * <p>This method generates the root of the HD wallet hierarchy from which all
     * other keys can be derived. The seed should be generated from a BIP39 mnemonic
     * for standardized entropy and recovery.
     * 
     * <p>To extract just the cryptographic key pair from the result, use
     * {@code createMasterKey(seed).keyPair()}.
     * 
     * @param seed the cryptographic seed (typically 64 bytes from BIP39)
     * @return a new Bip32Key representing the master key
     * @throws CryptoException if key generation fails
     */
    public static Bip32Key createMasterKey(byte[] seed) throws CryptoException {
        if (seed == null || seed.length < 16) {
            throw new CryptoException("Seed must be at least 16 bytes");
        }

        try {
            // Generate master key using HMAC-SHA512
            HMac hmac = new HMac(new SHA512Digest());
            hmac.init(new KeyParameter(BITCOIN_SEED.getBytes(StandardCharsets.UTF_8)));
            hmac.update(seed, 0, seed.length);

            byte[] i = new byte[hmac.getMacSize()];
            hmac.doFinal(i, 0);

            // Split result: first 32 bytes = private key, last 32 bytes = chain code
            BigInteger privateKey = new BigInteger(1, Arrays.copyOfRange(i, 0, 32));
            if (!KeyValidator.isValidDerivedKeyRange(privateKey)) {
                throw new CryptoException("Invalid master private key generated");
            }

            ECKeyPair masterKeyPair = ECKeyPair.fromPrivateKey(PrivateKey.fromBigInteger(privateKey));
            Bytes32 chainCode = Bytes32.wrap(Arrays.copyOfRange(i, 32, 64));

            return new Bip32Key(masterKeyPair, chainCode, 0, 0, Bytes.EMPTY);

        } catch (Exception e) {
            throw new CryptoException("Failed to create master key", e);
        }
    }

    /**
     * Derives an XDAG key using BIP44 standard derivation path.
     * 
     * <p>This method derives a key at the path {@code m/44'/586'/account'/0/addressIndex}
     * which is the standard path for XDAG addresses according to BIP44.
     * 
     * <p>Both account and addressIndex should be non-negative integers.
     * The method handles the hardened derivation internally.
     * 
     * @param master the master key from which to derive
     * @param account the account index (will be hardened automatically)
     * @param addressIndex the address index within the account
     * @return the derived Bip32Key for the specified path
     * @throws CryptoException if derivation fails
     */
    public static Bip32Key deriveXdagKey(Bip32Key master, int account, int addressIndex) throws CryptoException {
        if (account < 0 || addressIndex < 0) {
            throw new CryptoException("Account and address index must be non-negative");
        }

        // Build BIP44 path: m/44'/586'/account'/0/addressIndex
        int[] path = {PURPOSE, XDAG_COIN_TYPE, HARDENED_BIT | account, 0, addressIndex};
        return derivePath(master, path);
    }

    /**
     * Derives a key following the specified derivation path.
     * 
     * <p>The path is an array of integers where hardened derivation is indicated
     * by setting the most significant bit (>= 0x80000000).
     * 
     * @param parent the parent key from which to derive
     * @param path the derivation path as an array of child numbers
     * @return the derived Bip32Key
     * @throws CryptoException if any step of the derivation fails
     */
    public static Bip32Key derivePath(Bip32Key parent, int[] path) throws CryptoException {
        Bip32Key current = parent;
        for (int childNumber : path) {
            boolean isHardened = (childNumber & HARDENED_BIT) != 0;
            current = deriveChildKey(current, childNumber, isHardened);
        }
        return current;
    }

    private static Bip32Key deriveChildKey(Bip32Key parent, int childNumber, boolean isHardened) throws CryptoException {
        Bytes data;
        if (isHardened) {
            BigInteger privateKey = parent.keyPair().getPrivateKey().toBigInteger();
            // Use 33-byte format (0x00 prefix), consistent with original xdagj BIP44 implementation
            byte[] privateKeyBytes = bigIntegerToBytes33WithPrefix(privateKey);
            data = Bytes.concatenate(Bytes.wrap(privateKeyBytes), intToBytes(childNumber));
        } else {
            byte[] publicKey = parent.keyPair().getPublicKey().toCompressedBytes().toArrayUnsafe();
            data = Bytes.concatenate(Bytes.wrap(publicKey), intToBytes(childNumber));
        }

        HMac hmac = new HMac(new SHA512Digest());
        hmac.init(new KeyParameter(parent.chainCode().toArrayUnsafe()));
        hmac.update(data.toArrayUnsafe(), 0, data.size());
        byte[] i = new byte[hmac.getMacSize()];
        hmac.doFinal(i, 0);

        BigInteger il = new BigInteger(1, Arrays.copyOfRange(i, 0, 32));
        if (!KeyValidator.isValidDerivedKeyRange(il)) {
            throw new CryptoException("Derived private key is not in the valid range.");
        }

        BigInteger parentPrivateKey = parent.keyPair().getPrivateKey().toBigInteger();
        BigInteger derivedPrivateKey = parentPrivateKey.add(il).mod(CryptoProvider.getCurve().getN());
        if (!KeyValidator.isValidDerivedKeyRange(derivedPrivateKey)) {
            throw new CryptoException("Derived private key is zero.");
        }

        ECKeyPair derivedKeyPair = ECKeyPair.fromPrivateKey(PrivateKey.fromBigInteger(derivedPrivateKey));
        Bytes32 derivedChainCode = Bytes32.wrap(Arrays.copyOfRange(i, 32, 64));

        byte[] parentPublicKey = parent.keyPair().getPublicKey().toCompressedBytes().toArrayUnsafe();
        Bytes parentFingerprint = HashUtils.sha256hash160(Bytes.wrap(parentPublicKey)).slice(0, 4);
        
        return new Bip32Key(derivedKeyPair, derivedChainCode, parent.depth() + 1, childNumber, parentFingerprint);
    }

    /**
     * Converts a BigInteger to 33 bytes with 0x00 prefix for xdagj compatibility.
     * 
     * <p>This matches the original xdagj's getPrivateKeyBytes33() behavior,
     * which uses 33-byte format for hardened derivation.
     * 
     * @param value the BigInteger value (must be non-negative and fit in 33 bytes)
     * @return a 33-byte array with 0x00 prefix
     * @throws IllegalArgumentException if value is negative or too large
     */
    private static byte[] bigIntegerToBytes33WithPrefix(BigInteger value) {
        if (value.signum() < 0) {
            throw new IllegalArgumentException("BigInteger cannot be negative");
        }
        
        // Convert to 32 bytes first
        byte[] privateKey32 = bigIntegerToBytes32(value);
        
        // Add 0x00 prefix to make it 33 bytes
        byte[] result = new byte[33];
        result[0] = 0x00;
        System.arraycopy(privateKey32, 0, result, 1, 32);
        
        return result;
    }

    /**
     * Converts a BigInteger to exactly 32 bytes for private key serialization.
     */
    private static byte[] bigIntegerToBytes32(BigInteger value) {
        if (value.signum() < 0) {
            throw new IllegalArgumentException("BigInteger cannot be negative");
        }
        
        byte[] bytes = value.toByteArray();
        
        if (bytes.length == 32) {
            return bytes;
        } else if (bytes.length == 33 && bytes[0] == 0) {
            // Remove leading zero byte that Java adds for positive BigIntegers
            return Arrays.copyOfRange(bytes, 1, 33);
        } else if (bytes.length < 32) {
            // Pad with leading zeros to exactly 32 bytes
            byte[] padded = new byte[32];
            System.arraycopy(bytes, 0, padded, 32 - bytes.length, bytes.length);
            return padded;
        } else {
            throw new IllegalArgumentException("BigInteger is too large for 32 bytes");
        }
    }

    /**
     * Converts an integer to 4 bytes in big-endian format.
     */
    private static Bytes intToBytes(int value) {
        return Bytes.of(
                (byte) (value >> 24),
                (byte) (value >> 16),
                (byte) (value >> 8),
                (byte) value);
    }
} 