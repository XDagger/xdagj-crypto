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
import io.xdag.crypto.keys.Keys;
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
 * <p>The implementation follows the BIP44 derivation path:
 * {@code m / purpose' / coin_type' / account' / change / address_index}
 * 
 * <p>For XDAG, the specific path is:
 * {@code m / 44' / 586' / account' / 0 / address_index}
 * 
 * <p>All methods in this class are static and thread-safe. The class cannot
 * be instantiated as it serves as a utility class. The private constructor
 * prevents instantiation and subclassing.
 * 
 * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">BIP32</a>
 * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki">BIP44</a>
 */
public final class Bip44Wallet {

    /** 
     * The hardened derivation bit used in BIP32 key derivation.
     * When this bit is set, it indicates hardened derivation.
     */
    public static final int HARDENED_BIT = 0x80000000;
    private static final Bytes BIP32_SEED_KEY = Bytes.wrap("Bitcoin seed".getBytes(StandardCharsets.UTF_8));
    private static final int XDAG_BIP44_PATH = 44;
    private static final int XDAG_COIN_TYPE = 586;

    /**
     * Private constructor to prevent instantiation.
     * This class serves as a utility class with only static methods.
     */
    private Bip44Wallet() {
        // Utility class - prevent instantiation
    }

    /**
     * Creates a master key pair from a seed according to BIP32 specification.
     * 
     * <p>This method takes a cryptographic seed and generates the master
     * private key and chain code using HMAC-SHA512 with the key "Bitcoin seed".
     * The resulting master key pair can be used as the root for all further
     * key derivations.
     * 
     * @param seed the cryptographic seed bytes (typically 64 bytes from BIP39)
     * @return a new Bip32Node representing the master key pair
     * @throws CryptoException if the generated private key is invalid or out of range
     */
    public static Bip32Node createMasterKeyPair(byte[] seed) throws CryptoException {
        // I = HMAC-SHA512(Key = "Bitcoin seed", Data = seed)
        HMac hmac = new HMac(new SHA512Digest());
        hmac.init(new KeyParameter(BIP32_SEED_KEY.toArrayUnsafe()));
        hmac.update(seed, 0, seed.length);
        byte[] i = new byte[hmac.getMacSize()];
        hmac.doFinal(i, 0);

        // Split I into two 32-byte sequences, IL and IR
        BigInteger il = new BigInteger(1, Arrays.copyOfRange(i, 0, 32));
        if (il.equals(BigInteger.ZERO) || il.compareTo(CryptoProvider.getCurve().getN()) >= 0) {
            throw new CryptoException("Invalid master key generated from seed");
        }

        AsymmetricCipherKeyPair masterKeyPair = Keys.fromPrivateKey(il);
        Bytes32 chainCode = Bytes32.wrap(Arrays.copyOfRange(i, 32, 64));

        return new Bip32Node(masterKeyPair, chainCode, 0, 0, Bytes.wrap(new byte[4]));
    }

    /**
     * Derives an XDAG key pair using BIP44 standard derivation path.
     * 
     * <p>This method implements the XDAG-specific BIP44 derivation path:
     * {@code m / 44' / 586' / account' / 0 / address_index}
     * 
     * @param master the master Bip32Node (created from seed)
     * @param account the account index for derivation
     * @param addressIndex the address index for derivation
     * @return the derived Bip32Node for the specified account and address index
     * @throws CryptoException if key derivation fails at any step
     */
    public static Bip32Node deriveXdagKeyPair(Bip32Node master, int account, int addressIndex) throws CryptoException {
        // BIP44 path: m / 44' / 586' / account' / 0 / address_index
        int[] path = {
            XDAG_BIP44_PATH | HARDENED_BIT,      // 44'
            XDAG_COIN_TYPE | HARDENED_BIT,       // 586' 
            account | HARDENED_BIT,              // account'
            0,                                   // change (external)
            addressIndex                         // address_index
        };
        return derivePath(master, path);
    }

    /**
     * Derives a key pair following the specified derivation path.
     * 
     * <p>This method sequentially derives child keys according to the provided path.
     * Each element in the path represents a child index, with hardened derivation
     * indicated by the {@link #HARDENED_BIT}.
     * 
     * @param parent the parent Bip32Node to start derivation from
     * @param path an array of child indices defining the derivation path
     * @return the final derived Bip32Node
     * @throws CryptoException if any step in the derivation fails
     */
    public static Bip32Node derivePath(Bip32Node parent, int[] path) throws CryptoException {
        Bip32Node current = parent;
        for (int childNumber : path) {
            boolean isHardened = (childNumber & HARDENED_BIT) != 0;
            current = deriveChildKeyPair(current, childNumber, isHardened);
        }
        return current;
    }

    private static Bip32Node deriveChildKeyPair(Bip32Node parent, int childNumber, boolean isHardened) throws CryptoException {
        Bytes data;
        if (isHardened) {
            BigInteger privateKey = ((ECPrivateKeyParameters) parent.keyPair().getPrivate()).getD();
            // 使用33字节格式（0x00前缀），这与原始xdagj的BIP44实现一致
            byte[] privateKeyBytes = bigIntegerToBytes33WithPrefix(privateKey);
            data = Bytes.concatenate(Bytes.wrap(privateKeyBytes), intToBytes(childNumber));
        } else {
            byte[] publicKey = ((ECPublicKeyParameters) parent.keyPair().getPublic()).getQ().getEncoded(true);
            data = Bytes.concatenate(Bytes.wrap(publicKey), intToBytes(childNumber));
        }

        HMac hmac = new HMac(new SHA512Digest());
        hmac.init(new KeyParameter(parent.chainCode().toArrayUnsafe()));
        hmac.update(data.toArrayUnsafe(), 0, data.size());
        byte[] i = new byte[hmac.getMacSize()];
        hmac.doFinal(i, 0);

        BigInteger il = new BigInteger(1, Arrays.copyOfRange(i, 0, 32));
        if (il.compareTo(CryptoProvider.getCurve().getN()) >= 0) {
            throw new CryptoException("Derived private key is not in the valid range.");
        }

        BigInteger parentPrivateKey = ((ECPrivateKeyParameters) parent.keyPair().getPrivate()).getD();
        BigInteger derivedPrivateKey = parentPrivateKey.add(il).mod(CryptoProvider.getCurve().getN());
        if (derivedPrivateKey.equals(BigInteger.ZERO)) {
            throw new CryptoException("Derived private key is zero.");
        }

        AsymmetricCipherKeyPair derivedKeyPair = Keys.fromPrivateKey(derivedPrivateKey);
        Bytes32 derivedChainCode = Bytes32.wrap(Arrays.copyOfRange(i, 32, 64));

        ECPublicKeyParameters pub = (ECPublicKeyParameters) parent.keyPair().getPublic();
        byte[] parentPublicKey = pub.getQ().getEncoded(true);
        Bytes parentFingerprint = HashUtils.sha256hash160(Bytes.wrap(parentPublicKey)).slice(0, 4);
        
        return new Bip32Node(derivedKeyPair, derivedChainCode, parent.depth() + 1, childNumber, parentFingerprint);
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