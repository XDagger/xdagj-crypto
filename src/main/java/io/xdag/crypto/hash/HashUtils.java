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
package io.xdag.crypto.hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import lombok.extern.slf4j.Slf4j;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * Cryptographic hash functions for the XDAG crypto library.
 * 
 * <p>This class provides a unified interface for all cryptographic hash
 * operations used in the XDAG ecosystem, including SHA-256, RIPEMD-160,
 * and HMAC operations.
 * 
 * <p>All operations are designed to be thread-safe and use constant-time
 * algorithms where possible to prevent timing attacks. This implementation
 * prioritizes Tuweni Bytes for optimal performance and zero-copy operations.
 */
@Slf4j
public final class HashUtils {

    private static final ThreadLocal<MessageDigest> SHA256_DIGEST =
            ThreadLocal.withInitial(HashUtils::newSha256Digest);

    private HashUtils() {
        // Utility class - prevent instantiation
    }

    /**
     * Get a new SHA-256 MessageDigest instance.
     * 
     * @return a new SHA-256 MessageDigest
     * @throws RuntimeException if SHA-256 is not available (should never happen)
     */
    public static MessageDigest newSha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Compute SHA-256 hash of the given input.
     * 
     * @param input the data to hash
     * @return the SHA-256 hash as Bytes32
     */
    public static Bytes32 sha256(Bytes input) {
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }
        
        MessageDigest digest = SHA256_DIGEST.get();
        digest.reset(); // Reset digest for reuse
        byte[] hash = digest.digest(input.toArrayUnsafe());
        return Bytes32.wrap(hash);
    }

    /**
     * Compute double SHA-256 hash (SHA-256 of SHA-256).
     * This is commonly used in Bitcoin-style protocols.
     * 
     * @param input the data to hash
     * @return the double SHA-256 hash as Bytes32
     */
    public static Bytes32 doubleSha256(Bytes input) {
        Bytes32 firstHash = sha256(input);
        return sha256(firstHash);
    }

    /**
     * Compute Keccak-256 hash of the given input.
     * This is the standard hashing algorithm used in Ethereum.
     *
     * @param input the data to hash
     * @return the Keccak-256 hash as Bytes32
     */
    public static Bytes32 keccak256(Bytes input) {
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }
        KeccakDigest digest = new KeccakDigest(256);
        byte[] inputArray = input.toArrayUnsafe();
        digest.update(inputArray, 0, inputArray.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return Bytes32.wrap(hash);
    }

    /**
     * Compute RIPEMD-160 hash of the given input.
     * 
     * @param input the data to hash
     * @return the RIPEMD-160 hash as Bytes (20 bytes)
     */
    public static Bytes ripemd160(Bytes input) {
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }
        
        RIPEMD160Digest digest = new RIPEMD160Digest();
        byte[] inputArray = input.toArrayUnsafe();
        digest.update(inputArray, 0, inputArray.length);
        
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        
        return Bytes.wrap(hash);
    }

    /**
     * Compute SHA-256 followed by RIPEMD-160 hash.
     * This is the standard Bitcoin address hashing method.
     * 
     * @param input the data to hash
     * @return the hash160 result as Bytes (20 bytes)
     */
    public static Bytes sha256hash160(Bytes input) {
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }
        
        Bytes32 sha256Hash = sha256(input);
        return ripemd160(sha256Hash);
    }

    /**
     * Compute HMAC-SHA-256 of the given data with the specified key.
     * 
     * @param key the HMAC key
     * @param data the data to authenticate
     * @return the HMAC-SHA-256 result as Bytes32
     */
    public static Bytes32 hmacSha256(Bytes key, Bytes data) {
        if (key == null || data == null) {
            throw new IllegalArgumentException("Key and data cannot be null");
        }
        
        HMac hmac = new HMac(new SHA256Digest());
        hmac.init(new KeyParameter(key.toArrayUnsafe()));
        
        byte[] dataArray = data.toArrayUnsafe();
        hmac.update(dataArray, 0, dataArray.length);
        
        byte[] result = new byte[hmac.getMacSize()];
        hmac.doFinal(result, 0);
        
        return Bytes32.wrap(result);
    }

    /**
     * Perform a secure comparison of two Bytes in constant time.
     * This prevents timing attacks when comparing sensitive data.
     * 
     * @param a the first Bytes
     * @param b the second Bytes
     * @return true if the Bytes are equal, false otherwise
     */
    public static boolean constantTimeEquals(Bytes a, Bytes b) {
        if (a == null || b == null) {
            return a == b;
        }
        
        if (a.size() != b.size()) {
            return false;
        }
        
        int result = 0;
        for (int i = 0; i < a.size(); i++) {
            result |= a.get(i) ^ b.get(i);
        }
        
        return result == 0;
    }

    /**
     * Perform a secure comparison of two byte arrays in constant time.
     * Legacy method - prefer Bytes version for better performance.
     * 
     * @param a the first byte array
     * @param b the second byte array
     * @return true if the arrays are equal, false otherwise
     */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) {
            return a == b;
        }
        
        return constantTimeEquals(Bytes.wrap(a), Bytes.wrap(b));
    }
} 