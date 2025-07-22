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
package io.xdag.crypto.core;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicBoolean;
import lombok.extern.slf4j.Slf4j;

/**
 * Provides a cryptographically secure random number generator (CSRNG).
 * 
 * <p>This class provides thread-safe access to cryptographically secure
 * random number generation, with appropriate seeding and entropy management.
 * 
 * <p>The implementation ensures that:
 * - SecureRandom instances are properly seeded
 * - Thread-local instances are used to avoid contention
 * - Fallback mechanisms are in place for different platforms
 * - Uses the best available random implementation, prioritizing Bouncy Castle when available.
 */
@Slf4j
public final class SecureRandomProvider {
    
    // Thread-local SecureRandom instances to avoid contention
    private static final ThreadLocal<SecureRandom> THREAD_LOCAL_SECURE_RANDOM = 
            ThreadLocal.withInitial(SecureRandomProvider::createSecureRandom);
    
    private static final AtomicBoolean INITIALIZED = new AtomicBoolean(false);
    
    private SecureRandomProvider() {
        // Utility class
    }
    
    /**
     * Returns a singleton instance of {@link SecureRandom}.
     * 
     * @return a thread-safe instance of {@link SecureRandom}
     */
    public static SecureRandom getSecureRandom() {
        return THREAD_LOCAL_SECURE_RANDOM.get();
    }
    
    /**
     * Generates a specified number of random bytes.
     *
     * @param numBytes the number of random bytes to generate
     * @return a byte array containing the random bytes
     */
    public static byte[] getRandomBytes(int numBytes) {
        if (numBytes < 0) {
            throw new IllegalArgumentException("Number of bytes must be non-negative.");
        }
        byte[] bytes = new byte[numBytes];
        getSecureRandom().nextBytes(bytes);
        return bytes;
    }
    
    /**
     * Generate a cryptographically secure random integer.
     * 
     * @return a random integer
     */
    public static int getRandomInt() {
        return getSecureRandom().nextInt();
    }
    
    /**
     * Generate a cryptographically secure random long.
     * 
     * @return a random long
     */
    public static long getRandomLong() {
        return getSecureRandom().nextLong();
    }
    
    /**
     * Creates and configures a new {@link SecureRandom} instance.
     * This method attempts to use the most secure random implementation available.
     *
     * @return a new configured {@link SecureRandom} instance
     */
    private static SecureRandom createSecureRandom() {
        if (!INITIALIZED.getAndSet(true)) {
            CryptoProvider.install();
        }

        // Try Bouncy Castle's SHA1PRNG first (more widely supported than DRBG)
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", CryptoProvider.BOUNCY_CASTLE_PROVIDER);
            log.info("Using SHA1PRNG algorithm from Bouncy Castle provider.");
            return random;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            log.debug("Bouncy Castle SHA1PRNG not available. Trying platform default.", e);
        }

        // Try the default platform implementation
        try {
            SecureRandom random = SecureRandom.getInstanceStrong();
            log.info("Using platform's strong SecureRandom implementation.");
            return random;
        } catch (NoSuchAlgorithmException e) {
            log.debug("Strong SecureRandom not available. Using default.", e);
        }

        // Fallback to the simplest but still secure SecureRandom
        SecureRandom random = new SecureRandom();
        log.info("Using platform default SecureRandom implementation.");
        return random;
    }
    
    /**
     * Reseed the current thread's SecureRandom instance.
     * This should be called periodically in long-running applications.
     */
    public static void reseed() {
        THREAD_LOCAL_SECURE_RANDOM.get().setSeed(System.nanoTime());
        log.debug("Reseeded SecureRandom for current thread");
    }

} 