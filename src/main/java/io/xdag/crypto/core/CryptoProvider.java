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
import java.security.Security;
import java.util.concurrent.atomic.AtomicBoolean;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

/**
 * Unified cryptographic provider that manages Bouncy Castle security provider,
 * curve parameters, and secure random number generation.
 *
 * <p>This class provides:
 * - Bouncy Castle provider installation and management
 * - SECP256K1 elliptic curve parameters
 * - Thread-safe cryptographically secure random number generation
 *
 * <p>Design decisions:
 * - Uses a global SecureRandom instance rather than ThreadLocal instances
 * - SecureRandom is inherently thread-safe, so no additional synchronization needed
 * - Simpler design prioritizes code clarity over micro-optimizations
 *
 * @see <a href="http://www.bouncycastle.org/wiki/display/JA1/Provider+Installation">Bouncy Castle Provider Installation</a>
 */
@Slf4j
public final class CryptoProvider {

    /** The standard elliptic curve algorithm used for signatures. */
    public static final String ALGORITHM = "ECDSA";
    /** The name of the Bouncy Castle security provider. */
    public static final String BOUNCY_CASTLE_PROVIDER = "BC";
    /** The name of the elliptic curve being used. */
    public static final String CURVE_NAME = "secp256k1";

    /** The elliptic curve parameter specification for secp256k1. */
    public static final ECParameterSpec CURVE;

    private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName(CURVE_NAME);
    private static final ECDomainParameters CURVE_DOMAIN = new ECDomainParameters(
            CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());

    // Global SecureRandom instance - SecureRandom is thread-safe by design
    private static volatile SecureRandom secureRandom;
    
    private static final AtomicBoolean initialized = new AtomicBoolean(false);
    private static final Object INIT_LOCK = new Object();

    static {
        initialize();
        CURVE = new ECParameterSpec(
                CURVE_PARAMS.getCurve(),
                CURVE_PARAMS.getG(),
                CURVE_PARAMS.getN(),
                CURVE_PARAMS.getH());
    }

    private CryptoProvider() {
        // Utility class
    }

    // ============================= Provider Management =============================

    /**
     * Initializes the cryptographic provider and registers the Bouncy Castle security provider.
     * This method is thread-safe and idempotent.
     */
    public static void initialize() {
        if (!initialized.get()) {
            synchronized (INIT_LOCK) {
                if (!initialized.get()) {
                    if (Security.getProvider(BOUNCY_CASTLE_PROVIDER) == null) {
                        Security.addProvider(new BouncyCastleProvider());
                        log.info("Bouncy Castle provider registered successfully.");
                    } else {
                        log.debug("Bouncy Castle provider is already registered.");
                    }
                    
                    // Initialize the global SecureRandom instance
                    secureRandom = createSecureRandom();
                    
                    initialized.set(true);
                    log.info("CryptoProvider initialized.");
                }
            }
        }
    }

    /**
     * Checks if the crypto provider has been initialized.
     *
     * @return true if initialized, false otherwise
     */
    public static boolean isInstalled() {
        return initialized.get();
    }

    // ============================= Curve Parameters =============================

    /**
     * Returns the SECP256K1 curve domain parameters.
     *
     * @return the ECDomainParameters for secp256k1
     */
    public static ECDomainParameters getCurve() {
        return CURVE_DOMAIN;
    }

    // ============================= Secure Random Generation =============================

    /**
     * Returns the global {@link SecureRandom} instance.
     * 
     * <p><strong>Thread Safety:</strong> SecureRandom is inherently thread-safe according to 
     * Oracle's documentation. This single global instance can be safely used by multiple 
     * threads concurrently without additional synchronization.
     * 
     * <p>This method ensures the SecureRandom instance is always available and never returns null.
     * 
     * @return the global SecureRandom instance, never null
     * @see <a href="https://docs.oracle.com/en/java/javase/11/docs/api/java.base/java/security/SecureRandom.html">SecureRandom Thread Safety</a>
     */
    public static SecureRandom getSecureRandom() {
        SecureRandom instance = secureRandom;
        if (instance == null) {
            // This should never happen due to static initialization, but provide safety
            synchronized (INIT_LOCK) {
                if (secureRandom == null) {
                    initialize();
                }
                instance = secureRandom;
            }
        }
        return instance;
    }
    
    /**
     * Generates a specified number of random bytes.
     *
     * @param numBytes the number of random bytes to generate
     * @return a byte array containing the random bytes
     * @throws IllegalArgumentException if numBytes is negative
     */
    public static byte[] nextBytes(int numBytes) {
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
    public static int nextInt() {
        return getSecureRandom().nextInt();
    }

    /**
     * Generate a cryptographically secure random integer within a range.
     *
     * @param min the minimum value (inclusive)
     * @param max the maximum value (exclusive)
     * @return a random integer between min (inclusive) and max (exclusive)
     */
    public static int nextInt(int min, int max) {
        return getSecureRandom().nextInt(min, max);
    }
    
    /**
     * Generate a cryptographically secure random long.
     * 
     * @return a random long
     */
    public static long nextLong() {
        return getSecureRandom().nextLong();
    }

    /**
     * Generate a cryptographically secure random long within a range.
     *
     * @param lower the minimum value (inclusive)
     * @param upper the maximum value (exclusive)
     * @return a random long between lower (inclusive) and upper (exclusive)
     */
    public static long nextLong(long lower, long upper) {
        return getSecureRandom().nextLong(lower, upper);
    }

    /**
     * Reseed the global SecureRandom instance with entropy from the system.
     * 
     * <p><strong>Note:</strong> In most cases, manual reseeding is unnecessary as SecureRandom 
     * automatically reseeds itself as needed. This method is provided for special cases where
     * explicit reseeding is required.
     * 
     * <p>This method uses SecureRandom's own seed generation rather than potentially 
     * predictable sources like System.nanoTime().
     * 
     * @throws UnsupportedOperationException if the underlying SecureRandom implementation 
     *         does not support manual reseeding
     */
    public static void reseed() {
        SecureRandom sr = getSecureRandom();
        try {
            // Use SecureRandom's own generateSeed method for cryptographically secure entropy
            byte[] seed = sr.generateSeed(32); // 256 bits of entropy
            sr.setSeed(seed);
            log.debug("Reseeded global SecureRandom instance with 256 bits of entropy");
        } catch (Exception e) {
            log.warn("Failed to reseed SecureRandom, it will continue with automatic seeding", e);
            throw new UnsupportedOperationException("Manual reseeding not supported by this SecureRandom implementation", e);
        }
    }

    // ============================= Internal Methods =============================

    /**
     * Creates and configures a new {@link SecureRandom} instance.
     * This method attempts to use the most secure random implementation available.
     *
     * @return a new configured {@link SecureRandom} instance
     */
    private static SecureRandom createSecureRandom() {
        // Try Bouncy Castle's SHA1PRNG first (more widely supported than DRBG)
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG", BOUNCY_CASTLE_PROVIDER);
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
} 