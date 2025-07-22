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

import java.security.Security;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

/**
 * Utility class for managing the Bouncy Castle security provider and cryptographic curve parameters.
 *
 * <p>This class manages the initialization of the BouncyCastle security provider
 * and provides access to standard cryptographic parameters, such as the SECP256K1
 * curve, used throughout the library.
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

    private static volatile boolean initialized = false;
    private static final Object INIT_LOCK = new Object();

    static {
        install();
        CURVE = new ECParameterSpec(
                CURVE_PARAMS.getCurve(),
                CURVE_PARAMS.getG(),
                CURVE_PARAMS.getN(),
                CURVE_PARAMS.getH());
    }

    private CryptoProvider() {
        // Utility class
    }

    /**
     * Initializes and registers the Bouncy Castle security provider.
     * This method is thread-safe and idempotent.
     */
    public static void install() {
        if (!initialized) {
            synchronized (INIT_LOCK) {
                if (!initialized) {
                    if (Security.getProvider(BOUNCY_CASTLE_PROVIDER) == null) {
                        Security.addProvider(new BouncyCastleProvider());
                        log.info("Bouncy Castle provider registered successfully.");
                    } else {
                        log.debug("Bouncy Castle provider is already registered.");
                    }
                    initialized = true;
                    log.info("CryptoProvider initialized.");
                }
            }
        }
    }

    /**
     * Returns the SECP256K1 curve domain parameters.
     *
     * @return the ECDomainParameters for secp256k1
     */
    public static ECDomainParameters getCurve() {
        return CURVE_DOMAIN;
    }

    /**
     * Checks if the crypto provider has been initialized.
     *
     * @return true if initialized, false otherwise
     */
    public static boolean isInstalled() {
        return initialized;
    }
} 