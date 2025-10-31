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
package io.xdag.crypto.postquantum.dilithium;

import org.bouncycastle.pqc.crypto.crystals.dilithium.DilithiumParameters;

/**
 * Supported Dilithium parameter sets (post-quantum signature scheme selected by NIST).
 */
public enum DilithiumParameter {
    DILITHIUM2(DilithiumParameters.dilithium2, 2),
    DILITHIUM3(DilithiumParameters.dilithium3, 3),
    DILITHIUM5(DilithiumParameters.dilithium5, 5);

    /** Default parameter set providing NIST level-3 security. */
    public static final DilithiumParameter DEFAULT = DILITHIUM3;

    private final DilithiumParameters parameters;
    private final int securityLevel;

    DilithiumParameter(DilithiumParameters parameters, int securityLevel) {
        this.parameters = parameters;
        this.securityLevel = securityLevel;
    }

    public DilithiumParameters getParameters() {
        return parameters;
    }

    public int getSecurityLevel() {
        return securityLevel;
    }
}

