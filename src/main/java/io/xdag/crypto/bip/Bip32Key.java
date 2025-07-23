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

import io.xdag.crypto.keys.ECKeyPair;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/**
 * Represents a BIP32 hierarchical deterministic key containing a key pair, chain code, and derivation info.
 * 
 * <p>This record encapsulates all the necessary information for a key in a BIP32 HD wallet tree,
 * including the cryptographic key pair, chain code for further derivation, and metadata about
 * its position in the hierarchy. This follows the BIP32 specification's definition of "extended keys".
 *
 * <p>An extended key consists of:
 * <ul>
 *   <li>A key pair (private and public key)</li>
 *   <li>A chain code for deriving child keys</li>
 *   <li>Metadata about its position in the derivation tree</li>
 * </ul>
 * 
 * <p>This class provides a modern API using {@link ECKeyPair} for type-safe key management.
 *
 * @param keyPair The ECKeyPair containing the cryptographic keys.
 * @param chainCode The 32-byte chain code for this key, used for child key derivation.
 * @param depth The depth of this key in the HD tree (0 for master, increments with each derivation).
 * @param childNumber The number used to derive this key from its parent (includes hardened bit if applicable).
 * @param parentFingerprint The first 4 bytes of the parent's public key hash, used for key identification.
 * 
 * @see <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">BIP32 Specification</a>
 */
public record Bip32Key(
        ECKeyPair keyPair,
        Bytes32 chainCode,
        int depth,
        int childNumber,
        Bytes parentFingerprint) {
    

} 