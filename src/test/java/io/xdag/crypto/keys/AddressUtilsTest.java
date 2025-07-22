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
package io.xdag.crypto.keys;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.xdag.crypto.encoding.Base58;
import io.xdag.crypto.exception.AddressFormatException;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.junit.jupiter.api.Test;
import io.xdag.crypto.exception.CryptoException;

class AddressUtilsTest {

    @Test
    void shouldGenerateValidAddressFromPrivateKey() throws AddressFormatException, CryptoException {
        // Known private key
        Bytes32 privateKeyBytes = Bytes32.fromHexString("0x123456789012345678901234567890123456789012345678901234567890abcd");
        AsymmetricCipherKeyPair keyPair = Keys.fromPrivateKey(privateKeyBytes.toBigInteger());

        // Expected address hash (hash160 of compressed public key)
        String expectedAddressHashHex = "0x61fd40ede6ef213a939542e55122ccb61e2b7188";

        // Expected Base58Check address
        String expectedBase58Address = "9w7vyjrHmBcfeJAcSssHDDUhX8oyWdA52";

        // 1. Test address bytes generation
        Bytes addressBytes = AddressUtils.toBytesAddress(keyPair);
        assertThat(addressBytes).isEqualTo(Bytes.fromHexString(expectedAddressHashHex));

        // 2. Test Base58 address generation
        String base58Address = AddressUtils.toBase58Address(keyPair);
        assertThat(base58Address).isEqualTo(expectedBase58Address);

        // 3. Test decoding the address
        Bytes decodedBytes = AddressUtils.fromBase58Address(base58Address);
        assertThat(decodedBytes).isEqualTo(addressBytes);
    }

    @Test
    void shouldValidateAddressLengthCorrectly() {
        assertThat(AddressUtils.isValidAddress(Bytes.random(20))).isTrue();
        assertThat(AddressUtils.isValidAddress(Bytes.random(19))).isFalse();
        assertThat(AddressUtils.isValidAddress(Bytes.random(21))).isFalse();
        assertThat(AddressUtils.isValidAddress(null)).isFalse();
    }

    @Test
    void shouldThrowExceptionForInvalidAddresses() {
        // Invalid checksum from legacy test
        String invalidLegacyChecksumAddress = "7pWm5FZaNVV61wb4vQapqVixPaLC7Dh2a";
        assertThatThrownBy(() -> AddressUtils.fromBase58Address(invalidLegacyChecksumAddress))
                .isInstanceOf(AddressFormatException.InvalidChecksum.class);

        // Invalid checksum
        String invalidChecksumAddress = "PH1YAdVn1ejui3RMN7uSXShcVFkMYTQD1"; // Last char changed
        assertThatThrownBy(() -> AddressUtils.fromBase58Address(invalidChecksumAddress))
                .isInstanceOf(AddressFormatException.InvalidChecksum.class);

        // Invalid character
        String invalidCharAddress = "PH1YAdVn1ejui3RMN7uSXShcVFkMYTQDO"; // Contains 'O'
        assertThatThrownBy(() -> AddressUtils.fromBase58Address(invalidCharAddress))
                .isInstanceOf(AddressFormatException.InvalidCharacter.class);
                
        // Invalid length
        String shortAddress = "PH1YAdVn1ejui3RMN7uSXShcVFkMYTQD";
        assertThatThrownBy(() -> AddressUtils.fromBase58Address(shortAddress))
                .isInstanceOf(AddressFormatException.class);
    }

    @Test
    void shouldBeCompatibleWithKnownLegacyAddress() throws AddressFormatException {
        String knownAddress = "7pWm5FZaNVV61wb4vQapqVixPaLC7Dh2C";

        // 1. Test decoding a known valid address
        Bytes decodedBytes = AddressUtils.fromBase58Address(knownAddress);
        assertThat(decodedBytes).isNotNull();
        assertThat(decodedBytes.size()).isEqualTo(AddressUtils.ADDRESS_LENGTH);

        // 2. Test that encoding the decoded bytes gives back the original address
        String reEncodedAddress = Base58.encodeCheck(decodedBytes);
        assertThat(reEncodedAddress).isEqualTo(knownAddress);
    }

    @Test
    void shouldCheckAddressValidityCorrectly() {
        // Valid address from legacy test
        assertThat(AddressUtils.isLegacyValidAddress("7pWm5FZaNVV61wb4vQapqVixPaLC7Dh2C")).isTrue();
        assertThat(AddressUtils.isLegacyValidAddress("KD77RGFihFaqrJQrKK8MJ21hocJeq32Pf")).isTrue();
        // Invalid address from legacy test
        assertThat(AddressUtils.isLegacyValidAddress("7pWm5FZaNVV61wb4vQapqVixPaLC7Dh2a")).isFalse();
        // Our new format valid address
        assertThat(AddressUtils.isLegacyValidAddress("PH1YAdVn1ejui3RMN7uSXShcVFkMYTQDk")).isTrue();
        // Our new format invalid address
        assertThat(AddressUtils.isLegacyValidAddress("PH1YAdVn1ejui3RMN7uSXShcVFkMYTQD1")).isFalse();
    }
} 