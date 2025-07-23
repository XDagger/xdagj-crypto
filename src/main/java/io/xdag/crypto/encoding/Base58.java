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
package io.xdag.crypto.encoding;

import io.xdag.crypto.exception.AddressFormatException;
import io.xdag.crypto.hash.HashUtils;
import java.util.Arrays;
import lombok.extern.slf4j.Slf4j;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/**
 * Base58 encoding and decoding utilities.
 * 
 * <p>Base58 is a binary-to-text encoding scheme that is commonly used
 * in cryptocurrency applications. It avoids the use of similar-looking
 * characters (0, O, I, l) to reduce user error.
 * 
 * <p>This implementation includes support for:
 * - Standard Base58 encoding/decoding
 * - Base58Check encoding with checksum verification
 * - Thread-safe operations
 * - Constant-time validation where possible
 */
@Slf4j
public final class Base58 {
    
    private static final String BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final char[] ALPHABET = BASE58_ALPHABET.toCharArray();
    private static final int[] INDEXES = new int[128];
    
    static {
        Arrays.fill(INDEXES, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            INDEXES[ALPHABET[i]] = i;
        }
    }
    
    private Base58() {
        // Utility class - prevent instantiation
    }
    
    /**
     * Encode a Bytes object to Base58 string.
     * 
     * @param input the Bytes object to encode
     * @return the Base58 encoded string
     * @throws IllegalArgumentException if input is null
     */
    public static String encode(Bytes input) {
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }
        
        if (input.size() == 0) {
            return "";
        }
        
        // Convert to byte array for processing
        byte[] inputBytes = input.toArrayUnsafe();
        
        // Count leading zeros
        int zeros = 0;
        while (zeros < inputBytes.length && inputBytes[zeros] == 0) {
            zeros++;
        }
        
        // Convert to base58
        inputBytes = Arrays.copyOf(inputBytes, inputBytes.length);
        char[] encoded = new char[inputBytes.length * 2];
        int outputStart = encoded.length;
        
        for (int inputStart = zeros; inputStart < inputBytes.length; ) {
            encoded[--outputStart] = ALPHABET[divmod(inputBytes, inputStart, 256, 58)];
            if (inputBytes[inputStart] == 0) {
                inputStart++;
            }
        }
        
        // Preserve leading zeros
        while (outputStart < encoded.length && encoded[outputStart] == ALPHABET[0]) {
            outputStart++;
        }
        while (--zeros >= 0) {
            encoded[--outputStart] = ALPHABET[0];
        }
        
        return new String(encoded, outputStart, encoded.length - outputStart);
    }
    
    /**
     * Encode a byte array to Base58 string.
     * Legacy compatibility method - prefer {@link #encode(Bytes)}.
     *
     * @param input the byte array to encode
     * @return the Base58 encoded string
     * @throws IllegalArgumentException if input is null
     */
    public static String encode(byte[] input) {
        return encode(Bytes.wrap(input));
    }

    /**
     * Decode a Base58 string to a Bytes object.
     * 
     * @param input the Base58 string to decode
     * @return the decoded Bytes object
     * @throws AddressFormatException if the input contains invalid characters
     */
    public static Bytes decode(String input) throws AddressFormatException {
        if (input == null) {
            throw new IllegalArgumentException("Input cannot be null");
        }
        
        if (input.isEmpty()) {
            return Bytes.EMPTY;
        }
        
        // Convert the string to byte array
        byte[] input58 = new byte[input.length()];
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            int digit = c < 128 ? INDEXES[c] : -1;
            if (digit < 0) {
                throw new AddressFormatException.InvalidCharacter(c, i);
            }
            input58[i] = (byte) digit;
        }
        
        // Count leading zeros
        int zeros = 0;
        while (zeros < input58.length && input58[zeros] == 0) {
            zeros++;
        }
        
        // Convert from base58
        byte[] decoded = new byte[input.length()];
        int outputStart = decoded.length;
        
        for (int inputStart = zeros; inputStart < input58.length; ) {
            decoded[--outputStart] = divmod(input58, inputStart, 58, 256);
            if (input58[inputStart] == 0) {
                inputStart++;
            }
        }
        
        // Ignore extra leading zeros that were added during the calculation
        while (outputStart < decoded.length && decoded[outputStart] == 0) {
            outputStart++;
        }
        
        return Bytes.wrap(Arrays.copyOfRange(decoded, outputStart - zeros, decoded.length));
    }
    
    /**
     * Decode a Base58 string to byte array.
     * Legacy compatibility method - prefer {@link #decode(String)}.
     *
     * @param input the Base58 string to decode
     * @return the decoded byte array
     * @throws AddressFormatException if the input contains invalid characters
     */
    public static byte[] decodeToArray(String input) throws AddressFormatException {
        return decode(input).toArrayUnsafe();
    }

    /**
     * Encode a Bytes object to Base58Check string with checksum.
     * 
     * @param payload the Bytes object to encode
     * @return the Base58Check encoded string
     */
    public static String encodeCheck(Bytes payload) {
        if (payload == null) {
            throw new IllegalArgumentException("Payload cannot be null");
        }
        
        Bytes checksum = computeChecksum(payload);
        Bytes payloadWithChecksum = Bytes.concatenate(payload, checksum);
        
        return encode(payloadWithChecksum);
    }
    
    /**
     * Encode a byte array to Base58Check string with checksum.
     * Legacy compatibility method - prefer {@link #encodeCheck(Bytes)}.
     *
     * @param payload the byte array to encode
     * @return the Base58Check encoded string
     */
    public static String encodeCheck(byte[] payload) {
        return encodeCheck(Bytes.wrap(payload));
    }

    /**
     * Decode a Base58Check string to a Bytes object and verify the checksum.
     * 
     * @param input the Base58Check string to decode
     * @return the decoded payload as a Bytes object (without checksum)
     * @throws AddressFormatException if the checksum is invalid
     */
    public static Bytes decodeCheck(String input) throws AddressFormatException {
        Bytes decoded = decode(input);
        
        if (decoded.size() < 4) {
            throw new AddressFormatException.InvalidDataLength("Base58Check data too short");
        }
        
        Bytes payload = decoded.slice(0, decoded.size() - 4);
        Bytes checksum = decoded.slice(decoded.size() - 4);
        Bytes expectedChecksum = computeChecksum(payload);
        
        if (!HashUtils.constantTimeEquals(checksum.toArrayUnsafe(), expectedChecksum.toArrayUnsafe())) {
            throw new AddressFormatException.InvalidChecksum();
        }
        
        return payload;
    }
    
    /**
     * Decode a Base58Check string and verify the checksum.
     * Legacy compatibility method - prefer {@link #decodeCheck(String)}.
     *
     * @param input the Base58Check string to decode
     * @return the decoded payload (without checksum)
     * @throws AddressFormatException if the checksum is invalid
     */
    public static byte[] decodeCheckToArray(String input) throws AddressFormatException {
        return decodeCheck(input).toArrayUnsafe();
    }

    /**
     * Compute the 4-byte checksum for Base58Check encoding.
     * 
     * @param payload the payload to compute checksum for
     * @return the 4-byte checksum as Bytes
     */
    private static Bytes computeChecksum(Bytes payload) {
        Bytes32 hash = HashUtils.doubleSha256(payload);
        return hash.slice(0, 4);
    }
    
    /**
     * Divides a number, represented as an array of bytes each containing a single digit
     * in the specified base, by the given divisor. The given number is modified in-place
     * to contain the quotient, and the return value is the remainder.
     *
     * @param number the number to divide
     * @param firstDigit the index within the array of the first non-zero digit
     * @param base the base in which the number's digits are represented (up to 256)
     * @param divisor the number to divide by (up to 256)
     * @return the remainder of the division operation
     */
    private static byte divmod(byte[] number, int firstDigit, int base, int divisor) {
        int remainder = 0;
        for (int i = firstDigit; i < number.length; i++) {
            int digit = (int) number[i] & 0xFF;
            int temp = remainder * base + digit;
            number[i] = (byte) (temp / divisor);
            remainder = temp % divisor;
        }
        return (byte) remainder;
    }
    
    /**
     * Check if a string is a valid Base58 string.
     * 
     * @param input the string to validate
     * @return true if the string is valid Base58, false otherwise
     */
    public static boolean isValid(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }
        
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            if (c >= 128 || INDEXES[c] == -1) {
                return false;
            }
        }
        
        return true;
    }
} 