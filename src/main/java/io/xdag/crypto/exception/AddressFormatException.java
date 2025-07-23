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
package io.xdag.crypto.exception;

/**
 * Exception thrown when an address format is invalid.
 * 
 * <p>This exception indicates problems with address formatting, including:
 * <ul>
 * <li>Invalid characters in the address string</li>
 * <li>Incorrect address length</li>
 * <li>Failed checksum validation</li>
 * <li>Invalid Base58 encoding</li>
 * </ul>
 * 
 * <p>This exception extends {@link CryptoException} to provide unified
 * exception handling across the cryptographic library.
 */
public class AddressFormatException extends CryptoException {
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new address format exception with a default message.
     */
    public AddressFormatException() {
        super("Invalid address format");
    }

    /**
     * Constructs a new address format exception with the specified detail message.
     * 
     * @param message the detail message describing the specific format error
     */
    public AddressFormatException(String message) {
        super(message);
    }

    /**
     * Constructs a new address format exception with the specified detail message and cause.
     * 
     * @param message the detail message describing the specific format error
     * @param cause the underlying cause of this exception
     */
    public AddressFormatException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Constructs a new address format exception with the specified cause.
     * 
     * @param cause the underlying cause of this exception
     */
    public AddressFormatException(Throwable cause) {
        super(cause);
    }

    /**
     * Creates an exception for invalid character errors.
     * 
     * @param character the invalid character found
     * @param position the position of the invalid character
     * @return a new AddressFormatException with appropriate message
     */
    public static AddressFormatException invalidCharacter(char character, int position) {
        return new AddressFormatException("Invalid character '" + character + "' at position " + position);
    }

    /**
     * Creates an exception for invalid data length errors.
     * 
     * @param message the detail message about the length issue
     * @return a new AddressFormatException with appropriate message
     */
    public static AddressFormatException invalidDataLength(String message) {
        return new AddressFormatException("Invalid data length: " + message);
    }

    /**
     * Creates an exception for checksum validation failures.
     * 
     * @return a new AddressFormatException for checksum errors
     */
    public static AddressFormatException invalidChecksum() {
        return new AddressFormatException("Checksum validation failed");
    }

    /**
     * Creates an exception for checksum validation failures with custom message.
     * 
     * @param message the detail message about the checksum issue
     * @return a new AddressFormatException for checksum errors
     */
    public static AddressFormatException invalidChecksum(String message) {
        return new AddressFormatException("Checksum validation failed: " + message);
    }
}
