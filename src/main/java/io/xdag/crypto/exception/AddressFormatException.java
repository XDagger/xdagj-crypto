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
 * Exception thrown when an address format is invalid
 */
public class AddressFormatException extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new address format exception with no detail message.
     */
    public AddressFormatException() {
        super();
    }

    /**
     * Constructs a new address format exception with the specified detail message.
     * @param message the detail message.
     */
    public AddressFormatException(String message) {
        super(message);
    }

    /**
     * Exception thrown when an invalid character is found in an address
     */
    public static class InvalidCharacter extends AddressFormatException {
        private static final long serialVersionUID = 1L;
        /** The invalid character found in the address string. */
        public final char character;
        /** The position (0-based) of the invalid character. */
        public final int position;

        /**
         * Constructs an InvalidCharacter exception.
         * @param character The invalid character.
         * @param position The position of the character.
         */
        public InvalidCharacter(char character, int position) {
            super("Invalid character '" + character + "' at position " + position);
            this.character = character;
            this.position = position;
        }
    }

    /**
     * Exception thrown when address data length is invalid
     */
    public static class InvalidDataLength extends AddressFormatException {
        private static final long serialVersionUID = 1L;
        /**
         * Constructs a new invalid data length exception with no detail message.
         */
        public InvalidDataLength() {
            super();
        }

        /**
         * Constructs a new invalid data length exception with the specified detail message.
         * @param message the detail message.
         */
        public InvalidDataLength(String message) {
            super(message);
        }
    }

    /**
     * Exception thrown when address checksum validation fails
     */
    public static class InvalidChecksum extends AddressFormatException {
        private static final long serialVersionUID = 1L;
        /**
         * Constructs a new invalid checksum exception with a default message.
         */
        public InvalidChecksum() {
            super("Checksum does not validate");
        }

        /**
         * Constructs a new invalid checksum exception with the specified detail message.
         * @param message the detail message.
         */
        public InvalidChecksum(String message) {
            super(message);
        }
    }
}
