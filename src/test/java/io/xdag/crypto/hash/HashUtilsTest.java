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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

public class HashUtilsTest {

    @Test
    void testSha256() {
        // Test vector from https://en.bitcoin.it/wiki/SHA-256
        String original = "hello world";
        Bytes originalBytes = Bytes.wrap(original.getBytes());
        String expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assertEquals(expected, HashUtils.sha256(originalBytes).toHexString().substring(2));
    }

    @Test
    void testDoubleSha256() {
        // Test vector from bitcoin-core/qa-assets
        String original = "hello";
        Bytes originalBytes = Bytes.wrap(original.getBytes());
        String expected = "9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50";
        assertEquals(expected, HashUtils.doubleSha256(originalBytes).toHexString().substring(2));
    }

    @Test
    void testRipemd160() {
        // Test vector from https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
        Bytes originalBytes = Bytes.wrap("hello world".getBytes());
        String expected = "98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f";
        assertEquals(expected, HashUtils.ripemd160(originalBytes).toHexString().substring(2));
    }

    @Test
    void testKeccak256() {
        Bytes originalBytes = Bytes.wrap("hello".getBytes());
        String expected = "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8";
        assertEquals(expected, HashUtils.keccak256(originalBytes).toHexString().substring(2));
    }

    @Test
    void testHmacSha256() {
        // RFC 2104 test vector
        Bytes key = Bytes.wrap("Jefe".getBytes(StandardCharsets.US_ASCII));
        Bytes data = Bytes.wrap("what do ya want for nothing?".getBytes(StandardCharsets.US_ASCII));
        String expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
        assertEquals(expected, HashUtils.hmacSha256(key, data).toHexString().substring(2));
    }
    
    @Test
    void testSha256hash160() {
        // Bitcoin public key to address example
        Bytes pubKey = Bytes.fromHexString("0x0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6");
        String expected = "010966776006953d5567439e5e39f86a0d273bee";
        assertEquals(expected, HashUtils.sha256hash160(pubKey).toHexString().substring(2));
    }
    
    @Test
    void testConstantTimeEquals() {
        Bytes a = Bytes.fromHexString("0x010203");
        Bytes b = Bytes.fromHexString("0x010203");
        Bytes c = Bytes.fromHexString("0x010204");
        Bytes d = Bytes.fromHexString("0x0102");
        
        assertTrue(HashUtils.constantTimeEquals(a, b));
        assertFalse(HashUtils.constantTimeEquals(a, c));
        assertFalse(HashUtils.constantTimeEquals(a, d));
        assertTrue(HashUtils.constantTimeEquals(null, (Bytes) null));
        assertFalse(HashUtils.constantTimeEquals(a, null));
        assertFalse(HashUtils.constantTimeEquals(null, b));
    }

    @Test
    void testSha256ThreadSafety() throws InterruptedException {
        int threadCount = 20;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        String original = "multithread test string";
        Bytes originalBytes = Bytes.wrap(original.getBytes());
        String expected = "d96a84443198f795995536552e4f0b79d48b481c19f50f9078657270d4737f5b";

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    String hash = HashUtils.sha256(originalBytes).toHexString().substring(2);
                    assertEquals(expected, hash);
                } finally {
                    latch.countDown();
                }
            });
        }
        
        assertTrue(latch.await(5, TimeUnit.SECONDS), "Threads did not complete in time");
        executor.shutdownNow();
    }
} 