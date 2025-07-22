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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

public class SecureRandomProviderTest {

    @Test
    void testGetRandomBytes() {
        byte[] bytes1 = SecureRandomProvider.getRandomBytes(32);
        byte[] bytes2 = SecureRandomProvider.getRandomBytes(32);
        assertEquals(32, bytes1.length);
        assertNotNull(bytes1);
        assertNotNull(bytes2);

        // Test for negative length
        assertThrows(IllegalArgumentException.class, () -> SecureRandomProvider.getRandomBytes(-1));

        // Test for zero length
        byte[] zeroBytes = SecureRandomProvider.getRandomBytes(0);
        assertNotNull(zeroBytes);
        assertEquals(0, zeroBytes.length);


        boolean areDifferent = false;
        for (int i = 0; i < bytes1.length; i++) {
            if (bytes1[i] != bytes2[i]) {
                areDifferent = true;
                break;
            }
        }
        assertTrue(areDifferent, "Two calls to getRandomBytes should produce different results");
    }

    @Test
    void testGetRandomInt() {
        int int1 = SecureRandomProvider.getRandomInt();
        int int2 = SecureRandomProvider.getRandomInt();
        assertNotEquals(int1, int2, "Two calls to getRandomInt should produce different results");
    }

    @Test
    void testGetRandomLong() {
        long long1 = SecureRandomProvider.getRandomLong();
        long long2 = SecureRandomProvider.getRandomLong();
        assertNotEquals(long1, long2, "Two calls to getRandomLong should produce different results");
    }

    @Test
    void testThreadSafety() throws InterruptedException {
        int threadCount = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);
        Set<SecureRandom> instances = Collections.synchronizedSet(new HashSet<>());

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    instances.add(SecureRandomProvider.getSecureRandom());
                } finally {
                    latch.countDown();
                }
            });
        }

        assertTrue(latch.await(5, TimeUnit.SECONDS), "Threads did not complete in time");
        assertEquals(threadCount, instances.size(), "Each thread should have its own SecureRandom instance");
        executor.shutdownNow();
    }
    
    @Test
    void testReseed() {
        SecureRandom sr1 = SecureRandomProvider.getSecureRandom();
        byte[] bytes1 = new byte[20];
        sr1.nextBytes(bytes1);

        SecureRandomProvider.reseed();
        
        SecureRandom sr2 = SecureRandomProvider.getSecureRandom();
        byte[] bytes2 = new byte[20];
        sr2.nextBytes(bytes2);
        
        // After a reseed, the next random bytes should be different.
        boolean areDifferent = false;
        for (int i = 0; i < bytes1.length; i++) {
            if (bytes1[i] != bytes2[i]) {
                areDifferent = true;
                break;
            }
        }
        assertTrue(areDifferent, "Reseeding should change the sequence of random numbers");
    }
} 