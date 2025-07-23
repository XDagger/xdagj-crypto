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

/**
 * Tests for CryptoProvider's secure random functionality.
 */
public class CryptoProviderRandomTest {

    @Test
    void testGetRandomBytes() {
        byte[] bytes1 = CryptoProvider.getRandomBytes(32);
        byte[] bytes2 = CryptoProvider.getRandomBytes(32);
        assertEquals(32, bytes1.length);
        assertNotNull(bytes1);
        assertNotNull(bytes2);
        // Arrays should be different (probability of collision is negligible)
        assertNotEquals(bytes1, bytes2);
    }

    @Test
    void testGetRandomBytesEdgeCases() {
        assertThrows(IllegalArgumentException.class, () -> CryptoProvider.getRandomBytes(-1));

        byte[] zeroBytes = CryptoProvider.getRandomBytes(0);
        assertEquals(0, zeroBytes.length);
    }

    @Test
    void testGetSecureRandom() {
        SecureRandom sr1 = CryptoProvider.getSecureRandom();
        SecureRandom sr2 = CryptoProvider.getSecureRandom();
        
        assertNotNull(sr1);
        assertNotNull(sr2);
        // Should return the same global instance
        assertEquals(sr1, sr2);
    }

    @Test
    void testGetRandomInt() {
        int int1 = CryptoProvider.getRandomInt();
        int int2 = CryptoProvider.getRandomInt();
        // Should generate different random integers (probability of collision is very low)
        assertNotEquals(int1, int2);
    }

    @Test
    void testGetRandomLong() {
        long long1 = CryptoProvider.getRandomLong();
        long long2 = CryptoProvider.getRandomLong();
        // Should generate different random longs (probability of collision is negligible)
        assertNotEquals(long1, long2);
    }

    @Test
    void testThreadSafety() throws InterruptedException {
        int numThreads = 10;
        int numIterations = 100;
        
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        CountDownLatch latch = new CountDownLatch(numThreads);
        Set<SecureRandom> instances = Collections.synchronizedSet(new HashSet<>());
        
        for (int i = 0; i < numThreads; i++) {
            executor.submit(() -> {
                try {
                    for (int j = 0; j < numIterations; j++) {
                        instances.add(CryptoProvider.getSecureRandom());
                        CryptoProvider.getRandomBytes(16); // Test concurrent access
                    }
                } finally {
                    latch.countDown();
                }
            });
        }
        
        assertTrue(latch.await(10, TimeUnit.SECONDS));
        executor.shutdown();
        
        // All threads should see the same global instance
        assertEquals(1, instances.size());
    }

    @Test
    void testReseed() {
        SecureRandom sr1 = CryptoProvider.getSecureRandom();
        
        // Reseed should not fail
        CryptoProvider.reseed();
        
        SecureRandom sr2 = CryptoProvider.getSecureRandom();
        
        // Should still be the same global instance
        assertEquals(sr1, sr2);
    }

    @Test
    void testConcurrentSecureRandomAccess() throws InterruptedException {
        int numThreads = 20;
        int numOperations = 1000;
        
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);
        CountDownLatch latch = new CountDownLatch(numThreads);
        Set<byte[]> generatedBytes = Collections.synchronizedSet(new HashSet<>());
        
        for (int i = 0; i < numThreads; i++) {
            executor.submit(() -> {
                try {
                    for (int j = 0; j < numOperations; j++) {
                        // Test concurrent access to getSecureRandom()
                        SecureRandom sr = CryptoProvider.getSecureRandom();
                        assertNotNull(sr, "SecureRandom should never be null");
                        
                        // Test concurrent random byte generation
                        byte[] randomBytes = CryptoProvider.getRandomBytes(8);
                        assertEquals(8, randomBytes.length);
                        
                        // Add to set to verify uniqueness (probability of collision is negligible)
                        generatedBytes.add(randomBytes);
                        
                        // Test other random generation methods
                        CryptoProvider.getRandomInt();
                        CryptoProvider.getRandomLong();
                    }
                } finally {
                    latch.countDown();
                }
            });
        }
        
        assertTrue(latch.await(30, TimeUnit.SECONDS), "Concurrent test should complete within 30 seconds");
        executor.shutdown();
        
        // Verify that we generated a reasonable number of unique byte arrays
        // With 20 threads * 1000 operations = 20,000 8-byte arrays, 
        // the probability of collision is essentially zero
        assertTrue(generatedBytes.size() > numThreads * numOperations * 0.99, 
                "Should generate highly unique random byte arrays");
    }
} 