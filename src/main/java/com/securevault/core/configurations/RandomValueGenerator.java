package com.securevault.core.configurations;

import java.security.SecureRandom;
import java.util.Random;

public class RandomValueGenerator {
    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Random random = new Random();

    public static byte[] generateSecureBytes(int length) {
        byte[] nextBytes = new byte[length];
        secureRandom.nextBytes(nextBytes);
        return nextBytes;
    }

    public static byte[] generateBytes(int length) {
        byte[] nextBytes = new byte[length];
        random.nextBytes(nextBytes);
        return nextBytes;
    }
}
