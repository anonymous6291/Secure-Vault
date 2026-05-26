package com.securevault.core.configurations;

import java.security.SecureRandom;

public class SecureRandomValueGenerator {
    private static final SecureRandom secureRandom = new SecureRandom();

    public static byte[] generateSecureBytes(int length) {
        byte[] nextBytes = new byte[length];
        secureRandom.nextBytes(nextBytes);
        return nextBytes;
    }
}
