package com.securevault;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;

public class CipherManager {
    private static final String CIPHER_ALGORITHM = "AES/GCM/NoPadding";
    private static final String SECRET_KEY_FACTORY_PROVIDER = "PBKDF2WithHmacSHA256";
    private static final String SECRET_KEY_SPEC_PROVIDER = "AES";
    private static final int TAG_SIZE = 128;
    private static final int KEY_SIZE = 256;
    private static final int ITERATIONS = 100000;

    private static SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(SECRET_KEY_FACTORY_PROVIDER);
        KeySpec keySpec = new PBEKeySpec(password, salt, ITERATIONS, KEY_SIZE);
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        return new SecretKeySpec(secretKey.getEncoded(), SECRET_KEY_SPEC_PROVIDER);
    }

    public static Cipher getCipher(char[] password, byte[] iv, byte[] salt, int mode) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        SecretKey secretKey = deriveKey(password, salt);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_SIZE, iv);
        cipher.init(mode, secretKey, gcmParameterSpec);
        return cipher;
    }
}
