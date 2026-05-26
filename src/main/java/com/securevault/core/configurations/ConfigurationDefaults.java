package com.securevault.core.configurations;

public class ConfigurationDefaults {
    public static final int IV_LENGTH = 12;
    public static final int SALT_LENGTH = 16;
    private static final Data configurationManagerData = new Data("CONFIG_KEY".toCharArray(), new byte[]{1, 2, 3, 4, 5}, new byte[]{1, 2, 3, 4, 5});

    public static Data getConfigurationManagerData() {
        return configurationManagerData;
    }

    public record Data(char[] key, byte[] iv, byte[] salt) {
    }
}