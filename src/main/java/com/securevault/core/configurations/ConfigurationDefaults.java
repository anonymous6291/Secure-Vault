package com.securevault.core.configurations;

public class ConfigurationDefaults {
    public static final int IV_LENGTH = 12;
    public static final int SALT_LENGTH = 16;
    /*
    The values of "configurationManagerData" are used for protecting the config files.
    So modify these default values with random values.
    The values should be random of length at least 50 for security purposes.
     */
    private static final Data configurationManagerData = new Data("CONFIG_KEY".toCharArray(), new byte[]{1, 2, 3, 4, 5}, new byte[]{1, 2, 3, 4, 5});

    public static Data getConfigurationManagerData() {
        return configurationManagerData;
    }

    public record Data(char[] key, byte[] iv, byte[] salt) {
    }
}