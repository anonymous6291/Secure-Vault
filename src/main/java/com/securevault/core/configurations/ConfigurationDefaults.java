package com.securevault.core.configurations;

import com.securevault.core.Logger;

public class ConfigurationDefaults {
    public static final int IV_LENGTH = 12;
    public static final int SALT_LENGTH = 16;
    private static final Data configurationManagerData = new Data("CONFIG_KEY".toCharArray(), new byte[]{1, 2, 3, 4, 5}, new byte[]{1, 2, 3, 4, 5});
    private static final Data loggerData = new Data(new char[0], new byte[]{1, 2, 3, 4, 5}, new byte[]{1, 2, 3, 4, 5});

    public static Data getDefault(Class<?> caller) {
        if (caller == ConfigurationManager.class) {
            return configurationManagerData;
        } else if (caller == Logger.class) {
            return loggerData;
        } else {
            return new Data(new char[0], new byte[0], new byte[0]);
        }
    }

    public record Data(char[] key, byte[] iv, byte[] salt) {
    }
}