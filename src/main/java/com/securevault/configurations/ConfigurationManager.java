package com.securevault.configurations;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Date;

public class ConfigurationManager {
    private static final String VERSION = "1.0.0";
    private static final int KEY_LENGTH = 50;
    private static final int MAX_TRIES = 5;
    private static final int PER_DAY_MAX_TRIES = 15;
    private static final long WRONG_TRY_DELAY_MILLIS = 5 * 60 * 1000;
    private static final ObjectMapper json = new ObjectMapper();
    private static final Base64.Encoder base64Encoder = Base64.getEncoder();
    private static final Base64.Decoder base64Decoder = Base64.getDecoder();

    static {
        json.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    private final Path configurationPath;
    private final Configuration configuration;
    private final char[] vaultKey;

    public ConfigurationManager(Path config, boolean create, char[] key) throws Exception {
        configurationPath = config;
        ConfigurationDefaults.Data configurationManagerData = ConfigurationDefaults.getDefault(ConfigurationManager.class);
        if (create) {
            byte[] generatedChar = RandomValueGenerator.generateSecureBytes(KEY_LENGTH);
            vaultKey = base64Encoder.encodeToString(generatedChar).toCharArray();
            byte[] iv = RandomValueGenerator.generateSecureBytes(ConfigurationDefaults.IV_LENGTH);
            byte[] salt = RandomValueGenerator.generateSecureBytes(ConfigurationDefaults.SALT_LENGTH);
            Cipher cipher = CipherManager.getCipher(key, iv, salt, Cipher.ENCRYPT_MODE);
            byte[] encr = cipher.doFinal(generatedChar);
            configuration = new Configuration(VERSION, false, new Date(), 0, false, false, 0, base64Encoder.encodeToString(encr), base64Encoder.encodeToString(iv), base64Encoder.encodeToString(salt));
        } else {
            byte[] configData = Files.readAllBytes(config);
            Cipher cipher = CipherManager.getCipher(configurationManagerData.key(), configurationManagerData.iv(), configurationManagerData.salt(), Cipher.DECRYPT_MODE);
            String configString = new String(cipher.doFinal(configData), StandardCharsets.UTF_16);
            configuration = json.readValue(configString, Configuration.class);
            IO.println(configString);
            if (configuration.getIs_destructed()) {
                throw new VaultDestructedException();
            }
            if (configuration.getLockdown() && new Date().before(configuration.getLockdown_end_time())) {
                throw new LockdownModeException("Vault is in lockdown mode. Lockdown mode ends at [" + configuration.getLockdown_end_time() + "] .");
            }
            byte[] encrKey = base64Decoder.decode(configuration.getKey());
            byte[] iv = base64Decoder.decode(configuration.getIv());
            byte[] salt = base64Decoder.decode(configuration.getSalt());
            try {
                Cipher cipher1 = CipherManager.getCipher(key, iv, salt, Cipher.DECRYPT_MODE);
                byte[] decrKey = cipher1.doFinal(encrKey);
                vaultKey = base64Encoder.encodeToString(decrKey).toCharArray();
                configuration.setLockdown(false);
                configuration.setTries(0);
            } catch (AEADBadTagException e) {
                int tries = configuration.getTries() + 1;
                if (configuration.getSelf_destruct() && configuration.getSelf_destruct_limit() <= tries) {
                    String modifiedKey = base64Encoder.encodeToString(RandomValueGenerator.generateSecureBytes(configuration.getKey().length()));
                    configuration.setKey(modifiedKey);
                    configuration.setIs_destructed(true);
                    configuration.setSelf_destruct(false);
                    configuration.setSelf_destruct_limit(0);
                    tries = 0;
                } else if (tries >= PER_DAY_MAX_TRIES) {
                    tries = 0;
                    configuration.setLockdown(true);
                    configuration.setLockdown_end_time(new Date(System.currentTimeMillis() + 24L * 60 * 60 * 1000));
                } else if (tries >= MAX_TRIES) {
                    int extra = tries - MAX_TRIES;
                    if ((extra & 1) == 0) {
                        long delay = ((extra / 2) + 1) * WRONG_TRY_DELAY_MILLIS;
                        configuration.setLockdown(true);
                        configuration.setLockdown_end_time(new Date(delay + System.currentTimeMillis()));
                    }
                }
                configuration.setTries(tries);
                writeConfiguration();
                throw e;
            }
        }
    }

    public void changeKey(char[] newKey) throws Exception {
        byte[] iv = base64Decoder.decode(configuration.getIv());
        byte[] salt = base64Decoder.decode(configuration.getSalt());
        byte[] old = base64Decoder.decode(new String(vaultKey));
        Cipher cipher = CipherManager.getCipher(newKey, iv, salt, Cipher.ENCRYPT_MODE);
        byte[] encrypted = cipher.doFinal(old);
        configuration.setKey(base64Encoder.encodeToString(encrypted));
        writeConfiguration();
    }

    public void enableLockdownMode(long duration) {
        configuration.setLockdown(true);
        configuration.setLockdown_end_time(new Date(duration + System.currentTimeMillis()));
    }

    public void selfDestruct() {
        configuration.setIs_destructed(true);
        configuration.setKey(base64Encoder.encodeToString(RandomValueGenerator.generateSecureBytes(configuration.getKey().length())));
    }

    public boolean isSelfDestructEnabled() {
        return configuration.getSelf_destruct();
    }

    public int getSelfDestructTries() {
        return configuration.getSelf_destruct_limit();
    }

    public void disableSelfDestructMode() {
        configuration.setSelf_destruct(false);
        configuration.setSelf_destruct_limit(0);
    }

    public void setSelfDestructMode(int tries) {
        if (tries <= 0) {
            disableSelfDestructMode();
        } else {
            configuration.setSelf_destruct(true);
            configuration.setSelf_destruct_limit(tries);
        }
    }

    public char[] getVaultKey() {
        return vaultKey.clone();
    }

    public void writeConfiguration() throws Exception {
        ConfigurationDefaults.Data defaultConfigurationManagerData = ConfigurationDefaults.getDefault(ConfigurationManager.class);
        String configData = json.writeValueAsString(configuration);
        byte[] data = configData.getBytes(StandardCharsets.UTF_16);
        Cipher cipher = CipherManager.getCipher(defaultConfigurationManagerData.key(), defaultConfigurationManagerData.iv(), defaultConfigurationManagerData.salt(), Cipher.ENCRYPT_MODE);
        data = cipher.doFinal(data);
        Files.write(configurationPath, data);
    }

    static class Configuration {
        private String version;
        private boolean lockdown;
        private Date lockdown_end_time;
        private int tries;
        private boolean is_destructed;
        private boolean self_destruct;
        private int self_destruct_limit;
        private String key;
        private String iv;
        private String salt;

        public Configuration(String version, boolean lockdown, Date lockdown_end_time, int tries, boolean is_destructed, boolean self_destruct, int self_destruct_limit, String key, String iv, String salt) {
            this.version = version;
            this.lockdown = lockdown;
            this.lockdown_end_time = lockdown_end_time;
            this.tries = tries;
            this.is_destructed = is_destructed;
            this.self_destruct = self_destruct;
            this.self_destruct_limit = self_destruct_limit;
            this.key = key;
            this.iv = iv;
            this.salt = salt;
        }

        public Configuration() {
        }

        public String getVersion() {
            return version;
        }

        public void setVersion(String version) {
            this.version = version;
        }

        public boolean getLockdown() {
            return lockdown;
        }

        public void setLockdown(boolean lockdown) {
            this.lockdown = lockdown;
        }

        public Date getLockdown_end_time() {
            return lockdown_end_time;
        }

        public void setLockdown_end_time(Date lockdown_end_time) {
            this.lockdown_end_time = lockdown_end_time;
        }

        public int getTries() {
            return tries;
        }

        public void setTries(int tries) {
            this.tries = tries;
        }

        public boolean getIs_destructed() {
            return is_destructed;
        }

        public void setIs_destructed(boolean is_destructed) {
            this.is_destructed = is_destructed;
        }

        public boolean getSelf_destruct() {
            return self_destruct;
        }

        public void setSelf_destruct(boolean self_destruct) {
            this.self_destruct = self_destruct;
        }

        public int getSelf_destruct_limit() {
            return self_destruct_limit;
        }

        public void setSelf_destruct_limit(int self_destruct_limit) {
            this.self_destruct_limit = self_destruct_limit;
        }

        public String getKey() {
            return key;
        }

        public void setKey(String key) {
            this.key = key;
        }

        public String getIv() {
            return iv;
        }

        public void setIv(String iv) {
            this.iv = iv;
        }

        public String getSalt() {
            return salt;
        }

        public void setSalt(String salt) {
            this.salt = salt;
        }
    }
}

