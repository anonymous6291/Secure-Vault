package com.securevault;

import javax.crypto.AEADBadTagException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Vault {
    private static final String VAULT_FOLDER_NAME = "Secure Vault";
    private static final String CONFIG_FILE_NAME = "config.data";
    private static final String ENCRYPTED_LOG_FILE_NAME = "log.data";
    private static final String DECRYPTED_LOG_FILE_NAME = "log.data1";
    private static final int VAULT_KEY_MINIMUM_LENGTH = 5;
    private final FileSystem vaultFileSystem;
    private final ConfigurationManager configurationManager;
    private final String vaultPath;
    private final char[] vaultKey;
    private char[] password;
    private volatile boolean isVaultOpen;

    Vault(String path, boolean create, char[] password) throws Exception {
        assertVaultKeyRequirement(password);
        this.password = password.clone();
        Path vaultPath;
        if (create) {
            vaultPath = Paths.get(path, VAULT_FOLDER_NAME);
            if (Files.exists(vaultPath)) {
                throw new VaultException("Vault already exists.");
            }
            Files.createDirectories(vaultPath);
        } else {
            vaultPath = Paths.get(path);
            if (!Files.exists(vaultPath)) {
                throw new VaultException("Vault doesn't exist.");
            }
            if (!(Files.isDirectory(vaultPath) && Files.isRegularFile(vaultPath.resolve(CONFIG_FILE_NAME)))) {
                throw new VaultException("Not a valid vault.");
            }
        }
        this.vaultPath = vaultPath.toString();
        vaultFileSystem = vaultPath.getFileSystem();
        try {
            configurationManager = new ConfigurationManager(getPath(CONFIG_FILE_NAME), create, password);
        } catch (AEADBadTagException e) {
            throw new VaultException("Invalid password.");
        }
        vaultKey = configurationManager.getVaultKey();
        Logger.init(getPath(ENCRYPTED_LOG_FILE_NAME), getPath(DECRYPTED_LOG_FILE_NAME), vaultKey);
        Logger.logInfo("Vault opened.");
        IO.println(new String(vaultKey));
        isVaultOpen = true;
    }

    private void assertVaultKeyRequirement(char[] key) {
        if (key == null || key.length < VAULT_KEY_MINIMUM_LENGTH) {
            throw new VaultException("Vault key should be at least [" + VAULT_KEY_MINIMUM_LENGTH + "] length long.");
        }
    }

    private Path getPath(String subPath) {
        return vaultFileSystem.getPath(vaultPath, subPath);
    }

    private boolean different(char[] x, char[] y) {
        if (x == y) {
            return false;
        }
        if (x == null || y == null) {
            return true;
        }
        if (x.length != y.length) {
            return true;
        }
        int n = x.length;
        for (int i = 0; i < n; i++) {
            if (x[i] != y[i]) {
                return true;
            }
        }
        return false;
    }

    public void changeVaultKey(char[] password, char[] newKey) throws Exception {
        assertVaultKeyRequirement(newKey);
        if (different(this.password, password)) {
            Logger.logSevere("Changing of vault key failed due to wrong initial key.");
            throw new VaultException("Wrong vault key. Initial key not changed.");
        }
        configurationManager.changeKey(newKey.clone());
        this.password = newKey.clone();
        Logger.logWarn("Vault key changed.");
    }

    public boolean isVaultOpen() {
        return isVaultOpen;
    }

    public void lockdownVault(long duration) {
        configurationManager.enableLockdownMode(duration);
        closeVault();
    }

    public void selfDestructVault(char[] password) {
        if (different(this.password, password)) {
            Logger.logSevere("Vault destruction failed due to wrong vault key.");
            throw new VaultException("Wrong vault key. Vault not destructed.");
        }
        Logger.logWarn("Vault entered self destruction mode.");
        configurationManager.selfDestruct();
        closeVault();
    }

    public void closeVault() {
        if (!isVaultOpen()) {
            return;
        }
        Logger.logInfo("Closing vault.");
        try {
            isVaultOpen = false;
            int n = vaultKey.length;
            configurationManager.writeConfiguration();
            Logger.close();
            for (int i = 0; i < n; i++) {
                vaultKey[i] = 0;
            }
        } catch (Exception e) {
            throw new VaultException("Exception occurred while performing shutdown tasks of Vault : " + e);
        }
    }
}

class VaultException extends RuntimeException {
    VaultException(String message) {
        super(message);
    }
}