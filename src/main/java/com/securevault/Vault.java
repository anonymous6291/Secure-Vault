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
    private final FileSystem vaultFileSystem;
    private final ConfigurationManager configurationManager;
    private final String vaultPath;
    private char[] vaultKey;
    private volatile boolean isVaultOpen;

    Vault(String path, boolean create, char[] key) throws Exception {
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
            configurationManager = new ConfigurationManager(getPath(CONFIG_FILE_NAME), create, key);
        } catch (AEADBadTagException e) {
            vaultFileSystem.close();
            throw new VaultException("Invalid password.");
        }
        vaultKey = configurationManager.getVaultKey();
        Logger.init(getPath(ENCRYPTED_LOG_FILE_NAME), getPath(DECRYPTED_LOG_FILE_NAME), vaultKey);
        Logger.logInfo("Vault opened.");
        IO.println(new String(vaultKey));
        isVaultOpen = true;
    }

    private Path getPath(String subPath) {
        return vaultFileSystem.getPath(vaultPath, subPath);
    }

    public boolean isVaultOpen() {
        return isVaultOpen;
    }

    public void closeVault() {
        if (!isVaultOpen()) {
            return;
        }
        try {
            isVaultOpen = false;
            vaultKey = null;
            configurationManager.writeConfiguration();
            Logger.close();
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