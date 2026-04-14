package com.securevault;

import javax.crypto.AEADBadTagException;
import java.io.File;
import java.net.URI;
import java.nio.file.*;
import java.util.HashMap;
import java.util.Map;

public class Vault implements AutoCloseable {
    private static final String VAULT_FOLDER_NAME = "Secure Vault";
    private static final String VAULT_FILE_NAME = "vault.zip";
    private static final String CONFIG_FILE_NAME = "config.data";
    private static final String ENCRYPTED_LOG_FILE_NAME = "log.data";
    private static final String DECRYPTED_LOG_FILE_NAME = "log.data1";
    private final FileSystem vaultFileSystem;
    private final ConfigurationManager configurationManager;
    private final char[] vaultKey;

    Vault(String path, boolean create, char[] key) throws Exception {
        Path vaultPath;
        Map<String, String> env = new HashMap<>();
        if (create) {
            vaultPath = Paths.get(path, VAULT_FOLDER_NAME, VAULT_FILE_NAME);
            if (Files.exists(vaultPath)) {
                throw new VaultException("Vault already exists.");
            }
            Files.createDirectories(vaultPath.getParent());
            env.put("create", "true");
        } else {
            vaultPath = Paths.get(path);
            if (!Files.exists(vaultPath)) {
                throw new VaultException("No such vault doesn't exist.");
            }
            if (!Files.isRegularFile(vaultPath)) {
                throw new VaultException("Not a valid vault.");
            }
        }
        URI vaultURI = URI.create("jar:" + new File(vaultPath.toString()).toURI());
        vaultFileSystem = FileSystems.newFileSystem(vaultURI, env);
        try {
            configurationManager = new ConfigurationManager(vaultFileSystem.getPath("/", CONFIG_FILE_NAME), create, key);
        } catch (AEADBadTagException e) {
            vaultFileSystem.close();
            throw new VaultException("Invalid password.");
        }
        vaultKey = configurationManager.getVaultKey();
        Logger.init(vaultFileSystem.getPath("/" + ENCRYPTED_LOG_FILE_NAME), vaultFileSystem.getPath("/" + DECRYPTED_LOG_FILE_NAME), vaultKey);
        IO.println(new String(vaultKey));
    }

    public void closeVault() throws Exception {
        if (!vaultFileSystem.isOpen()) {
            return;
        }
        try {
            configurationManager.writeConfiguration();
            Logger.close();
        } catch (Exception e) {
            throw new VaultException("Exception occurred while performing shutdown tasks of Vault : " + e);
        } finally {
            vaultFileSystem.close();
        }
    }

    @Override
    public void close() throws Exception {
        if (!vaultFileSystem.isOpen()) {
            return;
        }
        closeVault();
    }
}

class VaultException extends RuntimeException {
    VaultException(String message) {
        super(message);
    }
}