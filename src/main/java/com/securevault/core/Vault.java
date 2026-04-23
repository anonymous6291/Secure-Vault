package com.securevault.core;

import com.securevault.core.configurations.ConfigurationManager;
import com.securevault.core.filehandlers.FileManager;
import com.securevault.core.filehandlers.VaultException;
import com.securevault.core.filehandlers.listeners.FileManagerUpdateListener;

import javax.crypto.AEADBadTagException;
import java.io.FileNotFoundException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

public class Vault {
    private static final String VAULT_FOLDER_NAME = "Secure Vault";
    private static final String CONFIG_FILE_NAME = "config.data";
    private static final String ENCRYPTED_LOG_FILE_NAME = "log.data";
    private static final String DECRYPTED_LOG_FILE_NAME = "log.data1";
    private static final int VAULT_KEY_MINIMUM_LENGTH = 5;
    private final FileSystem vaultFileSystem;
    private final ConfigurationManager configurationManager;
    private final FileManager fileManager;
    private final String vaultPath;
    private final Logger logger;
    private final char[] vaultKey;
    private char[] password;
    private volatile boolean isVaultOpen;

    public Vault(String path, boolean create, char[] password, FileManagerUpdateListener fileManagerUpdateListener) throws Exception {
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
        logger = new Logger(getPath(ENCRYPTED_LOG_FILE_NAME), getPath(DECRYPTED_LOG_FILE_NAME), vaultKey);
        logger.logInfo("Vault opened.");
        fileManager = new FileManager(vaultPath, vaultKey, fileManagerUpdateListener, logger);
        IO.println(new String(vaultKey));
        isVaultOpen = true;
    }

    private void assertVaultKeyRequirement(char[] key) {
        if (key == null || key.length < VAULT_KEY_MINIMUM_LENGTH) {
            throw new VaultException("Vault password must be at least [" + VAULT_KEY_MINIMUM_LENGTH + "] length long.");
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

    public void putFiles(Path from) throws FileNotFoundException {
        fileManager.addFiles(from);
    }

    public void getFiles(Path from, Path to) throws FileNotFoundException {
        fileManager.getFiles(from, to);
    }

    public boolean changeFileName(Path path, String newName) {
        return fileManager.changeFileName(path, newName);
    }

    public void deleteFile(Path path) {
        fileManager.deleteFile(path);
    }

    public void deleteDirectory(Path path) {
        fileManager.deleteDirectory(path);
    }

    public List<String> getFilesList() {
        return fileManager.getFilesList();
    }

    public void abortAllFileTransfers() {
        fileManager.abortAllFileTransfers();
    }

    public void changeVaultPassword(char[] currentPassword, char[] newKey) throws Exception {
        assertVaultKeyRequirement(newKey);
        if (different(password, currentPassword)) {
            logger.logSevere("Changing of vault password failed due to wrong initial password.");
            throw new VaultException("Wrong vault password. Initial password not changed.");
        }
        char[] cloned = newKey.clone();
        configurationManager.changeKey(cloned);
        password = cloned;
        logger.logWarn("Vault password changed.");
    }

    public boolean isVaultOpen() {
        return isVaultOpen;
    }

    public void lockdownVault(long duration) {
        configurationManager.enableLockdownMode(duration);
        closeVault();
    }

    public void setSelfDestruct(int tries) {
        configurationManager.setSelfDestructMode(tries);
    }

    public int getSelfDestructTries() {
        return configurationManager.getSelfDestructTries();
    }

    public void disableSelfDestruct() {
        configurationManager.disableSelfDestructMode();
    }

    public boolean isSelfDestructEnabled() {
        return configurationManager.isSelfDestructEnabled();
    }

    public void selfDestruct(char[] password) {
        if (different(this.password, password)) {
            logger.logSevere("Vault destruction failed due to wrong vault key.");
            throw new VaultException("Wrong vault key. Vault not destructed.");
        }
        logger.logWarn("Vault entered self destruction mode.");
        configurationManager.selfDestruct();
        closeVault();
    }

    public String getVersion() {
        return configurationManager.getVersion();
    }

    public Logger getLogger() {
        return logger;
    }

    public void closeVault() {
        if (!isVaultOpen()) {
            return;
        }
        logger.logInfo("Closing vault.");
        try {
            isVaultOpen = false;
            int n = vaultKey.length;
            configurationManager.writeConfiguration();
            fileManager.close();
            logger.close();
            for (int i = 0; i < n; i++) {
                vaultKey[i] = 0;
            }
        } catch (Exception e) {
            throw new VaultException("Exception occurred while performing shutdown tasks of Vault : " + e);
        }
    }
}