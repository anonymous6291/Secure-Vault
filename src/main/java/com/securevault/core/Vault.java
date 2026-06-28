package com.securevault.core;

import com.securevault.core.configurations.ConfigurationManager;
import com.securevault.core.filehandlers.FileManager;
import com.securevault.core.filehandlers.VaultException;
import com.securevault.core.filehandlers.listeners.FileManagerListener;
import com.securevault.core.keyhandlers.KeyType;
import com.securevault.core.keyhandlers.PasswordAndAPIKeyManager;
import com.securevault.core.keyhandlers.WebsiteIdPair;

import javax.crypto.AEADBadTagException;
import java.io.FileNotFoundException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;

public class Vault {
    private static final String VAULT_FOLDER_NAME = "Secure Vault";
    private static final String CONFIG_FILE_NAME = "config.data";
    private static final int VAULT_KEY_MINIMUM_LENGTH = 5;
    private static final long AUTO_SAVE_DELAY = 2 * 60 * 1000;
    private final AutoSaver autoSaver = new AutoSaver(AUTO_SAVE_DELAY);
    private final FileSystem vaultFileSystem;
    private final ConfigurationManager configurationManager;
    private final FileManager fileManager;
    private final PasswordAndAPIKeyManager passwordAndAPIKeyManager;
    private final Path vaultPath;
    private final Logger logger;
    private final char[] vaultKey;
    private char[] password;
    private volatile boolean isVaultOpen;

    public Vault(String path, boolean create, char[] password, FileManagerListener fileManagerListener, boolean independentMode) throws Exception {
        assertVaultKeyRequirement(password);
        this.password = password.clone();
        Path vaultPath = Paths.get(path, VAULT_FOLDER_NAME).normalize();
        if (create) {
            if (Files.exists(vaultPath)) {
                throw new VaultException("Vault already exists.");
            }
            Files.createDirectories(vaultPath);
        } else {
            if (!Files.isDirectory(vaultPath)) {
                throw new VaultException("Vault doesn't exist.");
            }
        }
        this.vaultPath = vaultPath;
        vaultFileSystem = vaultPath.getFileSystem();
        try {
            configurationManager = new ConfigurationManager(getPath(CONFIG_FILE_NAME), create, password);
        } catch (AEADBadTagException e) {
            throw new VaultException("Invalid password, corrupted configuration or version mismatch.");
        }
        vaultKey = configurationManager.getVaultKey();
        logger = new Logger(getPath(""), vaultKey, create, independentMode);
        logger.logInfo("Vault opened.");
        try {
            fileManager = new FileManager(getPath(""), vaultKey, create, fileManagerListener, logger);
            passwordAndAPIKeyManager = new PasswordAndAPIKeyManager(getPath(""), vaultKey, create, logger);
        } catch (Exception e) {
            logger.logError(e.getMessage());
            try {
                configurationManager.writeData();
            } catch (Exception _) {
            }
            try {
                logger.close();
            } catch (Exception _) {
            }
            throw e;
        }
        registerAutoSave(configurationManager);
        registerAutoSave(fileManager);
        registerAutoSave(passwordAndAPIKeyManager);
        autoSaver.start();
        isVaultOpen = true;
    }

    private void registerAutoSave(Writable writable) {
        autoSaver.register(writable);
    }

    private void assertVaultKeyRequirement(char[] key) {
        if (key == null || key.length < VAULT_KEY_MINIMUM_LENGTH) {
            throw new VaultException("Vault password must be at least [" + VAULT_KEY_MINIMUM_LENGTH + "] length long.");
        }
    }

    private Path getPath(String subPath) {
        return vaultFileSystem.getPath(vaultPath.toString(), subPath);
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

    public void putFile(Path from, Path to) throws FileNotFoundException {
        fileManager.addFile(from, to);
    }

    public void getFile(Path from, Path to) {
        fileManager.getFile(from, to);
    }

    public Path moveFile(Path path, Path newPath) {
        return fileManager.moveFile(path, newPath);
    }

    public String renameFile(Path path, String fileName) {
        return fileManager.renameFile(path, fileName);
    }

    public void deleteFile(Path path) {
        fileManager.deleteFile(path);
    }

    public List<String> getFilesList(Path path) {
        return fileManager.getFilesList(path);
    }

    public void abortAllFileTransfers() {
        fileManager.abortAllFileTransfers();
    }

    public boolean addKey(WebsiteIdPair websiteIdPair, String value, KeyType keyType) {
        return passwordAndAPIKeyManager.addKey(websiteIdPair, value, keyType);
    }

    public String getKeyValue(WebsiteIdPair websiteIdPair, KeyType keyType) {
        return passwordAndAPIKeyManager.getKeyValue(websiteIdPair, keyType);
    }

    public void deleteKey(WebsiteIdPair websiteIdPair, KeyType keyType) {
        passwordAndAPIKeyManager.deleteKey(websiteIdPair, keyType);
    }

    public List<WebsiteIdPair> searchKey(WebsiteIdPair websiteIdPair, KeyType keyType) {
        return passwordAndAPIKeyManager.searchKey(websiteIdPair, keyType);
    }

    public void clearKeys(KeyType keyType) {
        passwordAndAPIKeyManager.clearKeys(keyType);
    }

    public Set<WebsiteIdPair> getAllKeys(KeyType keyType) {
        return passwordAndAPIKeyManager.getAllKeys(keyType);
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

    public void lockdownVault(long minutes) {
        configurationManager.enableLockdownMode(minutes);
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

    private void deleteFilesRecursively(Path path) {
        try {
            if (Files.isDirectory(path)) {
                Files.list(path).forEach(this::deleteFilesRecursively);
            }
            Files.delete(path);
        } catch (Exception _) {
        }
    }

    public void selfDestruct(char[] password) {
        if (different(this.password, password)) {
            logger.logSevere("Vault destruction failed due to wrong vault key.");
            throw new VaultException("Wrong vault key. Vault not destructed.");
        }
        logger.logWarn("Vault entered self destruction mode.");
        configurationManager.selfDestruct();
        closeVault();
        deleteFilesRecursively(vaultPath);
    }

    public String getVersion() {
        return configurationManager.getVersion();
    }

    public Logger getLogger() {
        return logger;
    }

    public void clearLogs() {
        logger.clearLogs();
    }

    public void closeVault() {
        if (!isVaultOpen()) {
            return;
        }
        logger.logInfo("Closing vault.");
        autoSaver.shutdown();
        try {
            isVaultOpen = false;
            int n = vaultKey.length;
            configurationManager.writeData();
            fileManager.close();
            passwordAndAPIKeyManager.close();
            logger.close();
            for (int i = 0; i < n; i++) {
                vaultKey[i] = 0;
            }
        } catch (Exception e) {
            throw new VaultException("Exception occurred while performing shutdown tasks of Vault : " + e);
        }
    }

    static class AutoSaver {
        private final long RECHECK_DELAY = 500;
        private final LinkedList<Writable> autosave = new LinkedList<>();
        private final Semaphore lock = new Semaphore(1, true);
        private final long delay;
        private final AtomicBoolean shutdown = new AtomicBoolean(false);
        private final AtomicBoolean isShutdown = new AtomicBoolean(false);

        AutoSaver(long delay) {
            this.delay = delay;
        }

        void start() {
            new Thread(() -> {
                while (!shutdown.get()) {
                    long value = System.currentTimeMillis() + delay;
                    while (System.currentTimeMillis() < value && !shutdown.get()) {
                        try {
                            Thread.sleep(RECHECK_DELAY);
                        } catch (Exception _) {
                        }
                    }
                    if (!shutdown.get()) {
                        if (lock()) {
                            for (Writable writable : autosave) {
                                try {
                                    writable.writeData();
                                } catch (Exception _) {
                                }
                            }
                            unlock();
                        }
                    }
                }
                isShutdown.set(true);
            }).start();
        }

        private boolean lock() {
            try {
                lock.acquire();
                return true;
            } catch (Exception e) {
                return false;
            }
        }

        private void unlock() {
            lock.release();
        }

        void register(Writable writable) {
            if (!lock()) {
                return;
            }
            autosave.add(writable);
            unlock();
        }

        void deregister(Writable writable) {
            if (!lock()) {
                return;
            }
            autosave.remove(writable);
            unlock();
        }

        void shutdown() {
            shutdown.set(true);
            while (!isShutdown.get()) {
                try {
                    Thread.sleep(RECHECK_DELAY);
                } catch (InterruptedException _) {
                }
            }
        }
    }
}