package com.securevault;

import javax.crypto.Cipher;
import java.io.BufferedInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Semaphore;

public class FileManager {
    private static final String FILE_STORAGE_FOLDER_NAME = "files";
    private static final String FILE_DATA_NAME = "files.data";
    private final Map<String, FileData> allFiles;
    private final Path fileDataPath;
    private final Path fileStoragePath;
    private final char[] vaultKey;
    private final Semaphore lock = new Semaphore(1);

    FileManager(Path basePath, char[] vaultKey) throws Exception {
        this.vaultKey = vaultKey;
        fileDataPath = basePath.resolve(FILE_DATA_NAME);
        fileStoragePath = basePath.resolve(FILE_STORAGE_FOLDER_NAME);
        if (!Files.isRegularFile(fileDataPath)) {
            Files.createFile(fileDataPath);
        }
        if (!Files.isDirectory(fileStoragePath)) {
            Files.createDirectories(fileStoragePath);
        }
        allFiles = new HashMap<>();
        BufferedInputStream bufferedInputStream = new BufferedInputStream(Files.newInputStream(fileDataPath));
        byte[] iv = bufferedInputStream.readNBytes(ConfigurationDefaults.IV_LENGTH);
        byte[] salt = bufferedInputStream.readNBytes(ConfigurationDefaults.SALT_LENGTH);
        Cipher cipher = CipherManager.getCipher(vaultKey, iv, salt, Cipher.DECRYPT_MODE);
    }
}

class FileData {
    private final String maskedName;
    private final long fileLength;
    private String originalName;

    FileData(String originalName, String maskedName, long fileLength) {
        this.originalName = originalName;
        this.maskedName = maskedName;
        this.fileLength = fileLength;
    }

    public void setNewOriginalName(String newOriginalName) {
        this.originalName = newOriginalName;
    }

    public String getOriginalName() {
        return originalName;
    }

    public String getMaskedName() {
        return maskedName;
    }

    public long getFileLength() {
        return fileLength;
    }
}