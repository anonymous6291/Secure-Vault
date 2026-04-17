package com.securevault;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Semaphore;

public class FileManager {
    private static final String FILE_STORAGE_FOLDER_NAME = "files";
    private static final String FILE_DATA_NAME = "files.data";
    private static final String FILE_DATA_END_MARKER = "#############################END#############################";
    private final Semaphore lock = new Semaphore(1);
    private final Path fileDataPath;
    private final Path fileStoragePath;
    private final char[] vaultKey;
    private final byte[] iv;
    private final byte[] salt;
    private final Map<String, FileData> allFiles;
    private volatile char[] lastFileName;

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
        File dataFile = fileDataPath.toFile();
        String lastFileName = "0";
        if (dataFile.length() > 0) {
            BufferedInputStream bufferedInputStream = new BufferedInputStream(Files.newInputStream(fileDataPath));
            iv = bufferedInputStream.readNBytes(ConfigurationDefaults.IV_LENGTH);
            salt = bufferedInputStream.readNBytes(ConfigurationDefaults.SALT_LENGTH);
            Cipher cipher = CipherManager.getCipher(vaultKey, iv, salt, Cipher.DECRYPT_MODE);
            CipherInputStream cipherInputStream = new CipherInputStream(bufferedInputStream, cipher);
            String fileData = new String(cipherInputStream.readAllBytes());
            cipherInputStream.close();
            String[] data = fileData.split("\n");
            int n = data.length;
            for (int i = 0; i < n; i += 2) {
                String path = data[i];
                String originalName = data[i + 1];
                File file = fileStoragePath.resolve(path).toFile();
                if (!file.exists()) {
                    Logger.logError("File [" + originalName + "] has entry but doesn't exist, skipping it.");
                } else {
                    String maskedName = file.getName();
                    if (!isValidFileName(maskedName)) {
                        Logger.logError("[" + maskedName + "] is not a valid file name, skipping it.");
                    } else {
                        if (lastFileName.compareTo(maskedName) < 0) {
                            lastFileName = maskedName;
                        }
                        FileData currentFileData = new FileData(originalName, maskedName, file.length(), path);
                        allFiles.put(maskedName, currentFileData);
                    }
                }
            }
            Logger.logInfo("Total [" + allFiles.size() + "] file entries scanned.");
        } else {
            iv = RandomValueGenerator.generateSecureBytes(ConfigurationDefaults.IV_LENGTH);
            salt = RandomValueGenerator.generateSecureBytes(ConfigurationDefaults.SALT_LENGTH);
        }
        this.lastFileName = lastFileName.toCharArray();
        if (!allFiles.isEmpty()) {
            incrementFileName();
        }
    }

    private boolean lock() {
        try {
            lock.acquire();
            return true;
        } catch (InterruptedException e) {
            return false;
        }
    }

    private void unlock() {
        lock.release();
    }

    private boolean isValidFileName(String name) {
        int n = name.length();
        for (int i = 0; i < n; i++) {
            char x = name.charAt(i);
            if (x < '0' || x > '9') {
                return false;
            }
        }
        return true;
    }

    private void incrementFileName() {
        for (int i = lastFileName.length - 1; i >= 0; i--) {
            if (lastFileName[i] == '9') {
                lastFileName[i] = '0';
            } else {
                lastFileName[i]++;
                return;
            }
        }
        int n = lastFileName.length;
        char[] nextFileName = new char[n + 1];
        Arrays.fill(nextFileName, 0, n + 1, '0');
        lastFileName = nextFileName;
    }

    public List<FileData> getFilesList() {
        if (!lock()) {
            return null;
        }
        List<FileData> fileDataList = List.copyOf(allFiles.values());
        unlock();
        Logger.logInfo("All files list accessed.");
        return fileDataList;
    }

    private int addFilesRecursively(File current, Path pathToCopy) throws Exception {
        if (current.isFile()) {
            try {
                return 1;
            } catch (Exception e) {
                return 0;
            }
        } else {
            int result = 0;
            Path nextPath = pathToCopy.resolve(current.getName());
            File[] subFiles = current.listFiles();
            if (subFiles != null) {
                for (File file : subFiles) {
                    result += addFilesRecursively(file, nextPath);
                }
            }
            return result;
        }
    }

    public int addFiles(File current, String pathToCopy) throws Exception {
        if (!lock()) {
            return 0;
        }
        try {
            return addFilesRecursively(current, fileStoragePath.resolve(pathToCopy));
        } finally {
            unlock();
        }
    }

    public boolean changeFileName(String maskedName, String newOriginalName) {
        FileData fileData = allFiles.get(maskedName);
        if (fileData == null) {
            Logger.logError("Attempted to rename a file which doesn't has entry.");
            return false;
        }
        fileData.setOriginalName(newOriginalName);
        return true;
    }

    public void close() throws Exception {
        if (!lock()) {
            return;
        }
        try {
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(Files.newOutputStream(fileDataPath));
            bufferedOutputStream.write(iv);
            bufferedOutputStream.write(salt);
            Cipher cipher = CipherManager.getCipher(vaultKey, iv, salt, Cipher.ENCRYPT_MODE);
            CipherOutputStream cipherOutputStream = new CipherOutputStream(bufferedOutputStream, cipher);
            for (FileData data : allFiles.values()) {
                String value = data.getFilePath() + "\n" + data.getOriginalName() + "\n";
                cipherOutputStream.write(value.getBytes());
            }
            cipherOutputStream.write(FILE_DATA_END_MARKER.getBytes());
            cipherOutputStream.close();
            Logger.logInfo("FileManager closed.");
        } catch (Exception e) {
            Logger.logError("Exception occurred while closing the FileManager : " + e);
            throw e;
        } finally {
            unlock();
        }
    }
}