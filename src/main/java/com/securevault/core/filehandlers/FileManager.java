package com.securevault.core.filehandlers;

import com.securevault.core.Logger;
import com.securevault.core.configurations.CipherManager;
import com.securevault.core.configurations.ConfigurationDefaults;
import com.securevault.core.configurations.RandomValueGenerator;
import com.securevault.core.filehandlers.listeners.FileManagerUpdateListener;
import com.securevault.core.filehandlers.listeners.FileTransferManagerListener;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Semaphore;
import java.util.stream.Stream;

public class FileManager implements FileTransferManagerListener {
    private static final String FILE_STORAGE_FOLDER_NAME = "files";
    private static final String FILE_DATA_NAME = "files.data";
    private static final String FILE_DATA_END_MARKER = "#############################END#############################";
    private final Semaphore lock = new Semaphore(1);
    private final Path fileDataPath;
    private final Path fileStoragePath;
    private final char[] vaultKey;
    private final byte[] iv;
    private final byte[] salt;
    private final ConcurrentMap<Path, FileData> allFilesDataMapping;
    private final ConcurrentMap<Path, Path> allFilesMaskedNameMapping;
    private final FileTransferManager fileTransferManager;
    private final FileManagerUpdateListener fileManagerUpdateListener;
    private final Logger logger;
    private volatile char[] nextMaskedFileName;

    public FileManager(Path basePath, char[] vaultKey, FileManagerUpdateListener fileManagerUpdateListener, Logger logger) throws Exception {
        this.logger = logger;
        fileDataPath = Path.of(basePath.toString(), FILE_DATA_NAME);
        fileStoragePath = Path.of(basePath.toString(), FILE_STORAGE_FOLDER_NAME);
        if (!Files.isRegularFile(fileDataPath)) {
            Files.createFile(fileDataPath);
        }
        if (!Files.isDirectory(fileStoragePath)) {
            Files.createDirectories(fileStoragePath);
        }
        this.vaultKey = vaultKey;
        this.fileManagerUpdateListener = fileManagerUpdateListener;
        allFilesDataMapping = new ConcurrentHashMap<>();
        allFilesMaskedNameMapping = new ConcurrentHashMap<>();
        File dataFile = fileDataPath.toFile();
        String lastFileName = "0";
        logger.logInfo("FileManager started.");
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
            for (int i = 2; i < n; i += 3) {
                String path = data[i - 2];
                String maskedName = data[i - 1];
                String originalName = data[i];
                Path mainPath = Path.of(fileStoragePath.toString(), path);
                Path maskedFilePath = Path.of(mainPath.toString(), maskedName);
                File file = maskedFilePath.toFile();
                if (!file.exists()) {
                    logger.logError("File [" + originalName + "] has entry but doesn't exist, skipping it.");
                } else {
                    if (!isValidFileName(maskedName)) {
                        logger.logError("[" + maskedName + "] is not a valid file name, skipping it.");
                    } else {
                        if (smaller(lastFileName, maskedName)) {
                            lastFileName = maskedName;
                        }
                        FileData currentFileData = new FileData(originalName, maskedName, file.length(), path);
                        allFilesDataMapping.put(maskedFilePath, currentFileData);
                        allFilesMaskedNameMapping.put(Path.of(mainPath.toString(), originalName), maskedFilePath);
                    }
                }
            }
            logger.logInfo("Total [" + allFilesDataMapping.size() + "] file entries scanned.");
        } else {
            iv = RandomValueGenerator.generateSecureBytes(ConfigurationDefaults.IV_LENGTH);
            salt = RandomValueGenerator.generateSecureBytes(ConfigurationDefaults.SALT_LENGTH);
        }
        this.nextMaskedFileName = lastFileName.toCharArray();
        fileTransferManager = new FileTransferManager(vaultKey, this, logger);
        fileTransferManager.start();
        fileManagerUpdateListener.setFileTransferMonitor(fileTransferManager);
        if (!allFilesDataMapping.isEmpty()) {
            incrementNextFileName();
        }
    }

    private boolean smaller(String first, String second) {
        int n1 = first.length();
        int n2 = second.length();
        return n1 < n2 || (n1 == n2 && first.compareTo(second) < 0);
    }

    private Path removeParent(Path childPath, Path parentPath) {
        String child = childPath.toString();
        String parent = parentPath.toString();
        return Path.of(child.substring(child.indexOf(parent) + parent.length() + 1));
    }

    private void incrementNextFileName() {
        for (int i = nextMaskedFileName.length - 1; i >= 0; i--) {
            if (nextMaskedFileName[i] == '9') {
                nextMaskedFileName[i] = '0';
            } else {
                nextMaskedFileName[i]++;
                return;
            }
        }
        int n = nextMaskedFileName.length;
        char[] nextFileName = new char[n + 1];
        Arrays.fill(nextFileName, 0, n + 1, '0');
        this.nextMaskedFileName = nextFileName;
    }

    private String getNewMaskedFileName() {
        String fileName = new String(nextMaskedFileName);
        incrementNextFileName();
        return fileName;
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

    private boolean fileExists(Path filePath, FileTransferMode mode) {
        if (mode == FileTransferMode.ENCRYPT) {
            return allFilesMaskedNameMapping.containsKey(filePath);
        } else {
            return Files.exists(filePath);
        }
    }

    private Path renameFile(Path toFilePath, FileTransferMode mode) {
        Path parent = toFilePath.getParent();
        String fileName = toFilePath.getFileName().toString();
        int dotIndex = fileName.indexOf(".");
        String firstName, extension;
        if (dotIndex == -1) {
            firstName = fileName;
            extension = "";
        } else {
            firstName = fileName.substring(0, dotIndex);
            extension = fileName.substring(dotIndex);
        }
        int start = 1;
        Path newFilePath;
        while (fileExists(newFilePath = Path.of(parent.toString(), firstName + start + extension), mode)) {
            start++;
        }
        return newFilePath;
    }

    private void addFile0(Path from, Path to, FileTransferMode mode, List<FileTransferData> fileTransferDataList, FileCopyOption fileCopyOption) {
        Path toFilePath;
        Map<String, String> notes = null;
        if (mode == FileTransferMode.ENCRYPT) {
            Path originalFilePath = Path.of(to.toString(), from.getFileName().toString());
            if (allFilesMaskedNameMapping.containsKey(originalFilePath)) {
                FileCopyOption.Type fileCopyType = fileCopyOption.getType();
                if (fileCopyType == FileCopyOption.Type.RENAME_ALL || fileCopyType == FileCopyOption.Type.RENAME) {
                    if (fileCopyType == FileCopyOption.Type.RENAME) {
                        fileCopyOption.resetType();
                    }
                    toFilePath = Path.of(to.toString(), getNewMaskedFileName());
                    notes = Map.of("renamed", renameFile(originalFilePath, mode).getFileName().toString());
                } else if (fileCopyType == FileCopyOption.Type.SKIP_ALL || fileCopyType == FileCopyOption.Type.SKIP) {
                    if (fileCopyType == FileCopyOption.Type.SKIP) {
                        fileCopyOption.resetType();
                    }
                    return;
                } else if (fileCopyType == FileCopyOption.Type.ASK) {
                    int responseIndex = fileManagerUpdateListener.askForResponse("File [" + originalFilePath + "] already exists in vault.", FileCopyOption.options);
                    fileCopyOption.setType(responseIndex);
                    addFile0(from, to, mode, fileTransferDataList, fileCopyOption);
                    return;
                } else {
                    if (fileCopyType == FileCopyOption.Type.REPLACE) {
                        fileCopyOption.resetType();
                    }
                    FileData fileData = allFilesDataMapping.get(allFilesMaskedNameMapping.get(originalFilePath));
                    toFilePath = to.resolve(fileData.getMaskedName());
                }
            } else {
                toFilePath = to.resolve(getNewMaskedFileName());
            }
        } else {
            FileData fileData = allFilesDataMapping.get(from);
            if (fileData == null) {
                return;
            }
            String originalFileName = fileData.getOriginalName();
            toFilePath = to.resolve(originalFileName);
            if (Files.exists(toFilePath)) {
                FileCopyOption.Type fileCopyType = fileCopyOption.getType();
                if (fileCopyType == FileCopyOption.Type.RENAME_ALL || fileCopyType == FileCopyOption.Type.RENAME) {
                    if (fileCopyType == FileCopyOption.Type.RENAME) {
                        fileCopyOption.resetType();
                    }
                    toFilePath = renameFile(toFilePath, mode);
                } else if (fileCopyType == FileCopyOption.Type.SKIP_ALL || fileCopyType == FileCopyOption.Type.SKIP) {
                    if (fileCopyType == FileCopyOption.Type.SKIP) {
                        fileCopyOption.resetType();
                    }
                    return;
                } else if (fileCopyType == FileCopyOption.Type.ASK) {
                    int index = fileManagerUpdateListener.askForResponse("File [" + toFilePath + "] already exists.", FileCopyOption.options);
                    fileCopyOption.setType(index);
                    addFile0(from, to, mode, fileTransferDataList, fileCopyOption);
                    return;
                } else if (fileCopyType == FileCopyOption.Type.REPLACE) {
                    fileCopyOption.resetType();
                }
            }
        }
        FileTransferData fileTransferData = new FileTransferData(from, toFilePath, mode, notes == null ? Map.of() : notes);
        fileTransferDataList.add(fileTransferData);
    }

    private void recursivelyAddFiles(Path from, Path to, FileTransferMode mode, List<FileTransferData> fileTransferDataList, FileCopyOption fileCopyOption) {
        if (Files.isDirectory(from)) {
            Path toSubDirectory = to.resolve(from.getFileName());
            try (Stream<Path> pathStream = Files.list(from)) {
                pathStream.forEach(fromSubDirectory -> recursivelyAddFiles(fromSubDirectory, toSubDirectory, mode, fileTransferDataList, fileCopyOption));
            } catch (Exception e) {
                logger.logError("Exception occurred while traversing files : " + e);
            }
        } else if (Files.isRegularFile(from)) {
            addFile0(from, to, mode, fileTransferDataList, fileCopyOption);
        }
    }

    public void addFiles(Path from) throws FileNotFoundException {
        if (!Files.exists(from)) {
            throw new FileNotFoundException("[" + from + "] doesn't exist.");
        }
        List<FileTransferData> fileTransferDataList = new LinkedList<>();
        recursivelyAddFiles(from, fileStoragePath, FileTransferMode.ENCRYPT, fileTransferDataList, new FileCopyOption());
        fileTransferManager.transferFiles(fileTransferDataList);
    }

    public void getFiles(Path from, Path to) throws FileNotFoundException {
        Path fromPath = fileStoragePath.resolve(from);
        if (!Files.exists(fromPath)) {
            throw new FileNotFoundException("[" + from + "] doesn't exist.");
        }
        List<FileTransferData> fileTransferDataList = new LinkedList<>();
        recursivelyAddFiles(fromPath, to, FileTransferMode.DECRYPT, fileTransferDataList, new FileCopyOption());
        fileTransferManager.transferFiles(fileTransferDataList);
    }

    public boolean changeFileName(Path path, String newOriginalName) {
        Path maskedPath = allFilesMaskedNameMapping.remove(path);
        if (maskedPath == null) {
            logger.logError("Attempted to rename a file which doesn't has entry.");
            return false;
        }
        FileData fileData = allFilesDataMapping.get(maskedPath);
        fileData.setOriginalName(newOriginalName);
        allFilesMaskedNameMapping.put(path.resolveSibling(newOriginalName), maskedPath);
        return true;
    }

    private void deleteFile0(Path originalFilePath) {
        Path maskedFilePath = allFilesMaskedNameMapping.remove(originalFilePath);
        if (maskedFilePath == null) {
            return;
        }
        allFilesDataMapping.remove(maskedFilePath);
        try {
            Files.delete(maskedFilePath);
        } catch (Exception e) {
            logger.logError("Failed to delete file [" + originalFilePath + "] : " + e);
        }
    }

    public void deleteFile(Path path) {
        if (!lock()) {
            return;
        }
        Path filePath = Path.of(fileStoragePath.toString(), path.toString());
        logger.logWarn("Deleting file [" + path + "] .");
        deleteFile0(filePath);
        unlock();
    }

    private void deleteDirectory0(Path filePath) {
        if (Files.isDirectory(filePath)) {
            try (Stream<Path> files = Files.list(filePath)) {
                files.forEach(this::deleteDirectory0);
                Files.delete(filePath);
            } catch (Exception e) {
                logger.logError("Failed to delete directory [" + filePath + "] : " + e);
            }
        } else {
            FileData fileData = allFilesDataMapping.get(filePath);
            if (fileData != null) {
                deleteFile0(fileStoragePath.resolve(fileData.getOriginalFilePath()));
            }
        }
    }

    public void deleteDirectory(Path path) {
        if (!lock()) {
            return;
        }
        Path fileToBeDeleted = Path.of(fileStoragePath.toString(), path.toString());
        if (Files.isDirectory(fileToBeDeleted)) {
            logger.logWarn("Deleting directory [" + path + "] .");
            deleteDirectory0(fileToBeDeleted);
        }
        unlock();
    }

    public List<String> getFilesList() {
        if (!lock()) {
            return null;
        }
        List<String> fileDataList = new ArrayList<>();
        allFilesDataMapping.values().stream().map(fileData -> fileData.getOriginalFilePath().toString()).forEach(fileDataList::add);
        unlock();
        fileDataList.sort(String::compareTo);
        logger.logInfo("All files list accessed.");
        return fileDataList;
    }

    public void abortAllFileTransfers() {
        fileTransferManager.abortAllFileTransfers();
    }

    public void close() throws Exception {
        if (!lock()) {
            return;
        }
        fileTransferManager.shutdown();
        try {
            BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(Files.newOutputStream(fileDataPath));
            bufferedOutputStream.write(iv);
            bufferedOutputStream.write(salt);
            Cipher cipher = CipherManager.getCipher(vaultKey, iv, salt, Cipher.ENCRYPT_MODE);
            CipherOutputStream cipherOutputStream = new CipherOutputStream(bufferedOutputStream, cipher);
            for (FileData data : allFilesDataMapping.values()) {
                String value = data.getFilePath() + "\n" + data.getMaskedName() + "\n" + data.getOriginalName() + "\n";
                cipherOutputStream.write(value.getBytes());
            }
            cipherOutputStream.write(FILE_DATA_END_MARKER.getBytes());
            cipherOutputStream.close();
            logger.logInfo("FileManager closed.");
        } catch (Exception e) {
            logger.logError("Exception occurred while closing the FileManager : " + e);
            throw e;
        } finally {
            unlock();
        }
    }

    @Override
    public void fileTransferCompleted(FileTransferData fileTransferData) {
        Path from = fileTransferData.from();
        if (fileTransferData.mode() == FileTransferMode.ENCRYPT) {
            Path to = fileTransferData.to();
            File toFile = to.toFile();
            String fromFileName;
            if (fileTransferData.notes().containsKey("renamed")) {
                fromFileName = fileTransferData.notes().get("renamed");
            } else {
                fromFileName = from.getFileName().toString();
            }
            FileData fileData = new FileData(fromFileName, toFile.getName(), toFile.length(), removeParent(to.getParent(), fileStoragePath).toString());
            allFilesDataMapping.put(to, fileData);
            allFilesMaskedNameMapping.put(Path.of(fileStoragePath.toString(), fileData.getOriginalFilePath().toString()), to);
        }
        logger.logInfo("File [" + from + "] transfer complete.");
    }

    @Override
    public void fileTransferFailed(FileTransferData fileTransferData) {
        if (fileTransferData.mode() == FileTransferMode.ENCRYPT) {
            fileManagerUpdateListener.newUpdate("Failed to add file [" + fileTransferData.from() + "] to the vault.");
        } else {
            fileManagerUpdateListener.newUpdate("Failed to copy file to [" + fileTransferData.to() + "] from the vault.");
        }
    }

    static class FileCopyOption {
        private static final List<String> options = Arrays.stream(Type.values()).filter(x -> x != Type.ASK).map(Enum::toString).toList();
        private Type type;

        FileCopyOption() {
            this.type = Type.ASK;
        }

        Type getType() {
            return type;
        }

        void setType(Type type) {
            this.type = type;
        }

        void setType(int type) {
            this.type = switch (type) {
                case 0 -> Type.REPLACE;
                case 1 -> Type.REPLACE_ALL;
                case 2 -> Type.RENAME;
                case 3 -> Type.RENAME_ALL;
                case 4 -> Type.SKIP;
                default -> Type.SKIP_ALL;
            };
        }

        void resetType() {
            this.type = Type.ASK;
        }

        enum Type {
            ASK, REPLACE, REPLACE_ALL, RENAME, RENAME_ALL, SKIP, SKIP_ALL
        }
    }
}