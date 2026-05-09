package com.securevault.core.filehandlers;

import com.securevault.core.Logger;
import com.securevault.core.Writable;
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

public class FileManager implements FileTransferManagerListener, Writable {
    private static final String FILE_STORAGE_FOLDER_NAME = "files";
    private static final String FILE_DATA_NAME = "files.data";
    private static final String FILE_DATA_END_MARKER = "#############################END#############################";
    private final Semaphore lock = new Semaphore(1, true);
    private final Path fileDataPath;
    private final Path fileStoragePath;
    private final char[] vaultKey;
    private final byte[] iv;
    private final byte[] salt;
    private final PathTrie allFiles = new PathTrie();
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
        File dataFile = fileDataPath.toFile();
        String lastFileName = "0";
        logger.logInfo("FileManager started.");
        int filesCount = 0;
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
                Path maskedFilePath = Path.of(fileStoragePath.toString(), path, maskedName);
                File file = maskedFilePath.toFile();
                if (!file.exists()) {
                    logger.logError("File [" + path + "] has entry but doesn't exist, skipping it.");
                } else {
                    if (!isValidFileName(maskedName)) {
                        logger.logError("[" + maskedName + "] is not a valid file name, skipping it.");
                    } else {
                        if (smaller(lastFileName, maskedName)) {
                            lastFileName = maskedName;
                        }
                        FileData currentFileData = new FileData(originalName, maskedName, file.length(), path);
                        allFiles.putFileData(Path.of(path, originalName).toString(), currentFileData);
                        filesCount++;
                    }
                }
            }
            logger.logInfo("Total [" + filesCount + "] file entries scanned.");
        } else {
            iv = RandomValueGenerator.generateSecureBytes(ConfigurationDefaults.IV_LENGTH);
            salt = RandomValueGenerator.generateSecureBytes(ConfigurationDefaults.SALT_LENGTH);
        }
        this.nextMaskedFileName = lastFileName.toCharArray();
        fileTransferManager = new FileTransferManager(vaultKey, this, logger);
        fileTransferManager.start();
        fileManagerUpdateListener.setFileTransferMonitor(fileTransferManager);
        if (filesCount != 0) {
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
            return allFiles.fileExists(filePath.toString());
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

    private void addFileForTransfer(Path from, Path to, List<FileTransferData> fileTransferDataList, FileTransferMode fileTransferMode, FileCopyOption fileCopyOption) {
        if ((fileTransferMode == FileTransferMode.ENCRYPT && !Files.isRegularFile(from)) || (fileTransferMode == FileTransferMode.DECRYPT && !allFiles.fileExists(from.toString()))) {
            return;
        }
        Map<String, String> notes = Map.of();
        Path toFilePath;
        Path targetFilePath = Path.of(to.toString(), from.getFileName().toString());
        if ((fileTransferMode == FileTransferMode.ENCRYPT && allFiles.fileExists(targetFilePath.toString())) || (fileTransferMode == FileTransferMode.DECRYPT && Files.isRegularFile(targetFilePath))) {
            FileCopyOption.Type fileCopyType = fileCopyOption.getType();
            if (fileCopyType == FileCopyOption.Type.RENAME_ALL || fileCopyType == FileCopyOption.Type.RENAME) {
                String renamedName = renameFile(targetFilePath, fileTransferMode).getFileName().toString();
                if (fileTransferMode == FileTransferMode.ENCRYPT) {
                    notes = Map.of("renamed", renamedName);
                    toFilePath = Path.of(fileStoragePath.toString(), to.toString(), getNewMaskedFileName());
                } else {
                    toFilePath = Path.of(to.toString(), renamedName);
                }
            } else if (fileCopyType == FileCopyOption.Type.SKIP_ALL || fileCopyType == FileCopyOption.Type.SKIP) {
                return;
            } else if (fileCopyType == FileCopyOption.Type.ASK) {
                int responseIndex = fileManagerUpdateListener.askForResponse("File [" + targetFilePath + "] already exists in vault.", FileCopyOption.options);
                fileCopyOption.setType(responseIndex);
                addFileForTransfer(from, to, fileTransferDataList, fileTransferMode, fileCopyOption);
                return;
            } else {
                if (fileTransferMode == FileTransferMode.ENCRYPT) {
                    FileData fileData = allFiles.getFileData(targetFilePath.toString());
                    if (fileData == null) {
                        return;
                    }
                    toFilePath = Path.of(fileStoragePath.toString(), fileData.getMaskedFilePath().toString());
                } else {
                    toFilePath = targetFilePath;
                }
            }
        } else {
            if (fileTransferMode == FileTransferMode.ENCRYPT) {
                toFilePath = Path.of(fileStoragePath.toString(), to.toString(), getNewMaskedFileName());
            } else {
                toFilePath = Path.of(to.toString(), from.getFileName().toString());
            }
        }
        if (fileTransferMode == FileTransferMode.DECRYPT) {
            FileData fileData = allFiles.getFileData(from.toString());
            if (fileData == null) {
                return;
            }
            from = Path.of(fileStoragePath.toString(), fileData.getMaskedFilePath().toString());
        }
        FileTransferData fileTransferData = new FileTransferData(from, toFilePath, fileTransferMode, notes);
        fileTransferDataList.add(fileTransferData);
    }

    private void recursivelyAddFiles(Path from, Path to, List<FileTransferData> fileTransferDataList, FileCopyOption fileCopyOption) {
        if (Files.isDirectory(from)) {
            Path toSubDirectory = Path.of(to.toString(), from.getFileName().toString());
            try (Stream<Path> pathStream = Files.list(from)) {
                pathStream.forEach(fromSubFile -> recursivelyAddFiles(fromSubFile, toSubDirectory, fileTransferDataList, fileCopyOption));
            } catch (Exception e) {
                logger.logError("Exception occurred while traversing files : " + e);
            }
        } else if (Files.isRegularFile(from)) {
            addFileForTransfer(from, to, fileTransferDataList, FileTransferMode.ENCRYPT, fileCopyOption);
        }
    }

    public void addFile(Path from, Path to) throws FileNotFoundException {
        if (!Files.exists(from)) {
            throw new FileNotFoundException("[" + from + "] doesn't exist.");
        }
        if (!lock()) {
            return;
        }
        try {
            List<FileTransferData> fileTransferDataList = new LinkedList<>();
            addFileForTransfer(from, to, fileTransferDataList, FileTransferMode.ENCRYPT, new FileCopyOption());
            fileTransferManager.transferFiles(fileTransferDataList);
        } finally {
            unlock();
        }
    }

    public void addFiles(Path from, Path to) throws FileNotFoundException {
        if (!Files.exists(from)) {
            throw new FileNotFoundException("[" + from + "] doesn't exist.");
        }
        if (!lock()) {
            return;
        }
        try {
            List<FileTransferData> fileTransferDataList = new LinkedList<>();
            recursivelyAddFiles(from, to, fileTransferDataList, new FileCopyOption());
            fileTransferManager.transferFiles(fileTransferDataList);
        } finally {
            unlock();
        }
    }

    private void recursivelyGetFiles(Path from, Path to, List<FileTransferData> fileTransferDataList, FileCopyOption fileCopyOption) {
        if (allFiles.directoryExists(from.toString())) {
            Path toSubDirectory = Path.of(to.toString(), from.getFileName().toString());
            allFiles.di
        } else if (allFiles.fileExists(from.toString())) {
        }
    }

    public void getFile(Path from, Path to) {
        if (!lock()) {
            return;
        }
        try {
            List<FileTransferData> fileTransferDataList = new LinkedList<>();
            addFileForTransfer(from, to, fileTransferDataList, FileTransferMode.DECRYPT, new FileCopyOption());
            fileTransferManager.transferFiles(fileTransferDataList);
        } finally {
            unlock();
        }
    }

    public void getFiles(Path from, Path to) {
        if (!lock()) {
            return;
        }
        try {
            List<FileTransferData> fileTransferDataList = new LinkedList<>();
            recursivelyAddFiles(from, to, fileTransferDataList, new FileCopyOption());
            fileTransferManager.transferFiles(fileTransferDataList);
        } finally {
            unlock();
        }
    }

    public boolean changeFileName(Path path, String newOriginalName) {
        FileData fileData = allFiles.deleteFile(path.toString());
        if (fileData == null) {
            logger.logError("Attempted to rename a file which doesn't has entry.");
            return false;
        }
        allFiles.putFileData(Path.of(path.getParent().toString(), newOriginalName).toString(), fileData);
        return true;
    }

    public void deleteFile(Path path) {
        if (!lock()) {
            return;
        }
        FileData fileData = allFiles.deleteFile(path.toString());
        try {
            if (fileData != null) {
                Path filePath = Path.of(fileStoragePath.toString(), fileData.getMaskedName());
                logger.logWarn("Deleting file [" + path + "] .");
                Files.delete(filePath);
            }
        } catch (Exception _) {
        } finally {
            unlock();
        }
    }

    public void makeDirectory(Path path) {
        try {
            Path directory = Path.of(fileStoragePath.toString(), path.toString());
            Files.createDirectories(directory);
        } catch (Exception _) {
        }
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
                deleteFile0(Path.of(fileStoragePath.toString(), fileData.getOriginalFilePath().toString()));
            }
        }
    }

    public void deleteDirectory(Path path) {
        if (!lock()) {
            return;
        }
        try {
            Path fileToBeDeleted = Path.of(fileStoragePath.toString(), path.toString());
            if (Files.isDirectory(fileToBeDeleted)) {
                logger.logWarn("Deleting directory [" + path + "] .");
                deleteDirectory0(fileToBeDeleted);
            }
        } finally {
            unlock();
        }
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

    @Override
    public void writeData() throws Exception {
        lock();
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
        } catch (Exception e) {
            logger.logError("Exception occurred while writing data of FileManager : " + e);
            throw e;
        } finally {
            unlock();
        }
    }

    public void close() throws Exception {
        fileTransferManager.shutdown();
        writeData();
        logger.logInfo("FileManager closed.");
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

    static class PathTrie {
        static final String pathSeparator = File.separator;

        static class PathTrieNode {
            String name;
            ConcurrentMap<String, PathTrieNode> directories = new ConcurrentHashMap<>();
            ConcurrentMap<String, FileData> filesData = new ConcurrentHashMap<>();

            PathTrieNode(String name) {
                this.name = name;
            }

            void rename(String name) {
                this.name = name;
            }

            void putFileData(String name, FileData fileData) {
                filesData.put(name, fileData);
            }

            FileData getFileData(String name) {
                return filesData.get(name);
            }

            boolean fileDataExists(String name) {
                return filesData.containsKey(name);
            }

            FileData deleteFileData(String name) {
                return filesData.remove(name);
            }

            Set<String> getFilesList() {
                return filesData.keySet();
            }

            PathTrieNode putDirectory(String name) {
                PathTrieNode pathTrieNode = directories.get(name);
                if (pathTrieNode == null) {
                    directories.put(name, pathTrieNode = new PathTrieNode(name));
                }
                return pathTrieNode;
            }

            PathTrieNode getDirectory(String name) {
                return directories.get(name);
            }

            boolean isDirectory(String name) {
                return directories.containsKey(name);
            }

            void deleteDirectory(String name) {
                directories.remove(name);
            }

            Set<String> getDirectoriesList() {
                return directories.keySet();
            }

            boolean isEmpty() {
                return directories.isEmpty() && filesData.isEmpty();
            }
        }

        PathTrieNode root = new PathTrieNode("");

        String[] splitPath(String path) {
            return path.split(pathSeparator);
        }

        String appendPath(String first, String second) {
            return first + pathSeparator + second;
        }

        PathTrieNode getLastDirectory0(String[] path, int s, int e) {
            PathTrieNode current = root;
            while (s <= e && current != null) {
                current = current.getDirectory(path[s++]);
            }
            return current;
        }

        PathTrieNode makeDirectories0(String[] path, int s, int e) {
            PathTrieNode current = root;
            while (s <= e) {
                current = current.putDirectory(path[s++]);
            }
            return current;
        }

        FileData deleteRecursively(String[] paths, int i, PathTrieNode current, boolean file) {
            if (i == paths.length - 1) {
                if (file) {
                    return current.deleteFileData(paths[i]);
                } else {
                    current.deleteDirectory(paths[i]);
                }
                return null;
            }
            PathTrieNode next = current.getDirectory(paths[i]);
            if (next == null) {
                return null;
            }
            FileData fileData = deleteRecursively(paths, i + 1, next, file);
            if (next.isEmpty()) {
                current.deleteDirectory(paths[i]);
            }
            return fileData;
        }

        void putFileData(String path, FileData fileData) {
            String[] subPaths = splitPath(path);
            int n = subPaths.length;
            PathTrieNode lastDirectory = makeDirectories0(subPaths, 0, n - 2);
            lastDirectory.putFileData(subPaths[n - 1], fileData);
        }

        FileData getFileData(String path) {
            String[] paths = splitPath(path);
            int n = paths.length - 1;
            PathTrieNode lastDirectory = getLastDirectory0(paths, 0, n - 1);
            if (lastDirectory == null) {
                return null;
            }
            return lastDirectory.getFileData(paths[n]);
        }

        FileData deleteFile(String path) {
            String[] paths = splitPath(path);
            return deleteRecursively(paths, 0, root, true);
        }

        boolean fileExists(String path) {
            String[] paths = splitPath(path);
            int n = paths.length;
            PathTrieNode lastDirectory = getLastDirectory0(paths, 0, n - 2);
            return lastDirectory != null && lastDirectory.fileDataExists(paths[n - 1]);
        }

        void traverseFilesRecursively0(String[] paths, int i, String originalPath, PathTrieNode current, Set<String> files) {
            if (i == paths.length - 1) {
                current.getFilesList().forEach(x -> files.add(appendPath(originalPath, x)));
                return;
            }
            PathTrieNode next = current.getDirectory(paths[i]);
            if (next == null) {
                return;
            }
            traverseFilesRecursively0(paths, i + 1, originalPath, next, files);
        }

        Set<String> getFilesList(String path) {
            String[] paths = splitPath(path);
            Set<String> files = new LinkedHashSet<>();
            traverseFilesRecursively0(paths, 0, path, root, files);
            return files;
        }

        Set<String> directoryList() {
        }

        boolean directoryExists(String path) {
            String[] paths = splitPath(path);
            int n = paths.length - 1;
            PathTrieNode last = getLastDirectory0(paths, 0, n - 1);
            return last != null && last.isDirectory(paths[n]);
        }
    }

    static class FileCopyOption {
        private static final List<String> options = Arrays.stream(Type.values()).filter(x -> x != Type.ASK).map(Enum::toString).toList();
        private Type type;

        FileCopyOption() {
            this.type = Type.ASK;
        }

        Type getType() {
            Type current = type;
            switch (current) {
                case REPLACE, RENAME, SKIP -> resetType();
            }
            return current;
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