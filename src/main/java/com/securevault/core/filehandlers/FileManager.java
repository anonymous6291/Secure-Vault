package com.securevault.core.filehandlers;

import com.securevault.core.Logger;
import com.securevault.core.Writable;
import com.securevault.core.configurations.CipherManager;
import com.securevault.core.configurations.ConfigurationDefaults;
import com.securevault.core.configurations.SecureRandomValueGenerator;
import com.securevault.core.filehandlers.listeners.FileManagerListener;
import com.securevault.core.filehandlers.listeners.FileTransferManagerListener;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Semaphore;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public class FileManager implements FileTransferManagerListener, Writable {
    private static final String FORBIDDEN_FILE_NAME = "(?i:(CON|PRN|AUX|NUL|((COM|LPT)\\d*)))(\\..*)?";
    private static final String ALLOWED_FILE_NAME = "[a-zA-Z0-9\\s._\\-$#@]+";
    private static final String FILE_SEPARATOR = File.separator;
    private static final String QUOTED_FILE_SEPARATOR = Pattern.quote(FILE_SEPARATOR);
    private static final String ROOT_DIRECTORY = "root";
    private static final String FILE_STORAGE_FOLDER_NAME = "";// "files";
    private static final String FILE_DATA_NAME = "files.data";
    private static final String FILE_DATA_END_MARKER = "#############################END#############################";
    private final Semaphore lock = new Semaphore(1, true);
    private final Path fileDataPath;
    private final Path fileStoragePath;
    private final Path actualFileStoragePath;
    private final char[] vaultKey;
    private final byte[] iv;
    private final byte[] salt;
    private final PathTrie allFiles = new PathTrie();
    private final FileTransferManager fileTransferManager;
    private final FileManagerListener fileManagerListener;
    private final Logger logger;
    private volatile char[] nextMaskedFileName;

    public FileManager(Path basePath, char[] vaultKey, boolean create, FileManagerListener fileManagerListener, Logger logger) throws Exception {
        this.logger = logger;
        fileDataPath = Path.of(basePath.toString(), FILE_DATA_NAME);
        fileStoragePath = Path.of(basePath.toString(), FILE_STORAGE_FOLDER_NAME);
        actualFileStoragePath = Path.of(fileStoragePath.toString(), getInternalPath(Path.of("")).toString());
        this.vaultKey = vaultKey;
        this.fileManagerListener = fileManagerListener;
        String lastFileName = "0";
        int filesCount = 0;
        try {
            Set<String> maskedFileEntries = new HashSet<>();
            if (!create && Files.isRegularFile(fileDataPath)) {
                BufferedInputStream bufferedInputStream = new BufferedInputStream(Files.newInputStream(fileDataPath));
                iv = bufferedInputStream.readNBytes(ConfigurationDefaults.IV_LENGTH);
                salt = bufferedInputStream.readNBytes(ConfigurationDefaults.SALT_LENGTH);
                Cipher cipher = CipherManager.getCipher(vaultKey, iv, salt, Cipher.DECRYPT_MODE);
                CipherInputStream cipherInputStream = new CipherInputStream(bufferedInputStream, cipher);
                String fileData = new String(cipherInputStream.readAllBytes());
                cipherInputStream.close();
                String[] data = fileData.split("\n");
                String oldFileSeparator = data[0];
                int n = data.length;
                for (int i = 3; i < n; i += 3) {
                    String path = changeFileSeparator(data[i - 2], oldFileSeparator);
                    String maskedName = data[i - 1];
                    String originalName = data[i];
                    if (path.equals(FILE_DATA_END_MARKER) || maskedName.equals(FILE_DATA_END_MARKER) || originalName.equals(FILE_DATA_END_MARKER)) {
                        break;
                    }
                    Path maskedFilePath = Path.of(fileStoragePath.toString(), path, maskedName);
                    File file = maskedFilePath.toFile();
                    if (!file.exists()) {
                        logger.logError("File [" + path + "] has entry but doesn't exist, skipping it.");
                    } else {
                        if (smaller(lastFileName, maskedName)) {
                            lastFileName = maskedName;
                        }
                        maskedFileEntries.add(maskedFilePath.toString());
                        FileData currentFileData = new FileData(originalName, maskedName, file.length(), path);
                        allFiles.putFileData(currentFileData);
                        filesCount++;
                    }
                }
                logger.logInfo("Total [" + filesCount + "] file entries scanned.");
            } else {
                iv = SecureRandomValueGenerator.generateSecureBytes(ConfigurationDefaults.IV_LENGTH);
                salt = SecureRandomValueGenerator.generateSecureBytes(ConfigurationDefaults.SALT_LENGTH);
                Files.createFile(fileDataPath);
                Files.createDirectories(actualFileStoragePath);
            }
            removeFilesWithNoEntry(actualFileStoragePath, maskedFileEntries, false);
        } catch (Exception e) {
            throw new Exception("Exception occurred while starting the FileManager : " + e.getMessage());
        }
        this.nextMaskedFileName = lastFileName.toCharArray();
        fileTransferManager = new FileTransferManager(vaultKey, this, logger);
        fileTransferManager.start();
        fileManagerListener.setFileTransferMonitor(fileTransferManager);
        if (filesCount != 0) {
            incrementNextFileName();
        }
    }

    private void removeFilesWithNoEntry(Path current, Set<String> maskedFileEntries, boolean canDeleteDirectoryIfEmpty) {
        if (Files.isDirectory(current)) {
            try (Stream<Path> stream = Files.list(current)) {
                stream.forEach(subPath -> removeFilesWithNoEntry(subPath, maskedFileEntries, true));
            } catch (Exception _) {
            }
            if (!canDeleteDirectoryIfEmpty) {
                return;
            }
        } else if (Files.isRegularFile(current) && maskedFileEntries.contains(current.toString())) {
            return;
        }
        try {
            Files.delete(current);
        } catch (Exception _) {
        }
    }

    private String changeFileSeparator(String path, String oldFileSeparator) {
        if (oldFileSeparator.equals(FILE_SEPARATOR)) {
            return path;
        }
        return path.replace(oldFileSeparator, FILE_SEPARATOR);
    }

    private boolean smaller(String first, String second) {
        int n1 = first.length();
        int n2 = second.length();
        return n1 < n2 || (n1 == n2 && first.compareTo(second) < 0);
    }

    private boolean isForbiddenFileName(String name) {
        return name.matches(FORBIDDEN_FILE_NAME);
    }

    private boolean isFileNameAllowed(String name) {
        return !isForbiddenFileName(name) && name.matches(ALLOWED_FILE_NAME);
    }

    private Path removeLeadingDotsFromPath(Path path) {
        path = path.normalize();
        Path resultPath = Path.of("");
        for (Path subPath : path) {
            if (!subPath.toString().equals("..")) {
                resultPath = resultPath.resolve(subPath);
            }
        }
        return resultPath;
    }

    private Path getInternalPath(Path path) {
        path = removeLeadingDotsFromPath(path.normalize());
        return Path.of(ROOT_DIRECTORY, path.toString());
    }

    private boolean validPath(Path path) {
        for (Path subPath : path) {
            if (!isFileNameAllowed(subPath.toString())) {
                return false;
            }
        }
        return true;
    }

    private Path validateAndGetInternalPath(Path path) throws InvalidPathException {
        path = getInternalPath(path);
        if (!validPath(path)) {
            throw new InvalidPathException(path.toString(), "Path must not contain forbidden file names and characters except [a-z], [A-Z], [0-9], [ ], [.], [_], [-], [$], [#], [@] .");
        }
        return path;
    }

    private String sanitizeFileName(String fileName) {
        if (isForbiddenFileName(fileName)) {
            return "_" + fileName + "_";
        }
        if (fileName.matches(ALLOWED_FILE_NAME)) {
            return fileName;
        }
        int n = fileName.length();
        char[] sanitizedFileName = fileName.toCharArray();
        for (int j = 0; j < n; j++) {
            if (!String.valueOf(fileName.charAt(j)).matches(ALLOWED_FILE_NAME)) {
                sanitizedFileName[j] = '_';
            }
        }
        return new String(sanitizedFileName);
    }

    private Path sanitizePath(Path originalPath) {
        if (validPath(originalPath)) {
            return originalPath;
        }
        String[] paths = originalPath.toString().split(QUOTED_FILE_SEPARATOR);
        int n = paths.length;
        for (int i = 0; i < n; i++) {
            paths[i] = sanitizeFileName(paths[i]);
        }
        Path sanitizedPath = Path.of(paths[0]);
        for (int i = 1; i < n; i++) {
            sanitizedPath = sanitizedPath.resolve(paths[i]);
        }
        return sanitizedPath;
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
        Arrays.fill(nextFileName, '0');
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

    private boolean fileOrDirectoryExists(Path filePath, FileTransferMode mode) {
        if (mode == FileTransferMode.ENCRYPT) {
            return allFiles.fileOrDirectoryExists(filePath.toString());
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
        while (fileOrDirectoryExists(newFilePath = Path.of(parent.toString(), firstName + start + extension), mode)) {
            start++;
        }
        return newFilePath;
    }

    private void addFileForTransfer(Path from, Path to, FileTransferMode fileTransferMode, FileCopyOption fileCopyOption) {
        if ((fileTransferMode == FileTransferMode.ENCRYPT && !Files.isRegularFile(from)) || (fileTransferMode == FileTransferMode.DECRYPT && !allFiles.fileExists(from.toString()))) {
            return;
        }
        Map<String, String> notes = Map.of();
        Path toFilePath;
        Path targetFilePath;
        if (fileTransferMode == FileTransferMode.ENCRYPT) {
            targetFilePath = sanitizePath(Path.of(to.toString(), from.getFileName().toString()));
        } else {
            targetFilePath = Path.of(to.toString(), from.getFileName().toString());
        }
        if ((fileTransferMode == FileTransferMode.ENCRYPT && allFiles.fileOrDirectoryExists(targetFilePath.toString())) || (fileTransferMode == FileTransferMode.DECRYPT && Files.exists(targetFilePath))) {
            FileCopyOption.Type fileCopyType = fileCopyOption.getType();
            if (fileCopyType == FileCopyOption.Type.RENAME_ALL || fileCopyType == FileCopyOption.Type.RENAME) {
                String renamedName = sanitizeFileName(renameFile(targetFilePath, fileTransferMode).getFileName().toString());
                if (fileTransferMode == FileTransferMode.ENCRYPT) {
                    notes = Map.of("renamed", renamedName);
                    toFilePath = Path.of(fileStoragePath.toString(), targetFilePath.getParent().toString(), getNewMaskedFileName());
                } else {
                    toFilePath = Path.of(to.toString(), renamedName);
                }
            } else if (fileCopyType == FileCopyOption.Type.SKIP_ALL || fileCopyType == FileCopyOption.Type.SKIP) {
                return;
            } else if (fileCopyType == FileCopyOption.Type.ASK) {
                List<String> options;
                String message;
                if ((fileTransferMode == FileTransferMode.ENCRYPT && allFiles.directoryExists(targetFilePath.toString())) || (fileTransferMode == FileTransferMode.DECRYPT && Files.isDirectory(targetFilePath))) {
                    options = FileCopyOption.optionsExceptReplace;
                    message = "[" + targetFilePath + "] is a directory.";
                } else {
                    options = FileCopyOption.options;
                    message = "File [" + targetFilePath + "] already exists.";
                }
                String response = fileManagerListener.askForResponse(message, options);
                fileCopyOption.setType(Enum.valueOf(FileCopyOption.Type.class, response));
                addFileForTransfer(from, to, fileTransferMode, fileCopyOption);
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
                toFilePath = Path.of(fileStoragePath.toString(), sanitizePath(to).toString(), getNewMaskedFileName());
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
        FileTransferData fileTransferData = new FileTransferData(from.normalize(), toFilePath.normalize(), fileTransferMode, notes);
        fileTransferManager.transferFile(fileTransferData);
    }

    private void recursivelyAddFiles(Path from, Path to, FileCopyOption fileCopyOption) {
        if (Files.isDirectory(from)) {
            Path toSubDirectory = Path.of(to.toString(), from.getFileName().toString());
            try (Stream<Path> pathStream = Files.list(from)) {
                pathStream.forEach(fromSubFile -> recursivelyAddFiles(fromSubFile, toSubDirectory, fileCopyOption));
            } catch (Exception e) {
                logger.logError("Exception occurred while traversing files : " + e.getMessage());
            }
        } else if (Files.isRegularFile(from)) {
            addFileForTransfer(from, to, FileTransferMode.ENCRYPT, fileCopyOption);
        }
    }

    private void addFile0(Path from, Path to) throws FileNotFoundException {
        from = from.normalize();
        if (Files.isDirectory(from)) {
            addDirectory0(from, to);
            return;
        }
        if (!Files.isRegularFile(from)) {
            throw new FileNotFoundException("Regular file [" + from + "] doesn't exist.");
        }
        to = validateAndGetInternalPath(to);
        if (!lock()) {
            return;
        }
        try {
            addFileForTransfer(from, to, FileTransferMode.ENCRYPT, new FileCopyOption());
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while adding the file : " + e.getMessage());
        } finally {
            unlock();
        }
    }

    private void addDirectory0(Path from, Path to) throws FileNotFoundException {
        from = from.normalize();
        if (Files.isRegularFile(from)) {
            addFile0(from, to);
            return;
        }
        to = validateAndGetInternalPath(to);
        if (!lock()) {
            return;
        }
        try {
            recursivelyAddFiles(from, to, new FileCopyOption());
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while adding the directory : " + e.getMessage());
        } finally {
            unlock();
        }
    }

    public void addFile(Path from, Path to) throws FileNotFoundException {
        addFile0(from, to);
    }

    private void getFile0(Path from, Path to) {
        Path internalFrom = validateAndGetInternalPath(from);
        to = to.normalize();
        if (allFiles.directoryExists(internalFrom.toString())) {
            getDirectory0(from, to);
            return;
        }
        if (!lock()) {
            return;
        }
        try {
            addFileForTransfer(internalFrom, to, FileTransferMode.DECRYPT, new FileCopyOption());
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while getting the file : " + e.getMessage());
        } finally {
            unlock();
        }
    }

    private void getDirectory0(Path from, Path to) {
        Path normalizedFrom = validateAndGetInternalPath(from);
        if (allFiles.fileExists(normalizedFrom.toString())) {
            getFile0(from, to);
            return;
        }
        Path parent = normalizedFrom.getParent();
        if (parent == null) {
            parent = Path.of("");
        }
        Path normalizedFromParent = parent;
        String normalizedTo = to.normalize().toString();
        if (!lock()) {
            return;
        }
        try {
            FileCopyOption fileCopyOption = new FileCopyOption();
            allFiles.getAllFilesDataList(normalizedFrom.toString()).forEach(fileData -> addFileForTransfer(fileData.getOriginalFilePath(), Path.of(normalizedTo, normalizedFromParent.relativize(fileData.getFilePath()).toString()), FileTransferMode.DECRYPT, fileCopyOption));
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while getting the directory : " + e.getMessage());
        } finally {
            unlock();
        }
    }

    public void getFile(Path from, Path to) {
        getFile0(from, to);
    }

    public boolean changeFileName(Path path, String newOriginalName) {
        path = validateAndGetInternalPath(path);
        if (!lock()) {
            return false;
        }
        try {
            FileData fileData = allFiles.deleteFile(path.toString());
            if (fileData == null) {
                return false;
            }
            fileData.setOriginalName(newOriginalName);
            allFiles.putFileData(fileData);
            return true;
        } finally {
            unlock();
        }
    }

    private void deleteFileData(FileData fileData) {
        try {
            Path maskedFile = Path.of(fileStoragePath.toString(), fileData.getMaskedFilePath().toString());
            logger.logWarn("Deleting file [" + fileData.getOriginalFilePath() + "] .");
            if (Files.exists(maskedFile)) {
                Files.delete(maskedFile);
            }
        } catch (Exception e) {
            logger.logError("Failed to delete file [" + fileData.getOriginalFilePath() + "] : " + e.getMessage());
        }
    }

    private void deleteFile0(Path path) {
        Path internalPath = validateAndGetInternalPath(path);
        if (allFiles.directoryExists(internalPath.toString())) {
            deleteDirectory0(path);
            return;
        }
        if (!lock()) {
            return;
        }
        try {
            FileData fileData = allFiles.deleteFile(internalPath.toString());
            if (fileData != null) {
                deleteFileData(fileData);
            }
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while deleting the file [" + internalPath + "] : " + e.getMessage());
        } finally {
            unlock();
        }
    }

    private void deleteEmptyDirectories(Path path) {
        if (!Files.isDirectory(path)) {
            return;
        }
        try (Stream<Path> subPaths = Files.list(path)) {
            subPaths.forEach(this::deleteEmptyDirectories);
            if (!path.equals(actualFileStoragePath)) {
                Files.delete(path);
            }
        } catch (Exception _) {
        }
    }

    private void deleteDirectory0(Path path) {
        Path internalPath = validateAndGetInternalPath(path);
        if (allFiles.fileExists(internalPath.toString())) {
            deleteFile0(path);
            return;
        }
        if (!lock()) {
            return;
        }
        try {
            allFiles.deleteDirectory(internalPath.toString()).forEach(this::deleteFileData);
            deleteEmptyDirectories(Path.of(fileStoragePath.toString(), internalPath.toString()));
        } finally {
            unlock();
        }
    }

    public void deleteFile(Path path) {
        deleteFile0(path);
    }

    public List<String> getFilesList(Path path) {
        path = validateAndGetInternalPath(path);
        List<String> fileDataList = new LinkedList<>();
        if (!lock()) {
            return null;
        }
        try {
            allFiles.getAllFilesDataList(path.toString()).forEach(fileData -> fileDataList.add(fileData.getOriginalFilePath().toString()));
        } finally {
            unlock();
        }
        fileDataList.sort(String::compareTo);
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
            cipherOutputStream.write((FILE_SEPARATOR + "\n").getBytes());
            for (FileData data : allFiles.getAllFilesDataList(getInternalPath(Path.of("")).toString())) {
                String value = data.getFilePath() + "\n" + data.getMaskedName() + "\n" + data.getOriginalName() + "\n";
                cipherOutputStream.write(value.getBytes());
            }
            cipherOutputStream.write(FILE_DATA_END_MARKER.getBytes());
            cipherOutputStream.close();
        } catch (Exception e) {
            throw new Exception("Exception occurred while writing data of FileManager : " + e.getMessage());
        } finally {
            unlock();
        }
    }

    public void close() throws Exception {
        fileTransferManager.shutdown();
        writeData();
    }

    @Override
    public void fileTransferCompleted(FileTransferData fileTransferData) {
        Path from = fileTransferData.from();
        Path to = fileTransferData.to();
        if (fileTransferData.mode() == FileTransferMode.ENCRYPT) {
            File toFile = to.toFile();
            String fromFileName;
            if (fileTransferData.notes().containsKey("renamed")) {
                fromFileName = fileTransferData.notes().get("renamed");
            } else {
                fromFileName = sanitizeFileName(from.getFileName().toString());
            }
            Path filePath = fileStoragePath.relativize(to.getParent());
            FileData fileData = new FileData(fromFileName, toFile.getName(), toFile.length(), filePath.toString());
            allFiles.putFileData(fileData);
            fileManagerListener.fileAdded(fileData.getOriginalFilePath().toString());
            logger.logInfo("File [" + from + "] added.");
        } else {
            Path vaultFilePath = fileStoragePath.relativize(from);
            logger.logInfo("File [" + Path.of(vaultFilePath.getParent().toString(), to.getFileName().toString()) + "] retrieved.");
        }
    }

    @Override
    public void fileTransferFailed(FileTransferData fileTransferData) {
        if (fileTransferData.mode() == FileTransferMode.ENCRYPT) {
            fileManagerListener.fileTransferFailed("Failed to add file [" + fileTransferData.from() + "] to the vault.");
        } else {
            fileManagerListener.fileTransferFailed("Failed to copy file to [" + fileTransferData.to() + "] from the vault.");
        }
    }

    static class PathTrie {
        static final char SEPARATOR_CHAR = FILE_SEPARATOR.charAt(0);
        PathTrieNode root = new PathTrieNode("");

        String[] splitPath(String path) {
            int n = path.length();
            for (int i = 0; i < n; i++) {
                if (path.charAt(i) != SEPARATOR_CHAR) {
                    return path.substring(i).split(QUOTED_FILE_SEPARATOR);
                }
            }
            return new String[]{};
        }

        String appendPath(String first, String second) {
            return Path.of(first, second).toString();
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

        void putFileData(FileData fileData) {
            String[] subPaths = splitPath(fileData.getOriginalFilePath().toString());
            int n = subPaths.length - 1;
            PathTrieNode lastDirectory = makeDirectories0(subPaths, 0, n - 1);
            lastDirectory.putFileData(subPaths[n], fileData);
        }

        FileData getFileData(String path) {
            String[] paths = splitPath(path);
            int n = paths.length - 1;
            if (n < 0) {
                return null;
            }
            PathTrieNode lastDirectory = getLastDirectory0(paths, 0, n - 1);
            if (lastDirectory == null) {
                return null;
            }
            return lastDirectory.getFileData(paths[n]);
        }

        FileData deleteFile(String path) {
            String[] paths = splitPath(path);
            int n = paths.length - 1;
            if (n < 0) {
                return null;
            }
            PathTrieNode last = getLastDirectory0(paths, 0, n - 1);
            if (last == null) {
                return null;
            }
            return last.deleteFileData(paths[n]);
        }

        List<FileData> deleteDirectory(String path) {
            String[] paths = splitPath(path);
            List<FileData> allFilesData = new LinkedList<>();
            PathTrieNode last = getLastDirectory0(paths, 0, paths.length - 1);
            if (last != null) {
                last.deleteSelf(allFilesData);
            }
            return allFilesData;
        }

        boolean fileOrDirectoryExists(String path) {
            String[] paths = splitPath(path);
            int n = paths.length - 1;
            if (n < 0) {
                return false;
            }
            PathTrieNode lastDirectory = getLastDirectory0(paths, 0, n - 1);
            return lastDirectory != null && (lastDirectory.isDirectory(paths[n]) || lastDirectory.fileDataExists(paths[n]));
        }

        List<FileData> getAllFilesDataList(String path) {
            String[] paths = splitPath(path);
            List<FileData> allFilesData = new LinkedList<>();
            PathTrieNode last = getLastDirectory0(paths, 0, paths.length - 1);
            if (last != null) {
                last.getFilesListRecursively(allFilesData);
            }
            return allFilesData;
        }

        boolean fileExists(String path) {
            String[] paths = splitPath(path);
            int n = paths.length - 1;
            if (n < 0) {
                return true;
            }
            PathTrieNode last = getLastDirectory0(paths, 0, n - 1);
            return last != null && last.fileDataExists(paths[n]);
        }

        boolean directoryExists(String path) {
            String[] paths = splitPath(path);
            int n = paths.length - 1;
            if (n < 0) {
                return true;
            }
            PathTrieNode last = getLastDirectory0(paths, 0, n - 1);
            return last != null && last.isDirectory(paths[n]);
        }

        static class PathTrieNode {
            String name;
            ConcurrentMap<String, PathTrieNode> directories = new ConcurrentHashMap<>();
            ConcurrentMap<String, FileData> filesData = new ConcurrentHashMap<>();

            PathTrieNode(String name) {
                this.name = name;
            }

            void renameSelf(String newName) {
                name = newName;
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

            PathTrieNode putDirectory(String name) {
                return directories.computeIfAbsent(name, PathTrieNode::new);
            }

            PathTrieNode getDirectory(String name) {
                return directories.get(name);
            }

            boolean isDirectory(String name) {
                return directories.containsKey(name);
            }

            void getFilesListRecursively(List<FileData> fileDataList) {
                fileDataList.addAll(filesData.values());
                for (PathTrieNode subPaths : directories.values()) {
                    subPaths.getFilesListRecursively(fileDataList);
                }
            }

            void deleteSelf(List<FileData> deletedFileData) {
                getFilesListRecursively(deletedFileData);
                directories.clear();
                filesData.clear();
            }

            void deleteDirectory(String name) {
                directories.remove(name);
            }

            boolean isEmpty() {
                return directories.isEmpty() && filesData.isEmpty();
            }
        }
    }

    static class FileCopyOption {
        private static final List<String> options = Arrays.stream(Type.values()).filter(x -> x != Type.ASK).map(Enum::toString).toList();
        private static final List<String> optionsExceptReplace = options.stream().filter(x -> !(x.equals(Type.REPLACE.toString()) || x.equals(Type.REPLACE_ALL.toString()))).toList();
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
            ASK, RENAME, RENAME_ALL, REPLACE, REPLACE_ALL, SKIP, SKIP_ALL
        }
    }
}