package com.securevault.core.filehandlers;

import com.securevault.core.Logger;
import com.securevault.core.configurations.CipherManager;
import com.securevault.core.configurations.ConfigurationDefaults;
import com.securevault.core.configurations.SecureRandomValueGenerator;
import com.securevault.core.filehandlers.listeners.FileTransferManagerListener;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class FileTransferManager implements FileTransferMonitor {
    private static final int MAX_PARALLEL_FILE_TRANSFERS = Runtime.getRuntime().availableProcessors() - 1;
    private final Semaphore fileTransferLock = new Semaphore(MAX_PARALLEL_FILE_TRANSFERS);
    private final Semaphore universalLock = new Semaphore(1, true);
    private final ExecutorService executorService = Executors.newFixedThreadPool(MAX_PARALLEL_FILE_TRANSFERS);
    private final Duration DELAY = Duration.ofMillis(300);
    private final ConcurrentLinkedQueue<String> failedFiles = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<FileTransferHandler> pendingFiles = new ConcurrentLinkedQueue<>();
    private final AtomicInteger numberOfPendingFiles = new AtomicInteger(0);
    private final AtomicInteger numberOfRunningFileTransfers = new AtomicInteger(0);
    private final AtomicLong dataToBeTransferred = new AtomicLong(0);
    private final AtomicLong dataTransferred = new AtomicLong(0);
    private final char[] key;
    private final FileTransferManagerListener fileTransferManagerListener;
    private final Logger logger;
    private final AtomicInteger nextFileHandlerId = new AtomicInteger(1);
    private volatile boolean shutdown;
    private volatile boolean abortAllFileTransfers;

    FileTransferManager(char[] key, FileTransferManagerListener fileTransferManagerListener, Logger logger) {
        this.key = key;
        this.fileTransferManagerListener = fileTransferManagerListener;
        this.logger = logger;
        shutdown = false;
    }


    public void start() {
        if (isShutdown()) {
            return;
        }
        Thread.startVirtualThread(this::start0);
    }

    private void start0() {
        if (isShutdown()) {
            return;
        }
        while (!pendingFiles.isEmpty() || !shutdown) {
            if (!pendingFiles.isEmpty()) {
                try {
                    fileTransferLock.acquire();
                    if (abortAllFileTransfers) {
                        acquireUniversalLock();
                        fileTransferLock.release();
                        waitForRunningTransferHandlersToComplete();
                        while (!pendingFiles.isEmpty()) {
                            FileTransferHandler fileTransferHandler = pendingFiles.poll();
                            numberOfPendingFiles.decrementAndGet();
                            dataToBeTransferred.addAndGet(-fileTransferHandler.getDataToBeTransferred());
                        }
                        abortAllFileTransfers = false;
                        releaseUniversalLock();
                    } else {
                        FileTransferHandler fileTransferHandler = pendingFiles.poll();
                        if (fileTransferHandler == null) {
                            fileTransferLock.release();
                        } else {
                            numberOfRunningFileTransfers.incrementAndGet();
                            Thread.startVirtualThread(() -> startSingleFileTransfer(fileTransferHandler));
                        }
                    }
                } catch (Exception _) {
                }
            } else {
                try {
                    Thread.sleep(DELAY);
                } catch (Exception _) {
                }
            }
        }
    }

    private void startSingleFileTransfer(FileTransferHandler fileTransferHandler) {
        if (!abortAllFileTransfers) {
            Future<FileTransferStatus> result = executorService.submit(fileTransferHandler);
            if (fileTransferHandler.getMode() == FileTransferMode.ENCRYPT) {
                logger.logInfo("Adding file [" + fileTransferHandler.getFromFileName() + "].");
            } else {
                logger.logInfo("Retrieving file [" + fileTransferHandler.getToFileName() + "].");
            }
            long last = 0;
            while (!result.isDone()) {
                if (abortAllFileTransfers) {
                    fileTransferHandler.abortTransfer();
                    break;
                }
                long current = fileTransferHandler.getDataTransferred();
                dataTransferred.addAndGet(current - last);
                last = current;
                try {
                    Thread.sleep(DELAY);
                } catch (Exception _) {
                }
            }
            dataTransferred.addAndGet(fileTransferHandler.getDataToBeTransferred() - last);
            try {
                FileTransferStatus fileTransferStatus = result.get();
                if (fileTransferStatus == FileTransferStatus.FAILED) {
                    logger.logError("[" + fileTransferHandler.getFromFileName() + "] failed to transfer.");
                    failedFiles.offer("[" + fileTransferHandler.getFromFileName() + "] failed to transfer.");
                    fileTransferManagerListener.fileTransferFailed(fileTransferHandler.getFileTransferData());
                } else if (fileTransferStatus == FileTransferStatus.COMPLETED) {
                    fileTransferManagerListener.fileTransferCompleted(fileTransferHandler.getFileTransferData());
                }
            } catch (Exception _) {
                logger.logError("[" + fileTransferHandler.getFromFileName() + "] failed to transfer.");
                failedFiles.offer("[" + fileTransferHandler.getFromFileName() + "] failed to transfer.");
                fileTransferManagerListener.fileTransferFailed(fileTransferHandler.getFileTransferData());
            }
        }
        numberOfPendingFiles.decrementAndGet();
        numberOfRunningFileTransfers.decrementAndGet();
        fileTransferLock.release();
    }

    private boolean acquireUniversalLock() {
        try {
            universalLock.acquire();
            return true;
        } catch (Exception _) {
            return false;
        }
    }

    private void releaseUniversalLock() {
        universalLock.release();
    }

    private void transferFile0(FileTransferData fileTransferData) {
        FileTransferHandler fileTransferHandler = new FileTransferHandler(fileTransferData, key, nextFileHandlerId.getAndIncrement());
        try {
            Path to = fileTransferData.to();
            Files.createDirectories(to.getParent());
            pendingFiles.offer(fileTransferHandler);
            dataToBeTransferred.addAndGet(fileTransferHandler.getDataToBeTransferred());
            numberOfPendingFiles.incrementAndGet();
        } catch (Exception e) {
            logger.logError("[" + fileTransferHandler.getFromFilePath() + "] failed to transfer : " + e.getMessage());
            failedFiles.offer("[" + fileTransferHandler.getFromFilePath() + "] failed to transfer : " + e.getMessage());
        }
    }

    public void transferFile(FileTransferData fileTransferData) {
        if (isShutdown()) {
            throw new UnsupportedOperationException("FileTransferManager is shutdown, cannot transfer files.");
        }
        if (!acquireUniversalLock()) {
            return;
        }
        try {
            transferFile0(fileTransferData);
        } finally {
            releaseUniversalLock();
        }
    }

    public void transferFiles(List<FileTransferData> fileTransferDataList) {
        if (isShutdown()) {
            throw new UnsupportedOperationException("FileTransferManager is shutdown.");
        }
        if (!acquireUniversalLock()) {
            return;
        }
        try {
            fileTransferDataList.forEach(this::transferFile0);
        } finally {
            releaseUniversalLock();
        }
    }

    public void abortAllFileTransfers() {
        abortAllFileTransfers = true;
    }

    private void waitForRunningTransferHandlersToComplete() {
        while (numberOfRunningFileTransfers.get() != 0) {
            try {
                Thread.sleep(DELAY);
            } catch (Exception _) {
            }
        }
    }

    private void waitForAllTransfersToComplete() {
        while (numberOfPendingFiles.get() != 0) {
            try {
                Thread.sleep(DELAY);
            } catch (Exception _) {
            }
        }
    }

    public void shutdown() {
        shutdown = true;
        waitForAllTransfersToComplete();
        executorService.shutdown();
    }

    public boolean isShutdown() {
        return shutdown;
    }

    @Override
    public int getNumberOfPendingFileTransfers() {
        return numberOfPendingFiles.get();
    }

    @Override
    public int getNumberOfFailedFileTransfers() {
        return failedFiles.size();
    }

    @Override
    public List<String> getFailedFileTransfersList() {
        List<String> result = failedFiles.stream().toList();
        failedFiles.clear();
        return result;
    }

    @Override
    public double getFileTransferProgress() {
        long data = dataToBeTransferred.get();
        if (data == 0) {
            return 100;
        }
        return ((int) ((dataTransferred.get() * 100_00.0) / data)) / 100.0;
    }

    enum FileTransferStatus {
        FAILED, PENDING, COMPLETED, ABORTED
    }

    static class FileTransferHandler implements Callable<FileTransferStatus> {
        public static final String FILE_PART_EXTENSION = ".part";
        private static final int CHUNK_SIZE = 1024 * 1024; // 1 MB
        private static final long MAX_FILE_PART_SIZE = 1024 * 1024 * 256; // 256 MB
        private final FileTransferData fileTransferData;
        private final Path from;
        private final Path to;
        private final char[] key;
        private final FileTransferMode mode;
        private final int id;
        private final long dataToBeTransferred;
        private final AtomicLong dataTransferred;
        private volatile FileTransferStatus fileTransferStatus;
        private volatile boolean abortTransfer;

        FileTransferHandler(FileTransferData fileTransferData, char[] key, int id) {
            this.fileTransferData = fileTransferData;
            this.from = fileTransferData.from();
            this.to = fileTransferData.to();
            this.key = key;
            this.mode = fileTransferData.mode();
            this.id = id;
            if (mode == FileTransferMode.ENCRYPT) {
                dataToBeTransferred = from.toFile().length();
            } else {
                dataToBeTransferred = calculateEncryptedFileLength(from);
            }
            dataTransferred = new AtomicLong(0);
            fileTransferStatus = FileTransferStatus.PENDING;
            abortTransfer = false;
        }

        public static Path convertToPart(Path path, int partNumber) {
            return Path.of(path.toString() + FILE_PART_EXTENSION + partNumber);
        }

        private long calculateEncryptedFileLength(Path path) {
            long len = 0;
            int partNumber = 1;
            Path partPath;
            while (Files.exists(partPath = convertToPart(path, partNumber++))) {
                len += partPath.toFile().length();
            }
            return len;
        }

        @Override
        public FileTransferStatus call() {
            try {
                if (mode == FileTransferMode.ENCRYPT) {
                    return encryptFile();
                } else {
                    return decryptFile();
                }
            } catch (Exception e) {
                fileTransferStatus = FileTransferStatus.FAILED;
                return FileTransferStatus.FAILED;
            }
        }

        private FileTransferStatus encryptFile() throws Exception {
            try (InputStream inputStream = new BufferedInputStream(Files.newInputStream(from))) {
                long maxFilePartSize = MAX_FILE_PART_SIZE, bytesWritten = maxFilePartSize + 1;
                OutputStream outputStream = OutputStream.nullOutputStream();
                int ivLength = ConfigurationDefaults.IV_LENGTH, saltLength = ConfigurationDefaults.SALT_LENGTH;
                int len, partNumber = 1;
                byte[] chunk = new byte[CHUNK_SIZE];
                while (!(abortTransfer || (len = inputStream.read(chunk)) < 0)) {
                    if (bytesWritten + len > maxFilePartSize) {
                        outputStream.close();
                        byte[] iv = SecureRandomValueGenerator.generateSecureBytes(ivLength);
                        byte[] salt = SecureRandomValueGenerator.generateSecureBytes(saltLength);
                        Path partPath = convertToPart(to, partNumber++);
                        outputStream = new BufferedOutputStream(Files.newOutputStream(partPath));
                        outputStream.write(iv);
                        outputStream.write(salt);
                        outputStream = new CipherOutputStream(outputStream, CipherManager.getCipher(key, iv, salt, Cipher.ENCRYPT_MODE));
                        bytesWritten = 0;
                    }
                    bytesWritten += len;
                    outputStream.write(chunk, 0, len);
                    dataTransferred.addAndGet(len);
                }
                outputStream.close();
                if (abortTransfer) {
                    while (--partNumber > 0) {
                        Files.delete(convertToPart(to, partNumber));
                    }
                    return fileTransferStatus = FileTransferStatus.ABORTED;
                }
                return fileTransferStatus = FileTransferStatus.COMPLETED;
            }
        }

        private FileTransferStatus decryptFile() throws Exception {
            OutputStream outputStream = new BufferedOutputStream(Files.newOutputStream(to));
            int len, partNumber = 1;
            int ivLength = ConfigurationDefaults.IV_LENGTH, saltLength = ConfigurationDefaults.SALT_LENGTH;
            byte[] chunk = new byte[CHUNK_SIZE];
            InputStream inputStream = InputStream.nullInputStream();
            while (true) {
                if ((len = inputStream.read(chunk)) < 0) {
                    inputStream.close();
                    Path newPartPath = convertToPart(from, partNumber++);
                    if (!Files.exists(newPartPath)) {
                        break;
                    }
                    inputStream = new BufferedInputStream(Files.newInputStream(newPartPath));
                    byte[] iv = new byte[ivLength];
                    byte[] salt = new byte[saltLength];
                    if (inputStream.read(iv) != ivLength || inputStream.read(salt) != saltLength) {
                        outputStream.close();
                        inputStream.close();
                        Files.delete(to);
                        return fileTransferStatus = FileTransferStatus.FAILED;
                    }
                    inputStream = new CipherInputStream(inputStream, CipherManager.getCipher(key, iv, salt, Cipher.DECRYPT_MODE));
                } else {
                    outputStream.write(chunk, 0, len);
                    dataTransferred.addAndGet(len);
                }
            }
            inputStream.close();
            outputStream.close();
            if (abortTransfer) {
                Files.delete(to);
                return fileTransferStatus = FileTransferStatus.ABORTED;
            }
            return fileTransferStatus = FileTransferStatus.COMPLETED;
        }

        public int getId() {
            return id;
        }

        public FileTransferMode getMode() {
            return mode;
        }

        public FileTransferStatus getStatus() {
            return fileTransferStatus;
        }

        public FileTransferData getFileTransferData() {
            return fileTransferData;
        }

        public long getDataToBeTransferred() {
            return dataToBeTransferred;
        }

        public long getDataTransferred() {
            return dataTransferred.get();
        }

        public String getFromFileName() {
            return from.toFile().getName();
        }

        public Path getFromFilePath() {
            return from;
        }

        public String getToFileName() {
            return to.toFile().getName();
        }

        public void abortTransfer() {
            abortTransfer = true;
        }
    }
}

