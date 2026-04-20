package com.securevault.filehandlers;

import com.securevault.Logger;
import com.securevault.configurations.CipherManager;
import com.securevault.configurations.ConfigurationDefaults;
import com.securevault.configurations.RandomValueGenerator;
import com.securevault.filehandlers.listeners.FileTransferManagerListener;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class FileTransferManager implements FileTransferMonitor {
    private static final int MAX_PARALLEL_FILE_TRANSFERS = 5;
    private final Semaphore fileTransferLock = new Semaphore(MAX_PARALLEL_FILE_TRANSFERS);
    private final ExecutorService executorService = Executors.newFixedThreadPool(MAX_PARALLEL_FILE_TRANSFERS);
    private final Duration DELAY = Duration.ofMillis(300);
    private final ConcurrentLinkedQueue<String> failedFiles = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<FileTransferHandler> pendingFiles = new ConcurrentLinkedQueue<>();
    private final AtomicInteger numberOfPendingFiles = new AtomicInteger(0);
    private final AtomicLong dataToBeTransferred = new AtomicLong(0);
    private final AtomicLong dataTransferred = new AtomicLong(0);
    private final char[] key;
    private final FileTransferManagerListener fileTransferManagerListener;
    private int nextFileHandlerId;
    private volatile boolean shutdown;

    FileTransferManager(char[] key, FileTransferManagerListener fileTransferManagerListener) {
        this.key = key;
        this.fileTransferManagerListener = fileTransferManagerListener;
        shutdown = false;
    }

    private void start0() {
        if (isShutdown()) {
            return;
        }
        while (!pendingFiles.isEmpty() || !shutdown) {
            if (!pendingFiles.isEmpty()) {
                try {
                    fileTransferLock.acquire();
                    FileTransferHandler fileTransferHandler = pendingFiles.poll();
                    new Thread(() -> transferFile(fileTransferHandler)).start();
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

    private void transferFile(FileTransferHandler fileTransferHandler) {
        Future<FileTransferStatus> result = executorService.submit(fileTransferHandler);
        long last = 0;
        while (!result.isDone()) {
            long current = fileTransferHandler.getDataTransferred();
            dataTransferred.addAndGet(current - last);
            last = current;
            try {
                Thread.sleep(DELAY);
            } catch (Exception _) {
            }
        }
        dataTransferred.addAndGet(-last);
        dataToBeTransferred.addAndGet(-fileTransferHandler.getDataToBeTransferred());
        try {
            if (result.get() == FileTransferStatus.FAILED) {
                Logger.logError("[" + fileTransferHandler.getFromFileName() + "] failed to transfer.");
                failedFiles.offer("[" + fileTransferHandler.getFromFileName() + "] failed to transfer.");
                fileTransferManagerListener.fileTransferFailed(fileTransferHandler.getFileTransferData());
            } else {
                fileTransferManagerListener.fileTransferCompleted(fileTransferHandler.getFileTransferData());
            }
        } catch (Exception _) {
        }
        numberOfPendingFiles.decrementAndGet();
        fileTransferLock.release();
    }

    public void start() {
        if (isShutdown()) {
            return;
        }
        new Thread(this::start0).start();
    }

    public void transferFiles(List<FileTransferData> fileTransferDataList) {
        if (isShutdown()) {
            throw new IllegalStateException("FileTransferManager is shutdown.");
        }
        fileTransferDataList.forEach(fileTransferData -> {
            Path to = fileTransferData.to();
            FileTransferHandler fileTransferHandler = new FileTransferHandler(fileTransferData, key, nextFileHandlerId++);
            try {
                Files.createDirectories(to.getParent());
                pendingFiles.offer(fileTransferHandler);
                dataToBeTransferred.addAndGet(fileTransferHandler.getDataToBeTransferred());
                numberOfPendingFiles.incrementAndGet();
            } catch (Exception e) {
                failedFiles.offer("[" + fileTransferHandler.getFromFilePath() + "] failed to transfer.");
            }
        });
    }

    public void shutdown() {
        shutdown = true;
        while (numberOfPendingFiles.get() != 0) {
            try {
                Thread.sleep(DELAY);
            } catch (Exception _) {
            }
        }
        executorService.shutdown();
    }

    public boolean isShutdown() {
        return shutdown;
    }

    @Override
    public int getNumberOfFilesPending() {
        return numberOfPendingFiles.get();
    }

    @Override
    public int getNumberOfFilesFailed() {
        return failedFiles.size();
    }

    @Override
    public List<String> getFailedFilesList() {
        List<String> result = failedFiles.stream().toList();
        failedFiles.clear();
        return result;
    }

    @Override
    public double getProgress() {
        long data = dataToBeTransferred.get();
        if (data == 0) {
            return -1;
        }
        return (dataTransferred.get() * 100.0) / data;
    }

    public enum FileTransferStatus {
        FAILED, PENDING, COMPLETED
    }

    static class FileTransferHandler implements Callable<FileTransferStatus> {
        private static final int CHUNK_SIZE = 1024 * 1024;
        private final FileTransferData fileTransferData;
        private final Path from;
        private final Path to;
        private final char[] key;
        private final FileTransferMode mode;
        private final int id;
        private final long dataToBeTransferred;
        private final AtomicLong dataTransferred;
        private volatile FileTransferStatus fileTransferStatus;

        FileTransferHandler(FileTransferData fileTransferData, char[] key, int id) {
            this.fileTransferData = fileTransferData;
            this.from = fileTransferData.from();
            this.to = fileTransferData.to();
            this.key = key;
            this.mode = fileTransferData.mode();
            this.id = id;
            File fromFile = from.toFile();
            dataToBeTransferred = fromFile.length();
            dataTransferred = new AtomicLong(0);
            fileTransferStatus = FileTransferStatus.PENDING;
        }

        @Override
        public FileTransferStatus call() {
            try (BufferedInputStream bufferedInputStream = new BufferedInputStream(Files.newInputStream(from)); BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(Files.newOutputStream(to))) {
                byte[] iv, salt;
                int cipherMode;
                if (mode == FileTransferMode.ENCRYPT) {
                    iv = RandomValueGenerator.generateSecureBytes(ConfigurationDefaults.IV_LENGTH);
                    salt = RandomValueGenerator.generateSecureBytes(ConfigurationDefaults.SALT_LENGTH);
                    bufferedOutputStream.write(iv);
                    bufferedOutputStream.write(salt);
                    cipherMode = Cipher.ENCRYPT_MODE;
                } else {
                    int ivLength = ConfigurationDefaults.IV_LENGTH;
                    int saltLength = ConfigurationDefaults.SALT_LENGTH;
                    iv = new byte[ivLength];
                    salt = new byte[saltLength];
                    if (!(bufferedInputStream.read(iv) == ivLength && bufferedInputStream.read(salt) == saltLength)) {
                        throw new RuntimeException("Corrupted file [" + from + "] .");
                    }
                    cipherMode = Cipher.DECRYPT_MODE;
                }
                Cipher cipher = CipherManager.getCipher(key, iv, salt, cipherMode);
                CipherOutputStream cipherOutputStream = new CipherOutputStream(bufferedOutputStream, cipher);
                byte[] chunk = new byte[CHUNK_SIZE];
                int len;
                while ((len = bufferedInputStream.read(chunk)) > 0) {
                    cipherOutputStream.write(chunk, 0, len);
                    dataTransferred.addAndGet(len);
                }
                cipherOutputStream.close();
            } catch (Exception e) {
                Logger.logError("Transfer of [" + from + "] to [" + to + "] failed. : " + e);
                fileTransferStatus = FileTransferStatus.FAILED;
                return FileTransferStatus.FAILED;
            }
            Logger.logInfo("Transfer of [" + from + "] to [" + to + "] was successful.");
            fileTransferStatus = FileTransferStatus.COMPLETED;
            return FileTransferStatus.COMPLETED;
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
    }
}

