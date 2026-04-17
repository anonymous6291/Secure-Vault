package com.securevault;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

public class FileTransferManager {
    private static final int MAX_PARALLEL_FILE_TRANSFERS = 5;
    private final ExecutorService executorService = Executors.newFixedThreadPool(MAX_PARALLEL_FILE_TRANSFERS);
    private final char[] key;

    FileTransferManager(char[] key) {
        this.key = key;
    }

    static class FileTransferHandler implements Callable<FileTransferStatus> {
        private static final int CHUNK_SIZE = 1024 * 1024;
        private final Path from;
        private final Path to;
        private final char[] key;
        private final FileTransferMode mode;
        private final int id;
        private final long totalData;
        private final AtomicLong dataTransferred;
        private volatile FileTransferStatus fileTransferStatus;

        FileTransferHandler(Path from, Path to, char[] key, FileTransferMode mode, int id) {
            this.from = from;
            this.to = to;
            this.key = key;
            this.mode = mode;
            this.id = id;
            File fromFile = from.toFile();
            totalData = fromFile.length();
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

        public FileTransferStatus getStatus() {
            return fileTransferStatus;
        }

        public double getPercentageCompleted() {
            return switch (fileTransferStatus) {
                case FileTransferStatus.COMPLETED, FileTransferStatus.FAILED -> 100.0;
                default -> (dataTransferred.get() * 100.0) / totalData;
            };
        }
    }

    public enum FileTransferMode {
        ENCRYPT, DECRYPT
    }

    public enum FileTransferStatus {
        FAILED, PENDING, COMPLETED
    }
}
