package com.securevault.core;

import com.securevault.core.configurations.CipherManager;
import com.securevault.core.configurations.ConfigurationDefaults;
import com.securevault.core.configurations.SecureRandomValueGenerator;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Semaphore;

public class Logger {
    private static final String ENCRYPTED_LOG_FILE_NAME = "log.data";
    private static final String DECRYPTED_LOG_FILE_NAME = "log.data1";
    private final Semaphore lock = new Semaphore(1, true);
    private final Path encryptedLogFile;
    private final Path decryptedLogFile;
    private final boolean printLogToIO;
    private final char[] encryptionKey;
    private final byte[] salt;
    private final byte[] iv;
    private BufferedOutputStream logFileWriter;

    public Logger(Path logPath, char[] key, boolean create, boolean printLogToIO) {
        encryptedLogFile = Path.of(logPath.toString(), ENCRYPTED_LOG_FILE_NAME);
        decryptedLogFile = Path.of(logPath.toString(), DECRYPTED_LOG_FILE_NAME);
        this.printLogToIO = printLogToIO;
        try {
            int saltLength = ConfigurationDefaults.SALT_LENGTH;
            int ivLength = ConfigurationDefaults.IV_LENGTH;
            if (!create && Files.isRegularFile(encryptedLogFile)) {
                try (InputStream inputStream = Files.newInputStream(encryptedLogFile); BufferedOutputStream fileOutputStream = new BufferedOutputStream(Files.newOutputStream(decryptedLogFile))) {
                    iv = inputStream.readNBytes(ivLength);
                    salt = inputStream.readNBytes(saltLength);
                    Cipher cipher = CipherManager.getCipher(key, iv, salt, Cipher.DECRYPT_MODE);
                    CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);
                    cipherInputStream.transferTo(fileOutputStream);
                } catch (Exception e) {
                    throw new Exception("Exception occurred while reading log : " + e.getMessage());
                }
            } else {
                salt = SecureRandomValueGenerator.generateSecureBytes(saltLength);
                iv = SecureRandomValueGenerator.generateSecureBytes(ivLength);
            }
            if (!Files.exists(decryptedLogFile)) {
                Files.createFile(decryptedLogFile);
            }
            logFileWriter = new BufferedOutputStream(Files.newOutputStream(decryptedLogFile, StandardOpenOption.APPEND));
            encryptionKey = key;
        } catch (Exception e) {
            throw new RuntimeException("Initialization of Logger failed : " + e.getMessage());
        }
    }

    private boolean notLocked() {
        try {
            lock.acquire();
            return false;
        } catch (InterruptedException e) {
            return true;
        }
    }

    private void unlock() {
        lock.release();
    }

    public void logSevere(String message) {
        log(message, LogType.SEVERE);
    }

    public void logError(String message) {
        log(message, LogType.ERROR);
    }

    public void logWarn(String message) {
        log(message, LogType.WARN);
    }

    public void logInfo(String message) {
        log(message, LogType.INFO);
    }

    public void log(String message, LogType logType) {
        if (notLocked()) {
            return;
        }
        if (printLogToIO) {
            IO.println("[" + logType + "] : " + message);
        }
        try {
            logFileWriter.write((new Date() + " [" + logType + "] : " + message + "\n").getBytes());
            logFileWriter.flush();
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while writing to the log file : " + e.getMessage());
        } finally {
            unlock();
        }
    }

    public String getLogs(int lastLines) {
        if (notLocked()) {
            return "";
        }
        try {
            logFileWriter.close();
        } catch (Exception e) {
            try {
                close0();
            } catch (Exception _) {
            }
            unlock();
            throw new RuntimeException("Exception occurred in Logger while closing the stream : " + e.getMessage());
        }
        try (BufferedReader bufferedReader = Files.newBufferedReader(decryptedLogFile)) {
            List<String> logs = new LinkedList<>();
            String nextLine;
            while ((nextLine = bufferedReader.readLine()) != null) {
                if (logs.size() == lastLines) {
                    logs.removeFirst();
                }
                logs.add(nextLine);
            }
            StringBuilder allLogs = new StringBuilder();
            logs.forEach(x -> allLogs.append(x).append('\n'));
            return allLogs.toString();
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while getting logs.");
        } finally {
            try {
                logFileWriter = new BufferedOutputStream(Files.newOutputStream(decryptedLogFile, StandardOpenOption.APPEND));
            } catch (Exception e) {
                try {
                    close0();
                } catch (Exception _) {
                }
            }
            unlock();
        }
    }

    public void clearLogs() {
        if (notLocked()) {
            return;
        }
        try {
            logFileWriter.close();
        } catch (Exception _) {
            unlock();
            return;
        }
        try {
            logFileWriter = new BufferedOutputStream(Files.newOutputStream(decryptedLogFile));
        } catch (Exception e) {
            try {
                close0();
            } catch (Exception _) {
            }
            throw new RuntimeException("Exception occurred while opening the log file : " + e.getMessage());
        } finally {
            unlock();
        }
    }

    private void close0() throws Exception {
        logFileWriter.close();
        OutputStream outputStream = Files.newOutputStream(encryptedLogFile);
        outputStream.write(iv);
        outputStream.write(salt);
        Cipher cipher = CipherManager.getCipher(encryptionKey, iv, salt, Cipher.ENCRYPT_MODE);
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
        BufferedInputStream bufferedInputStream = new BufferedInputStream(Files.newInputStream(decryptedLogFile));
        bufferedInputStream.transferTo(cipherOutputStream);
        cipherOutputStream.close();
        bufferedInputStream.close();
        Files.delete(decryptedLogFile);
    }

    public void close() {
        notLocked();
        try {
            close0();
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while writing the encrypted logs : " + e.getMessage());
        } finally {
            unlock();
        }
    }

    public enum LogType {
        SEVERE, ERROR, WARN, INFO
    }
}
