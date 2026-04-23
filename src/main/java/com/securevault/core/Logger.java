package com.securevault.core;

import com.securevault.core.configurations.CipherManager;
import com.securevault.core.configurations.ConfigurationDefaults;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Semaphore;

public class Logger {
    private static final ConfigurationDefaults.Data configurations = ConfigurationDefaults.getDefault(Logger.class);
    private final Semaphore lock = new Semaphore(1, true);
    private final Path encrLogFile;
    private final Path decrLogFile;
    private final char[] encryptionKey;
    private BufferedOutputStream logFileWriter;

    public Logger(Path encryptedLogFile, Path decryptedLogFile, char[] key) {
        if (!lock()) {
            throw new RuntimeException("Initialization of Logger failed.");
        }
        try {
            if (Files.isRegularFile(encryptedLogFile)) {
                try (CipherInputStream cipherInputStream = new CipherInputStream(Files.newInputStream(encryptedLogFile), CipherManager.getCipher(key, configurations.iv(), configurations.salt(), Cipher.DECRYPT_MODE)); BufferedOutputStream fileOutputStream = new BufferedOutputStream(Files.newOutputStream(decryptedLogFile))) {
                    cipherInputStream.transferTo(fileOutputStream);
                } catch (Exception e) {
                    IO.println("Exception occurred while reading log : " + e);
                }
            }
            if (!Files.exists(decryptedLogFile)) {
                Files.createFile(decryptedLogFile);
            }
            logFileWriter = new BufferedOutputStream(Files.newOutputStream(decryptedLogFile, StandardOpenOption.APPEND));
            encrLogFile = encryptedLogFile;
            decrLogFile = decryptedLogFile;
            encryptionKey = key;
        } catch (Exception e) {
            throw new RuntimeException("Initialization of Logger failed : " + e);
        } finally {
            unlock();
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

    public synchronized void log(String message, LogType logType) {
        IO.println("[" + logType + "] : " + message);
        try {
            logFileWriter.write((new Date() + " [" + logType + "] : " + message + "\n").getBytes());
            logFileWriter.flush();
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while writing to the log file : " + e);
        } finally {
            unlock();
        }
    }

    public String getLogs(int lastLines) {
        try {
            logFileWriter.close();
        } catch (Exception e) {
            try {
                close0();
            } catch (Exception _) {
            }
            unlock();
            throw new RuntimeException("Exception occurred in Logger while closing the stream : " + e);
        }
        try (BufferedReader bufferedReader = Files.newBufferedReader(decrLogFile)) {
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
                logFileWriter = new BufferedOutputStream(Files.newOutputStream(decrLogFile, StandardOpenOption.APPEND));
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
        try {
            logFileWriter.close();
        } catch (Exception _) {
        }
        try {
            logFileWriter = new BufferedOutputStream(Files.newOutputStream(decrLogFile));
        } catch (Exception e) {
            try {
                close0();
            } catch (Exception _) {
            }
            throw new RuntimeException("Exception occurred while opening the log file : " + e);
        } finally {
            unlock();
        }
    }

    private void close0() throws Exception {
        logFileWriter.close();
        Cipher cipher = CipherManager.getCipher(encryptionKey, configurations.iv(), configurations.salt(), Cipher.ENCRYPT_MODE);
        CipherOutputStream cipherOutputStream = new CipherOutputStream(Files.newOutputStream(encrLogFile), cipher);
        BufferedInputStream bufferedInputStream = new BufferedInputStream(Files.newInputStream(decrLogFile));
        bufferedInputStream.transferTo(cipherOutputStream);
        cipherOutputStream.close();
        bufferedInputStream.close();
        Files.delete(decrLogFile);
    }

    public void close() {
        if (!lock()) {
            throw new RuntimeException("Unable to gain lock while closing the Logger.");
        }
        try {
            close0();
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while writing the encrypted logs : " + e);
        } finally {
            unlock();
        }
    }

    public enum LogType {
        SEVERE, ERROR, WARN, INFO
    }
}
