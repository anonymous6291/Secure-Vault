package com.securevault;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Semaphore;

public class Logger {
    private static final ConfigurationDefaults.Data configurations = ConfigurationDefaults.getDefault(Logger.class);
    private static BufferedOutputStream logFileWriter;
    private static Path encrLogFile;
    private static Path decrLogFile;
    private static boolean initialized;
    private static char[] encryptionKey;
    private static final Semaphore lock = new Semaphore(1, true);

    public static void init(Path encryptedLogFile, Path decryptedLogFile, char[] key) throws Exception {
        if (initialized) {
            return;
        }
        if (!lock()) {
            throw new RuntimeException("Initialization of Logger failed.");
        }
        try {
            try {
                if (Files.isRegularFile(encryptedLogFile)) {
                    Cipher cipher = CipherManager.getCipher(key, configurations.iv(), configurations.salt(), false);
                    CipherInputStream cipherInputStream = new CipherInputStream(Files.newInputStream(encryptedLogFile), cipher);
                    BufferedOutputStream fileOutputStream = new BufferedOutputStream(Files.newOutputStream(decryptedLogFile));
                    cipherInputStream.transferTo(fileOutputStream);
                    cipherInputStream.close();
                    fileOutputStream.close();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            logFileWriter = new BufferedOutputStream(Files.newOutputStream(decryptedLogFile));
            encrLogFile = encryptedLogFile;
            decrLogFile = decryptedLogFile;
            encryptionKey = key;
            initialized = true;
        } catch (Exception e) {
            throw new RuntimeException("Initialization of Logger failed : " + e);
        } finally {
            unlock();
        }
    }

    private static boolean lock() {
        try {
            lock.acquire();
            return true;
        } catch (InterruptedException e) {
            return false;
        }
    }

    private static void unlock() {
        lock.release();
    }

    public static synchronized void log(String message, LogType logType) {
        if (!initialized) {
            IO.println("[" + logType + "] : " + message);
        }
        if (!lock()) {
            return;
        }
        try {
            logFileWriter.write(("[" + logType + "] : " + message + "\n").getBytes());
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while writing to the log file : " + e);
        } finally {
            unlock();
        }
    }

    public static void close() throws Exception {
        if (!initialized) {
            return;
        }
        if (!lock()) {
            throw new RuntimeException("Unable to gain lock while closing the Logger.");
        }
        try {
            logFileWriter.close();
            Cipher cipher = CipherManager.getCipher(encryptionKey, configurations.iv(), configurations.salt(), true);
            CipherOutputStream cipherOutputStream = new CipherOutputStream(Files.newOutputStream(encrLogFile), cipher);
            BufferedInputStream bufferedInputStream = new BufferedInputStream(Files.newInputStream(decrLogFile));
            bufferedInputStream.transferTo(cipherOutputStream);
            cipherOutputStream.close();
            bufferedInputStream.close();
            initialized = false;
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while writing the encrypted logs : " + e);
        } finally {
            Files.delete(decrLogFile);
            unlock();
        }
    }

    public enum LogType {
        SEVERE, ERROR, WARN, INFO
    }
}
