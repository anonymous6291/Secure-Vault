package com.securevault;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedList;
import java.util.List;
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
            if (Files.isRegularFile(encryptedLogFile)) {
                try (CipherInputStream cipherInputStream = new CipherInputStream(Files.newInputStream(encryptedLogFile), CipherManager.getCipher(key, configurations.iv(), configurations.salt(), false)); BufferedOutputStream fileOutputStream = new BufferedOutputStream(Files.newOutputStream(decryptedLogFile))) {
                    cipherInputStream.transferTo(fileOutputStream);
                } catch (Exception e) {
                    IO.println("Exception occurred while reading encrypted file : " + e);
                }
            }
            logFileWriter = new BufferedOutputStream(Files.newOutputStream(decryptedLogFile, StandardOpenOption.APPEND));
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

    public static void logSevere(String message) {
        log(message, LogType.SEVERE);
    }

    public static void logError(String message) {
        log(message, LogType.ERROR);
    }

    public static void logWarn(String message) {
        log(message, LogType.WARN);
    }

    public static void logInfo(String message) {
        log(message, LogType.INFO);
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
            logFileWriter.flush();
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while writing to the log file : " + e);
        } finally {
            unlock();
        }
    }

    public static String getLogs(int lastLines) {
        if (!(initialized && lock())) {
            return null;
        }
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
            for (String s : logs) {
                allLogs.append(s).append('\n');
            }
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

    public static void clearLogs() {
        if (!(initialized && lock())) {
            return;
        }
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

    private static void close0() throws Exception {
        logFileWriter.close();
        Cipher cipher = CipherManager.getCipher(encryptionKey, configurations.iv(), configurations.salt(), true);
        CipherOutputStream cipherOutputStream = new CipherOutputStream(Files.newOutputStream(encrLogFile), cipher);
        BufferedInputStream bufferedInputStream = new BufferedInputStream(Files.newInputStream(decrLogFile));
        bufferedInputStream.transferTo(cipherOutputStream);
        cipherOutputStream.close();
        bufferedInputStream.close();
        initialized = false;
        Files.delete(decrLogFile);
    }

    public static void close() throws Exception {
        if (!initialized) {
            return;
        }
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
