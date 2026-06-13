package com.securevault.core.keyhandlers;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securevault.core.Logger;
import com.securevault.core.Writable;
import com.securevault.core.configurations.CipherManager;
import com.securevault.core.configurations.ConfigurationDefaults;
import com.securevault.core.configurations.SecureRandomValueGenerator;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.Semaphore;

public class PasswordAndAPIKeyManager implements Writable {
    private static final String DIRECTORY_NAME = "keys";
    private static final String API_KEY_FILE_NAME = "data1";
    private static final String PASSWORD_FILE_NAME = "data2";
    private static final ObjectMapper jsonHandler = new ObjectMapper();
    private static final Base64.Encoder encoder = Base64.getEncoder();
    private static final Base64.Decoder decoder = Base64.getDecoder();
    private final Semaphore lock = new Semaphore(1, true);
    private final Path apiKeyDataPath;
    private final Path passwordDataPath;
    private final Logger logger;
    private final char[] key;
    private final byte[][] ivs = new byte[2][];
    private final byte[][] salts = new byte[2][];
    private TreeMap<WebsiteIdPair, String> apiKeys = new TreeMap<>();
    private TreeMap<WebsiteIdPair, String> passwords = new TreeMap<>();

    static {
        jsonHandler.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public PasswordAndAPIKeyManager(Path basePath, char[] key, boolean create, Logger logger) throws Exception {
        Path parentPath = Path.of(basePath.toString(), DIRECTORY_NAME);
        apiKeyDataPath = Path.of(parentPath.toString(), API_KEY_FILE_NAME);
        passwordDataPath = Path.of(parentPath.toString(), PASSWORD_FILE_NAME);
        this.key = key;
        this.logger = logger;
        try {
            if (!Files.isDirectory(parentPath)) {
                Files.createDirectories(parentPath);
            }
            readFromFileToTrie(create, apiKeyDataPath, apiKeys, key, 0);
            readFromFileToTrie(create, passwordDataPath, passwords, key, 1);
        } catch (Exception e) {
            throw new Exception("Exception occurred while starting the PasswordAndAPIKeyManager : " + e.getMessage());
        }
    }

    private boolean notLocked() {
        try {
            lock.acquire();
            return false;
        } catch (InterruptedException _) {
            return true;
        }
    }

    private void unlock() {
        lock.release();
    }

    private String base64Encode(byte[] value) {
        return encoder.encodeToString(value);
    }

    private String base64Decode(String value) {
        return new String(decoder.decode(value));
    }

    private void readFromFileToTrie(boolean create, Path filePath, TreeMap<WebsiteIdPair, String> keys, char[] password, int index) throws Exception {
        int ivLength = ConfigurationDefaults.IV_LENGTH, saltLength = ConfigurationDefaults.SALT_LENGTH;
        if (!create && Files.isRegularFile(filePath)) {
            byte[] iv = new byte[ivLength];
            byte[] salt = new byte[saltLength];
            InputStream inputStream = Files.newInputStream(filePath);
            if (inputStream.read(iv) != ivLength || inputStream.read(salt) != saltLength) {
                throw new RuntimeException("Corrupt data file.");
            }
            Cipher cipher = CipherManager.getCipher(password, iv, salt, Cipher.DECRYPT_MODE);
            CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher);
            String allData = new String(cipherInputStream.readAllBytes());
            cipherInputStream.close();
            String[] split = allData.split("\n");
            for (String s : split) {
                if (!s.isEmpty()) {
                    PairValue pairValue = jsonHandler.readValue(base64Decode(s), PairValue.class);
                    keys.put(pairValue.websiteIdPair(), pairValue.value());
                }
            }
            ivs[index] = iv;
            salts[index] = salt;
            return;
        }
        ivs[index] = SecureRandomValueGenerator.generateSecureBytes(ivLength);
        salts[index] = SecureRandomValueGenerator.generateSecureBytes(saltLength);
    }

    private void logError(Exception e) {
        logger.logError("Exception occurred inside PasswordAndAPIKeyManager : " + e.getMessage());
    }

    public boolean addKey(WebsiteIdPair websiteIdPair, String value, KeyType keyType) {
        if (notLocked()) {
            return false;
        }
        try {
            if (keyType == KeyType.PASSWORD) {
                if (passwords.containsKey(websiteIdPair)) {
                    return false;
                }
                passwords.put(websiteIdPair, value);
            } else {
                if (apiKeys.containsKey(websiteIdPair)) {
                    return false;
                }
                apiKeys.put(websiteIdPair, value);
            }
            return true;
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while adding the password : " + e.getMessage());
        } finally {
            unlock();
        }
    }

    public String getKeyValue(WebsiteIdPair websiteIdPair, KeyType keyType) {
        if (notLocked()) {
            return "";
        }
        try {
            if (keyType == KeyType.PASSWORD) {
                return passwords.get(websiteIdPair);
            } else {
                return apiKeys.get(websiteIdPair);
            }
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while getting the password : " + e.getMessage());
        } finally {
            unlock();
        }
    }

    public void deleteKey(WebsiteIdPair websiteIdPair, KeyType keyType) {
        if (notLocked()) {
            return;
        }
        try {
            if (keyType == KeyType.PASSWORD) {
                passwords.remove(websiteIdPair);
            } else {
                apiKeys.remove(websiteIdPair);
            }
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while deleting the password : " + e.getMessage());
        } finally {
            unlock();
        }
    }

    public List<WebsiteIdPair> searchKey(WebsiteIdPair websiteIdPair, KeyType keyType) {
        List<WebsiteIdPair> result = new LinkedList<>();
        if (notLocked()) {
            return result;
        }
        try {
            if (keyType == KeyType.PASSWORD) {
                result.addAll(passwords.keySet());
            } else {
                result.addAll(apiKeys.keySet());
            }
            return result.stream().filter(x -> x.websiteName().startsWith(websiteIdPair.websiteName())).filter(x -> x.id().startsWith(websiteIdPair.id())).toList();
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while searching the password : " + e.getMessage());
        } finally {
            unlock();
        }
    }

    public void clearKeys(KeyType keyType) {
        if (notLocked()) {
            return;
        }
        try {
            if (keyType == KeyType.PASSWORD) {
                passwords.clear();
            } else {
                apiKeys.clear();
            }
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while clearing all passwords : " + e.getMessage());
        } finally {
            unlock();
        }
    }

    public Set<WebsiteIdPair> getAllKeys(KeyType keyType) {
        Set<WebsiteIdPair> set = new TreeSet<>();
        if (notLocked()) {
            return set;
        }
        try {
            if (keyType == KeyType.PASSWORD) {
                set.addAll(passwords.keySet());
            } else {
                set.addAll(apiKeys.keySet());
            }
            return set;
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while getting all passwords : " + e.getMessage());
        } finally {
            unlock();
        }
    }

    private void writeToFile(Path filePath, TreeMap<WebsiteIdPair, String> keys, char[] password, int index) throws Exception {
        try {
            OutputStream outputStream = Files.newOutputStream(filePath);
            outputStream.write(ivs[index]);
            outputStream.write(salts[index]);
            Cipher cipher = CipherManager.getCipher(password, ivs[index], salts[index], Cipher.ENCRYPT_MODE);
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
            for (WebsiteIdPair websiteIdPair : keys.keySet()) {
                PairValue pairValue = new PairValue(websiteIdPair, keys.get(websiteIdPair));
                String result = base64Encode(jsonHandler.writeValueAsBytes(pairValue)) + "\n";
                cipherOutputStream.write(result.getBytes());
            }
            cipherOutputStream.close();
        } catch (Exception e) {
            logError(e);
            throw e;
        }
    }

    @Override
    public void writeData() {
        notLocked();
        try {
            writeToFile(apiKeyDataPath, apiKeys, key, 0);
            writeToFile(passwordDataPath, passwords, key, 1);
        } catch (Exception e) {
            throw new RuntimeException("Exception occurred while writing the data of PasswordAndAPIKey : " + e.getMessage());
        } finally {
            unlock();
        }
    }

    public void close() {
        writeData();
        apiKeys = null;
        passwords = null;
        ivs[0] = null;
        ivs[1] = null;
        salts[0] = null;
        salts[1] = null;
    }
}

record PairValue(WebsiteIdPair websiteIdPair, String value) {
}