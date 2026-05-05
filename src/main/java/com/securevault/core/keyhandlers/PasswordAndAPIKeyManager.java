package com.securevault.core.keyhandlers;

import com.securevault.core.Logger;
import com.securevault.core.Writable;
import com.securevault.core.configurations.CipherManager;
import com.securevault.core.configurations.ConfigurationDefaults;
import com.securevault.core.configurations.RandomValueGenerator;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;

public class PasswordAndAPIKeyManager implements Writable {
    private static final String DIRECTORY_NAME = "keys";
    private static final String API_KEY_FILE_NAME = "data1";
    private static final String PASSWORD_FILE_NAME = "data2";
    private static final Base64.Encoder encoder = Base64.getEncoder();
    private static final Base64.Decoder decoder = Base64.getDecoder();
    private final Semaphore lock = new Semaphore(1, true);
    private final Path apiKeyDataPath;
    private final Path passwordDataPath;
    private final Logger logger;
    private final char[] key;
    private Trie apiKeys;
    private Trie passwords;
    private final byte[][] ivs = new byte[2][];
    private final byte[][] salts = new byte[2][];

    public PasswordAndAPIKeyManager(Path basePath, char[] key, Logger logger) throws Exception {
        Path parentPath = Path.of(basePath.toString(), DIRECTORY_NAME);
        apiKeyDataPath = Path.of(parentPath.toString(), API_KEY_FILE_NAME);
        passwordDataPath = Path.of(parentPath.toString(), PASSWORD_FILE_NAME);
        if (!Files.isDirectory(parentPath)) {
            Files.createDirectories(parentPath);
        }
        this.key = key;
        this.logger = logger;
        apiKeys = new Trie();
        passwords = new Trie();
        readFromFileToTrie(apiKeyDataPath, apiKeys, key, 0);
        readFromFileToTrie(passwordDataPath, passwords, key, 1);
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

    private String base64Encode(byte[] value) {
        return encoder.encodeToString(value);
    }

    private String base64Decode(String value) {
        return new String(decoder.decode(value));
    }

    private void readFromFileToTrie(Path filePath, Trie trie, char[] password, int index) {
        int ivLength = ConfigurationDefaults.IV_LENGTH, saltLength = ConfigurationDefaults.SALT_LENGTH;
        if (Files.exists(filePath)) {
            try {
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
                int n = split.length;
                for (int i = 1; i < n; i += 2) {
                    trie.putValue(base64Decode(split[i - 1]), base64Decode(split[i]));
                }
                ivs[index] = iv;
                salts[index] = salt;
                return;
            } catch (Exception e) {
                logError(e);
            }
        }
        ivs[index] = RandomValueGenerator.generateSecureBytes(ivLength);
        salts[index] = RandomValueGenerator.generateSecureBytes(saltLength);
    }

    private void writeTrieToFile(Path filePath, Trie trie, char[] password, int index) {
        try {
            OutputStream outputStream = Files.newOutputStream(filePath);
            outputStream.write(ivs[index]);
            outputStream.write(salts[index]);
            Cipher cipher = CipherManager.getCipher(password, ivs[index], salts[index], Cipher.ENCRYPT_MODE);
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
            Map<String, String> pairs = trie.getAllPairs();
            for (String name : pairs.keySet()) {
                String value = pairs.get(name);
                String result = base64Encode(name.getBytes()) + "\n" + base64Encode(value.getBytes()) + "\n";
                cipherOutputStream.write(result.getBytes());
            }
            cipherOutputStream.close();
        } catch (Exception e) {
            logError(e);
        }
    }

    private void logError(Exception e) {
        logger.logError("Exception occurred inside PasswordAndAPIKeyManager : " + e);
    }

    public void putPassword(String name, String value) {
        passwords.putValue(name, value);
    }

    public String getPassword(String name) {
        return passwords.getValue(name);
    }

    public void deletePassword(String name) {
        passwords.deleteKey(name);
    }

    public Set<String> searchPassword(String prefix) {
        return passwords.searchKey(prefix);
    }

    public void clearAllPasswords() {
        passwords.clearAll();
    }

    public void putAPIKey(String name, String value) {
        apiKeys.putValue(name, value);
    }

    public String getAPIKey(String name) {
        return apiKeys.getValue(name);
    }

    public void deleteAPIKey(String name) {
        apiKeys.deleteKey(name);
    }

    public Set<String> searchAPIKey(String prefix) {
        return apiKeys.searchKey(prefix);
    }

    public void clearAllAPIKeys() {
        apiKeys.clearAll();
    }

    @Override
    public void writeData() {
        lock();
        ConfigurationDefaults.Data data = ConfigurationDefaults.getDefault(PasswordAndAPIKeyManager.class);
        writeTrieToFile(apiKeyDataPath, apiKeys, key, 0);
        writeTrieToFile(passwordDataPath, passwords, key, 1);
        unlock();
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

    static class Trie {
        static class TrieNode {
            private final Map<Character, TrieNode> children = new ConcurrentHashMap<>();
            private String name;
            private String value;

            TrieNode getOrMakeChild(char c) {
                if (children.containsKey(c)) {
                    return children.get(c);
                }
                TrieNode child = new TrieNode();
                children.put(c, child);
                return child;
            }

            TrieNode getChild(char c) {
                return children.get(c);
            }

            Collection<TrieNode> getChildren() {
                return children.values();
            }

            void removeChild(char c) {
                children.remove(c);
            }

            boolean hasChildrenOrData() {
                return !children.isEmpty() || value != null;
            }

            String getKey() {
                return name;
            }

            void setKey(String name) {
                this.name = name;
            }

            String getValue() {
                return value;
            }

            void setValue(String value) {
                this.value = value;
            }

            void clearValue() {
                name = null;
                value = null;
            }

            void clear() {
                clearValue();
                children.clear();
            }
        }

        private final TrieNode root = new TrieNode();
        private final Semaphore lock = new Semaphore(1, true);

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

        void putValue(String name, String value) {
            if (!lock()) {
                return;
            }
            TrieNode current = root;
            for (char c : name.toCharArray()) {
                current = current.getOrMakeChild(c);
            }
            current.setKey(name);
            current.setValue(value);
            unlock();
        }

        String getValue(String name) {
            if (!lock()) {
                return null;
            }
            TrieNode current = root;
            for (char c : name.toCharArray()) {
                current = current.getChild(c);
                if (current == null) {
                    unlock();
                    return "";
                }
            }
            unlock();
            return current.getValue();
        }

        private void recursiveDelete(TrieNode node, String name, int index) {
            if (name.length() == index) {
                node.clearValue();
                return;
            }
            TrieNode child = node.getChild(name.charAt(index));
            recursiveDelete(child, name, index + 1);
            if (!child.hasChildrenOrData()) {
                node.removeChild(name.charAt(index));
            }
        }

        void deleteKey(String name) {
            if (!lock()) {
                return;
            }
            recursiveDelete(root, name, 0);
            unlock();
        }

        private void recursiveKeySearch(TrieNode node, Set<String> result) {
            if (node.getValue() != null) {
                result.add(node.getKey());
            }
            for (TrieNode child : node.getChildren()) {
                recursiveKeySearch(child, result);
            }
        }

        Set<String> searchKey(String prefix) {
            if (!lock()) {
                return Set.of();
            }
            Set<String> result = new LinkedHashSet<>();
            TrieNode current = root;
            for (char c : prefix.toCharArray()) {
                current = current.getChild(c);
                if (current == null) {
                    unlock();
                    return result;
                }
            }
            recursiveKeySearch(current, result);
            unlock();
            return result;
        }

        private void getAllPairsRecursively(TrieNode node, Map<String, String> allKeys) {
            if (node.getValue() != null) {
                allKeys.put(node.getKey(), node.getValue());
            }
            for (TrieNode trieNode : node.getChildren()) {
                getAllPairsRecursively(trieNode, allKeys);
            }
        }

        void clearAll() {
            root.clear();
        }

        Map<String, String> getAllPairs() {
            Map<String, String> keys = new LinkedHashMap<>();
            if (!lock()) {
                return keys;
            }
            getAllPairsRecursively(root, keys);
            unlock();
            return keys;
        }
    }
}
