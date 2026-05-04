package com.securevault.core.keyhandlers;

import com.securevault.core.Logger;
import com.securevault.core.configurations.CipherManager;
import com.securevault.core.configurations.ConfigurationDefaults;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;

public class PasswordAndApiKeyManager {
    private static final String DIRECTORY_NAME = "keys";
    private static final String API_KEY_FILE_NAME = "data1";
    private static final String PASSWORD_FILE_NAME = "data2";
    private static final Base64.Encoder encoder = Base64.getEncoder();
    private static final Base64.Decoder decoder = Base64.getDecoder();
    private final Semaphore lock = new Semaphore(1);
    private final Trie apiKeys;
    private final Trie passwords;
    private final Path apiKeyDataPath;
    private final Path passwordDataPath;
    private final char[] key;
    private final Logger logger;

    PasswordAndApiKeyManager(Path basePath, char[] key, Logger logger) {
        apiKeyDataPath = Path.of(basePath.toString(), DIRECTORY_NAME, API_KEY_FILE_NAME);
        passwordDataPath = Path.of(basePath.toString(), DIRECTORY_NAME, PASSWORD_FILE_NAME);
        this.key = key;
        this.logger = logger;
        apiKeys = new Trie();
        passwords = new Trie();
        ConfigurationDefaults.Data data = ConfigurationDefaults.getDefault(PasswordAndApiKeyManager.class);
        byte[] iv = data.iv();
        byte[] salt = data.salt();
        readFromFileToTrie(apiKeyDataPath, apiKeys, key, iv, salt);
        readFromFileToTrie(passwordDataPath, passwords, key, iv, salt);
    }

    private String base64Encoder(byte[] value) {
        return encoder.encodeToString(value);
    }

    private String base64Decode(String value) {
        return new String(decoder.decode(value));
    }

    private void readFromFileToTrie(Path filePath, Trie trie, char[] key, byte[] iv, byte[] salt) {
        if (Files.exists(filePath)) {
            try {
                Cipher cipher = CipherManager.getCipher(key, iv, salt, Cipher.DECRYPT_MODE);
                CipherInputStream cipherInputStream = new CipherInputStream(Files.newInputStream(filePath), cipher);
                String allData = new String(cipherInputStream.readAllBytes());
                cipherInputStream.close();
                String[] split = allData.split("\n");
                int n = split.length;
                for (int i = 1; i < n; i += 2) {
                    trie.putValue(base64Decode(split[i - 1]), base64Decode(split[i]));
                }
            } catch (Exception e) {
                logError(e);
            }
        }
    }

    private void writeTrieToFile(Path filePath, Trie trie, char[] key, byte[] iv, byte[] salt) {
        try {
            Cipher cipher = CipherManager.getCipher(key, iv, salt, Cipher.ENCRYPT_MODE);
        } catch (Exception e) {
            logError(e);
        }
    }

    private void logError(Exception e) {
        logger.logError("Exception occurred inside PasswordAndApiKeyManager : " + e);
    }

    public void close() {
    }

    static class Trie {
        static class TrieNode {
            private final Map<Character, TrieNode> children = new ConcurrentHashMap<>();
            private String key;
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
                return key;
            }

            void setKey(String key) {
                this.key = key;
            }

            String getValue() {
                return value;
            }

            void setValue(String value) {
                this.value = value;
            }

            void clearValue() {
                key = null;
                value = null;
            }
        }

        private final TrieNode root = new TrieNode();
        private final Semaphore lock = new Semaphore(1);

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

        void putValue(String key, String value) {
            if (!lock()) {
                return;
            }
            TrieNode current = root;
            for (char c : key.toCharArray()) {
                current = current.getOrMakeChild(c);
            }
            current.setKey(key);
            current.setValue(value);
            unlock();
        }

        String getValue(String key) {
            if (!lock()) {
                return null;
            }
            TrieNode current = root;
            for (char c : key.toCharArray()) {
                current = current.getChild(c);
                if (current == null) {
                    return null;
                }
            }
            unlock();
            return current.getValue();
        }

        private void recursiveDelete(TrieNode node, String key, int index) {
            if (key.length() == index) {
                node.clearValue();
                return;
            }
            TrieNode child = node.getChild(key.charAt(index));
            recursiveDelete(child, key, index + 1);
            if (!child.hasChildrenOrData()) {
                node.removeChild(key.charAt(index));
            }
        }

        void deleteValue(String key) {
            if (!lock()) {
                return;
            }
            recursiveDelete(root, key, 0);
            unlock();
        }

        private void advancedRecursiveKeySearch(TrieNode node, String key, int index, Set<String> result) {
            if (key.length() == index && node.getValue() != null) {
                result.add(node.getKey());
            }
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
                    return result;
                }
            }
            recursiveKeySearch(current, result);
            unlock();
            return result;
        }

        private void getAllKeysRecursively(TrieNode node, Map<String, String> allKeys) {
            if (node.getValue() != null) {
                allKeys.put(node.getKey(), node.getValue());
            }
            for (TrieNode trieNode : node.getChildren()) {
                getAllKeysRecursively(trieNode, allKeys);
            }
        }

        Map<String, String> getAllKeys() {
            Map<String, String> keys = new LinkedHashMap<>();
            if (!lock()) {
                return keys;
            }
            getAllKeysRecursively(root, keys);
            unlock();
            return keys;
        }
    }
}
