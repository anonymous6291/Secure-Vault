package com.securevault.core.keyhandlers;

import com.securevault.core.Logger;

import java.nio.file.Path;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;

public class PasswordAndApiKeyManager {
    private static final String DIRECTORY_NAME = "keys";
    private static final String FILE_NAME = "DATA";
    private final Semaphore lock = new Semaphore(1);
    private final Trie keys;
    private final Path fileDataPath;
    private final char[] key;
    private final Logger logger;

    PasswordAndApiKeyManager(Path basePath, char[] key, Logger logger) {
        fileDataPath = Path.of(basePath.toString(), DIRECTORY_NAME, FILE_NAME);
        keys = new Trie();
        this.key = key;
        this.logger = logger;
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
                return !children.isEmpty() || key != null;
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
                value = null;
            }
        }

        private final TrieNode root = new TrieNode();

        void putValue(String key, String value) {
            TrieNode current = root;
            for (char c : key.toCharArray()) {
                current = current.getOrMakeChild(c);
            }
            current.setKey(key);
            current.setValue(value);
        }

        String getValue(String key) {
            TrieNode current = root;
            for (char c : key.toCharArray()) {
                current = current.getChild(c);
                if (current == null) {
                    return null;
                }
            }
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
            recursiveDelete(root, key, 0);
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
            Set<String> result = new LinkedHashSet<>();
            TrieNode current = root;
            for (char c : prefix.toCharArray()) {
                current = current.getChild(c);
                if (current == null) {
                    return result;
                }
            }
            recursiveKeySearch(current, result);
            return result;
        }
    }
}
