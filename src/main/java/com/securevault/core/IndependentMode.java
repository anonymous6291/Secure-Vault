package com.securevault.core;

import com.securevault.core.filehandlers.FileTransferMonitor;
import com.securevault.core.filehandlers.listeners.FileManagerUpdateListener;

import java.io.Console;
import java.io.File;
import java.nio.file.Path;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public class IndependentMode {
    private static final Map<String, CommandType> COMMANDS = new LinkedHashMap<>();
    private static final String EXIT_COMMAND = "e|exit";
    private static final String EXIT_COMMAND_REGEX = "(?i:(exit|e))";
    private static final String CONFIRM_REGEX = "(?i:(yes))|(?i:(y))";
    private static final String VAULT_PATH_ARGUMENT = "-p";
    private static final String HIERARCHY_SPACE_PER_DEPTH = "   ";
    private static FileTransferMonitor fileTransferMonitor;

    static {
        COMMANDS.put("v", CommandType.VERSION);
        COMMANDS.put("cp", CommandType.CHANGE_PASSWORD);
        COMMANDS.put("sd", CommandType.SELF_DESTRUCT);
        COMMANDS.put("ld", CommandType.LOCKDOWN);
        COMMANDS.put("ssd", CommandType.SET_SELF_DESTRUCT);
        COMMANDS.put("gsdt", CommandType.GET_SELF_DESTRUCT_TRIES);
        COMMANDS.put("dsd", CommandType.DISABLE_SELF_DESTRUCT);
        COMMANDS.put("isde", CommandType.IS_SELF_DESTRUCT_ENABLED);
        COMMANDS.put("pf", CommandType.PUT_FILE);
        COMMANDS.put("pd", CommandType.PUT_DIRECTORY);
        COMMANDS.put("gf", CommandType.GET_FILE);
        COMMANDS.put("gd", CommandType.GET_DIRECTORY);
        COMMANDS.put("gfl", CommandType.GET_FILES_LIST);
        COMMANDS.put("cfn", CommandType.CHANGE_FILE_NAME);
        COMMANDS.put("df", CommandType.DELETE_FILE);
        COMMANDS.put("md", CommandType.MAKE_DIRECTORY);
        COMMANDS.put("dd", CommandType.DELETE_DIRECTORY);
        COMMANDS.put("aaft", CommandType.ABORT_ALL_FILE_TRANSFERS);
        COMMANDS.put("pp", CommandType.PUT_PASSWORD);
        COMMANDS.put("gp", CommandType.GET_PASSWORD);
        COMMANDS.put("dp", CommandType.DELETE_PASSWORD);
        COMMANDS.put("sp", CommandType.SEARCH_PASSWORD);
        COMMANDS.put("dap", CommandType.DELETE_ALL_PASSWORDS);
        COMMANDS.put("pak", CommandType.PUT_API_KEY);
        COMMANDS.put("gak", CommandType.GET_API_KEY);
        COMMANDS.put("dak", CommandType.DELETE_API_KEY);
        COMMANDS.put("sak", CommandType.SEARCH_API_KEY);
        COMMANDS.put("daak", CommandType.DELETE_ALL_API_KEYS);
        COMMANDS.put("gnopft", CommandType.GET_NUMBER_OF_PENDING_FILE_TRANSFERS);
        COMMANDS.put("gnofft", CommandType.GET_NUMBER_OF_FAILED_FILE_TRANSFERS);
        COMMANDS.put("gfftl", CommandType.GET_FAILED_FILE_TRANSFERS_LIST);
        COMMANDS.put("gftp", CommandType.GET_FILE_TRANSFER_PROGRESS);
        COMMANDS.put("gl", CommandType.GET_LOG);
        COMMANDS.put("cl", CommandType.CLEAR_LOGS);
    }

    private static void printUsageList() {
        for (String command : COMMANDS.keySet()) {
            IO.println(command + " => " + COMMANDS.get(command));
        }
    }

    private static String readConfidentialString() {
        Console console = System.console();
        if (console == null) {
            return IO.readln();
        }
        return new String(console.readPassword());
    }

    public static void start(String[] args) {
        try {
            int n = args.length, i = 0;
            String path = null;
            boolean create = true;
            String password;
            while (i < n) {
                if (args[i] != null) {
                    if (args[i].equals(VAULT_PATH_ARGUMENT)) {
                        if (i + 1 < n) {
                            path = args[i + 1];
                            create = false;
                            i++;
                        }
                    } else {
                        IO.println("Invalid argument [" + args[i] + "] .");
                        return;
                    }
                }
                i++;
            }
            if (path == null) {
                path = IO.readln("Enter the vault path: ");
                create = IO.readln("You want to create the vault, [yes|no] ? ").matches(CONFIRM_REGEX);
            }
            IO.println("Enter the password: ");
            password = readConfidentialString();
            if (create) {
                IO.println("Renter the password: ");
                if (!password.equals(readConfidentialString())) {
                    IO.println("Password didn't match.");
                    return;
                }
            }
            independentModeVaultStart(path, create, password.toCharArray());
        } catch (Exception e) {
            IO.println("Exception occurred in Secret Vault: " + e.getMessage());
        }
    }

    private static boolean confirmAction(CommandType usageCommand) {
        String reply = IO.readln("Do you really want to execute [" + usageCommand + "] , [yes|no] ?");
        return reply.matches(CONFIRM_REGEX);
    }

    private static void printTrieHierarchy(TrieNode trieNode, boolean root, String print) {
        if (root) {
            IO.println(" " + trieNode.name);
        }
        Collection<TrieNode> children = trieNode.getChildren();
        String currentPrint = print + HIERARCHY_SPACE_PER_DEPTH + "|";
        String lastChildPrint = print + HIERARCHY_SPACE_PER_DEPTH + " ";
        int i = 1;
        for (TrieNode child : children) {
            IO.println(currentPrint);
            IO.println(currentPrint + "->" + child.name);
            if (i++ == children.size()) {
                printTrieHierarchy(child, false, lastChildPrint);
            } else {
                printTrieHierarchy(child, false, currentPrint);
            }
        }
    }

    private static void addToTrie(TrieNode trieNode, String value, String split) {
        String[] values = value.split(split);
        for (String current : values) {
            trieNode = trieNode.child.computeIfAbsent(current, _ -> new TrieNode(current));
        }
    }

    private static TrieNode convertToTrie(List<String> values, String split) {
        TrieNode trieNode = new TrieNode("");
        for (String value : values) {
            addToTrie(trieNode, value, split);
        }
        return trieNode;
    }

    private static void printFilesList(List<String> filesList) {
        TrieNode trieNode = convertToTrie(filesList, Pattern.quote(File.separator));
        for (TrieNode child : trieNode.getChildren()) {
            printTrieHierarchy(child, true, "");
        }
    }

    private static void independentModeVaultStart(String path, boolean create, char[] password) throws Exception {
        Vault vault = new Vault(path, create, password, new FileManagerUpdateListener() {
            @Override
            public void setFileTransferMonitor(FileTransferMonitor fileTransferMonitor1) {
                fileTransferMonitor = fileTransferMonitor1;
            }

            @Override
            public int askForResponse(String query, List<String> options) {
                IO.println(query + "\nOptions:");
                int i = 1;
                for (String option : options) {
                    IO.println(i++ + ") " + option);
                }
                while (true) {
                    try {
                        return Integer.parseInt(IO.readln("Enter the option number: ")) - 1;
                    } catch (Exception _) {
                    }
                }
            }

            @Override
            public void newUpdate(String update) {
                IO.println("Update:\n" + update);
            }
        }, true);
        printUsageList();
        Logger logger = vault.getLogger();
        String option;
        while (!(option = IO.readln("Enter the option or [" + EXIT_COMMAND + "] to exit: ")).matches(EXIT_COMMAND_REGEX)) {
            IO.println();
            try {
                CommandType usageCommand = COMMANDS.get(option);
                if (usageCommand == null) {
                    printUsageList();
                } else {
                    switch (usageCommand) {
                        case VERSION -> IO.println(vault.getVersion());
                        case CHANGE_PASSWORD -> {
                            IO.println("Enter the current password: ");
                            char[] currentPassword = readConfidentialString().toCharArray();
                            IO.println("Enter the new password: ");
                            char[] newPassword = readConfidentialString().toCharArray();
                            IO.println("Renter the new password: ");
                            char[] recheckPassword = readConfidentialString().toCharArray();
                            boolean flag = newPassword.length == recheckPassword.length;
                            if (flag) {
                                for (int i = newPassword.length - 1; flag && i >= 0; i--) {
                                    flag = newPassword[i] == recheckPassword[i];
                                }
                            }
                            if (!flag) {
                                IO.println("New password mismatch. Try again.");
                            } else if (confirmAction(usageCommand)) {
                                vault.changeVaultPassword(currentPassword, newPassword);
                            }
                        }
                        case SELF_DESTRUCT -> {
                            IO.println("Enter the current password: ");
                            char[] currentPassword = readConfidentialString().toCharArray();
                            if (confirmAction(usageCommand)) {
                                vault.selfDestruct(currentPassword);
                            }
                        }
                        case LOCKDOWN -> {
                            try {
                                long seconds = Long.parseLong(IO.readln("Enter the lockdown duration in seconds: "));
                                if (confirmAction(usageCommand)) {
                                    vault.lockdownVault(seconds);
                                }
                            } catch (NumberFormatException _) {
                                IO.println("Invalid duration.");
                            }
                        }
                        case SET_SELF_DESTRUCT -> {
                            try {
                                int tries = Integer.parseInt(IO.readln("Enter the number of tries: "));
                                if (confirmAction(usageCommand)) {
                                    vault.setSelfDestruct(tries);
                                }
                            } catch (NumberFormatException _) {
                                IO.println("Invalid tries value.");
                            }
                        }
                        case GET_SELF_DESTRUCT_TRIES -> IO.println(vault.getSelfDestructTries());
                        case DISABLE_SELF_DESTRUCT -> {
                            if (confirmAction(usageCommand)) {
                                vault.disableSelfDestruct();
                            }
                        }
                        case IS_SELF_DESTRUCT_ENABLED -> IO.println(vault.isSelfDestructEnabled());
                        case PUT_FILE, PUT_DIRECTORY -> {
                            Path from = Path.of(IO.readln("From path: "));
                            Path to = Path.of(IO.readln("To path: "));
                            if (confirmAction(usageCommand)) {
                                if (usageCommand == CommandType.PUT_FILE) {
                                    vault.putFile(from, to);
                                } else {
                                    vault.putDirectory(from, to);
                                }
                            }
                        }
                        case GET_FILE, GET_DIRECTORY -> {
                            Path from = Path.of(IO.readln("From path: "));
                            Path to = Path.of(IO.readln("To path: "));
                            if (confirmAction(usageCommand)) {
                                if (usageCommand == CommandType.GET_FILE) {
                                    vault.getFile(from, to);
                                } else {
                                    vault.getDirectory(from, to);
                                }
                            }
                        }
                        case GET_FILES_LIST -> {
                            Path path1 = Path.of(IO.readln("Enter the path: "));
                            int depth = Integer.parseInt(IO.readln("Enter the depth (-1 to list all Files) : "));
                            IO.println("Files:");
                            printFilesList(vault.getFilesList(path1, depth));
                        }
                        case CHANGE_FILE_NAME -> {
                            Path filePath = Path.of(IO.readln("File path: "));
                            String newName = IO.readln("Enter the new name: ");
                            if (confirmAction(usageCommand)) {
                                vault.changeFileName(filePath, newName);
                            }
                        }
                        case DELETE_FILE -> {
                            Path filePath = Path.of(IO.readln("Path of file to delete: "));
                            if (confirmAction(usageCommand)) {
                                vault.deleteFile(filePath);
                            }
                        }
                        case MAKE_DIRECTORY -> {
                            Path filePath = Path.of(IO.readln("Path of directory to make: "));
                            if (confirmAction(usageCommand)) {
                                vault.makeDirectory(filePath);
                            }
                        }
                        case DELETE_DIRECTORY -> {
                            Path filePath = Path.of(IO.readln("Path of directory to delete: "));
                            if (confirmAction(usageCommand)) {
                                vault.deleteDirectory(filePath);
                            }
                        }
                        case ABORT_ALL_FILE_TRANSFERS -> {
                            if (confirmAction(usageCommand)) {
                                vault.abortAllFileTransfers();
                            }
                        }
                        case PUT_PASSWORD -> {
                            String name = IO.readln("Name of password: ");
                            IO.println("Enter the password: ");
                            String value = readConfidentialString();
                            vault.putPassword(name, value);
                        }
                        case GET_PASSWORD -> {
                            String value = vault.getPassword(IO.readln("Enter the name: "));
                            String printString = "The password is: \"" + value + "\".\nWhen you are done, press enter so that screen can be cleared.";
                            IO.readln(printString);
                            IO.println("\033[2J\033[H");
                        }
                        case DELETE_PASSWORD -> {
                            String name = IO.readln("Enter the name: ");
                            if (confirmAction(usageCommand)) {
                                vault.deletePassword(name);
                            }
                        }
                        case SEARCH_PASSWORD -> IO.println(vault.searchPassword(IO.readln("Enter the prefix: ")));
                        case DELETE_ALL_PASSWORDS -> {
                            if (confirmAction(usageCommand)) {
                                vault.clearAllStoredPasswords();
                            }
                        }
                        case PUT_API_KEY -> {
                            String name = IO.readln("Name of API Key: ");
                            IO.println("Enter the API Key: ");
                            String value = readConfidentialString();
                            vault.putAPIKey(name, value);
                        }
                        case GET_API_KEY -> {
                            String value = vault.getAPIKey(IO.readln("Enter the name: "));
                            String printString = "The API Key is: \"" + value + "\".\nWhen you are done, press enter so that screen can be cleared.";
                            IO.readln(printString);
                            IO.println("\033[2J\033[H");
                        }
                        case DELETE_API_KEY -> {
                            String name = IO.readln("Enter the name: ");
                            if (confirmAction(usageCommand)) {
                                vault.deleteAPIKey(name);
                            }
                        }
                        case SEARCH_API_KEY -> IO.println(vault.searchAPIKey(IO.readln("Enter the prefix: ")));
                        case DELETE_ALL_API_KEYS -> {
                            if (confirmAction(usageCommand)) {
                                vault.clearAllStoredAPIKeys();
                            }
                        }
                        case GET_NUMBER_OF_PENDING_FILE_TRANSFERS ->
                                IO.println(fileTransferMonitor.getNumberOfPendingFileTransfers());
                        case GET_NUMBER_OF_FAILED_FILE_TRANSFERS ->
                                IO.println(fileTransferMonitor.getNumberOfFailedFileTransfers());
                        case GET_FAILED_FILE_TRANSFERS_LIST ->
                                IO.println(fileTransferMonitor.getFailedFileTransfersList());
                        case GET_FILE_TRANSFER_PROGRESS ->
                                IO.println(fileTransferMonitor.getFileTransferProgress() + "%");
                        case GET_LOG -> {
                            try {
                                int number = Integer.parseInt(IO.readln("Enter the number of last logs lines you want to see: "));
                                IO.println(logger.getLogs(number));
                            } catch (NumberFormatException _) {
                                IO.println("Invalid number of lines.");
                            }
                        }
                        case CLEAR_LOGS -> {
                            if (confirmAction(usageCommand)) {
                                vault.clearLogs();
                            }
                        }
                    }
                }
            } catch (Exception e) {
                IO.println("Exception occurred : " + e);
            }
            IO.println();
        }
        vault.closeVault();
    }

    static class TrieNode {
        Map<String, TrieNode> child;
        String name;

        TrieNode(String name) {
            this.name = name;
            child = new LinkedHashMap<>();
        }

        Collection<TrieNode> getChildren() {
            return child.values();
        }
    }
}
