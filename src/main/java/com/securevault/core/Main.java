package com.securevault.core;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securevault.core.filehandlers.FileTransferMonitor;
import com.securevault.core.filehandlers.listeners.FileManagerUpdateListener;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.nio.file.Path;
import java.security.spec.KeySpec;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

enum CommandType {
    OPEN,
    IS_OPEN,
    CLOSE,
    VERSION,
    CHANGE_PASSWORD,
    SELF_DESTRUCT,
    LOCKDOWN,
    SET_SELF_DESTRUCT,
    GET_SELF_DESTRUCT_TRIES,
    DISABLE_SELF_DESTRUCT,
    IS_SELF_DESTRUCT_ENABLED,
    PUT_FILE,
    PUT_DIRECTORY,
    GET_FILE,
    GET_DIRECTORY,
    GET_FILES_LIST,
    CHANGE_FILE_NAME,
    DELETE_FILE,
    MAKE_DIRECTORY,
    DELETE_DIRECTORY,
    ABORT_ALL_FILE_TRANSFERS,
    PUT_PASSWORD,
    GET_PASSWORD,
    DELETE_PASSWORD,
    SEARCH_PASSWORD,
    DELETE_ALL_PASSWORDS,
    PUT_API_KEY,
    GET_API_KEY,
    DELETE_API_KEY,
    SEARCH_API_KEY,
    DELETE_ALL_API_KEYS,
    RESPONSE,
    GET_NUMBER_OF_PENDING_FILE_TRANSFERS,
    GET_NUMBER_OF_FAILED_FILE_TRANSFERS,
    GET_FAILED_FILE_TRANSFERS_LIST,
    GET_FILE_TRANSFER_PROGRESS,
    GET_LOG,
    CLEAR_LOGS
}

enum OutputType {
    ERROR,
    INVALID_COMMAND,
    RESPONSE,
    UPDATE,
}

public class Main implements FileManagerUpdateListener {
    private static final Map<String, UsageCommand> COMMANDS = new LinkedHashMap<>();
    private static final String DEPENDENT_MODE_ARGUMENT = "-d";
    private static final String EXIT_COMMAND = "EXIT";
    private static final int ITERATIONS = 100000;
    private static final int KEY_LENGTH = 256;
    private static final int TAG_SIZE = 128;
    private static final ObjectMapper jsonHandler = new ObjectMapper();
    private static final AtomicInteger responseId = new AtomicInteger(0);
    private static final AtomicBoolean shutdown = new AtomicBoolean(false);
    private static final ConcurrentHashMap<Integer, ResponseHandler> responseHandlers = new ConcurrentHashMap<>();
    private static final Base64.Encoder encoder = Base64.getEncoder();
    private static final Base64.Decoder decoder = Base64.getDecoder();
    private static Cipher encryptCipher;
    private static Cipher decryptCipher;
    private static FileTransferMonitor fileTransferMonitor;
    private static Vault vault;

    static {
        jsonHandler.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        COMMANDS.put("v", UsageCommand.VERSION);
        COMMANDS.put("cp", UsageCommand.CHANGE_PASSWORD);
        COMMANDS.put("sd", UsageCommand.SELF_DESTRUCT);
        COMMANDS.put("ld", UsageCommand.LOCKDOWN);
        COMMANDS.put("ssd", UsageCommand.SET_SELF_DESTRUCT);
        COMMANDS.put("gsdt", UsageCommand.GET_SELF_DESTRUCT_TRIES);
        COMMANDS.put("dsd", UsageCommand.DISABLE_SELF_DESTRUCT);
        COMMANDS.put("isde", UsageCommand.IS_SELF_DESTRUCT_ENABLED);
        COMMANDS.put("pf", UsageCommand.PUT_FILE);
        COMMANDS.put("pd", UsageCommand.PUT_DIRECTORY);
        COMMANDS.put("gf", UsageCommand.GET_FILE);
        COMMANDS.put("gd", UsageCommand.GET_DIRECTORY);
        COMMANDS.put("gfl", UsageCommand.GET_FILES_LIST);
        COMMANDS.put("cfn", UsageCommand.CHANGE_FILE_NAME);
        COMMANDS.put("df", UsageCommand.DELETE_FILE);
        COMMANDS.put("md", UsageCommand.MAKE_DIRECTORY);
        COMMANDS.put("dd", UsageCommand.DELETE_DIRECTORY);
        COMMANDS.put("aaft", UsageCommand.ABORT_ALL_FILE_TRANSFERS);
        COMMANDS.put("pp", UsageCommand.PUT_PASSWORD);
        COMMANDS.put("gp", UsageCommand.GET_PASSWORD);
        COMMANDS.put("dp", UsageCommand.DELETE_PASSWORD);
        COMMANDS.put("sp", UsageCommand.SEARCH_PASSWORD);
        COMMANDS.put("dap", UsageCommand.DELETE_ALL_PASSWORDS);
        COMMANDS.put("pak", UsageCommand.PUT_API_KEY);
        COMMANDS.put("gak", UsageCommand.GET_API_KEY);
        COMMANDS.put("dak", UsageCommand.DELETE_API_KEY);
        COMMANDS.put("sak", UsageCommand.SEARCH_API_KEY);
        COMMANDS.put("daak", UsageCommand.DELETE_ALL_API_KEYS);
        COMMANDS.put("gnopft", UsageCommand.GET_NUMBER_OF_PENDING_FILE_TRANSFERS);
        COMMANDS.put("gnofft", UsageCommand.GET_NUMBER_OF_FAILED_FILE_TRANSFERS);
        COMMANDS.put("gfftl", UsageCommand.GET_FAILED_FILE_TRANSFERS_LIST);
        COMMANDS.put("gftp", UsageCommand.GET_FILE_TRANSFER_PROGRESS);
        COMMANDS.put("gl", UsageCommand.GET_LOGS);
        COMMANDS.put("cl", UsageCommand.CLEAR_LOGS);
    }

    static void main(String[] args) {
        boolean dependentMode = false;
        if (args != null) {
            for (String s : args) {
                if (s != null && s.equals(DEPENDENT_MODE_ARGUMENT)) {
                    dependentMode = true;
                    break;
                }
            }
        }
        if (dependentMode) {
            dependentMode();
        } else {
            independentMode();
        }
    }

    private static void independentMode() {
        try {
            String path = System.getProperty("user.dir");
            boolean create = false;
            String password = "WORLD";
            //path = IO.readln("Enter the vault path: ");
            //create = Boolean.parseBoolean(IO.readln("You want to create the vault? "));
            //password = IO.readln("Enter the password: ");
            independentModeVaultStart(path, create, password.toCharArray());
        } catch (Exception e) {
            IO.println("Exception occurred while opening the vault: " + e);
        }
    }

    private static void printUsageList() {
        for (String command : COMMANDS.keySet()) {
            IO.println(command + " => " + COMMANDS.get(command));
        }
    }

    private static boolean confirmAction(UsageCommand usageCommand) {
        String reply = IO.readln("Do you really want to execute [" + usageCommand + "] ? [Y|N] ?");
        return reply.matches("[yY]");
    }

    private static String readConfidentialString() {
        Console console = System.console();
        if (console == null) {
            return IO.readln();
        }
        return new String(console.readPassword());
    }

    private static void independentModeVaultStart(String path, boolean create, char[] password) throws Exception {
        Vault vault = new Vault(path, create, password, new FileManagerUpdateListener() {
            @Override
            public void setFileTransferMonitor(FileTransferMonitor fileTransferMonitor1) {
                fileTransferMonitor = fileTransferMonitor1;
            }

            @Override
            public int askForResponse(String query, List<String> options) {
                String printQuery = query + "\nOptions (enter 0th based index of the option):\n" + options;
                while (true) {
                    try {
                        return Integer.parseInt(IO.readln(printQuery));
                    } catch (Exception _) {
                    }
                }
            }

            @Override
            public void newUpdate(String update) {
                IO.println("Update:\n" + update);
            }
        });
        printUsageList();
        Logger logger = vault.getLogger();
        String option;
        while (!(option = IO.readln("Enter the option or [" + EXIT_COMMAND + "] to exit: ")).equals(EXIT_COMMAND)) {
            IO.println();
            try {
                UsageCommand usageCommand = COMMANDS.get(option);
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
                                if (usageCommand == UsageCommand.PUT_FILE) {
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
                                if (usageCommand == UsageCommand.GET_FILE) {
                                    vault.getFile(from, to);
                                } else {
                                    vault.getDirectory(from, to);
                                }
                            }
                        }
                        case GET_FILES_LIST -> IO.println(vault.getFilesList(Path.of(IO.readln("Enter the path: "))));
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
                        case GET_FILE_TRANSFER_PROGRESS -> IO.println(fileTransferMonitor.getFileTransferProgress());
                        case GET_LOGS -> {
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

    private static void dependentMode() {
        char[] password = IO.readln().toCharArray();
        byte[] iv = decoder.decode(IO.readln());
        byte[] salt = decoder.decode(IO.readln());
        try {
            initHandles(password, iv, salt);
        } catch (Exception e) {
            IO.println(e.toString());
        }
    }

    private static Cipher getCipher(char[] password, byte[] iv, byte[] salt, int mode) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec keySpec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(TAG_SIZE, iv);
        cipher.init(mode, secretKeySpec, gcmParameterSpec);
        return cipher;
    }

    private static void initHandles(char[] password, byte[] iv, byte[] salt) throws Exception {
        encryptCipher = getCipher(password, iv, salt, Cipher.ENCRYPT_MODE);
        decryptCipher = getCipher(password, iv, salt, Cipher.DECRYPT_MODE);
        Thread.startVirtualThread(() -> {
            while (!shutdown.get()) {
                try {
                    String data = IO.readln();
                    String decryptedData = decryptData(data);
                    Command command = jsonHandler.readValue(decryptedData, Command.class);
                    handleCommand(command);
                } catch (Exception e) {
                    sendOutput(new Output(OutputType.ERROR, -1, List.of(e.toString())));
                }
            }
        });
    }

    private static String encryptData(String data) throws Exception {
        byte[] encryptedData = encryptCipher.doFinal(data.getBytes());
        return encoder.encodeToString(encryptedData);
    }

    private static String decryptData(String data) throws Exception {
        byte[] decodedData = decoder.decode(data);
        return new String(decryptCipher.doFinal(decodedData));
    }

    private static boolean validNumberOfArguments(Command command, int numberOfArguments) {
        if (command.args() == null || command.args().size() != numberOfArguments) {
            sendInvalidCommandInfo(command);
            return false;
        }
        return true;
    }

    private static void handleCommand(Command command) {
        CommandType commandType = command.type();
        List<String> args = command.args();
        try {
            if (commandType == CommandType.OPEN) {
                if (vault != null && vault.isVaultOpen()) {
                    sendOutput(new Output(OutputType.ERROR, command.commandId(), List.of("Vault is already open.")));
                } else if (validNumberOfArguments(command, 3)) {
                    String path = args.get(0);
                    boolean create = Boolean.parseBoolean(args.get(1));
                    char[] password = args.get(2).toCharArray();
                    try {
                        vault = new Vault(path, create, password, new Main());
                        sendOutput(new Output(OutputType.RESPONSE, command.commandId(), List.of("Vault opened.")));
                    } catch (Exception e) {
                        sendOutput(new Output(OutputType.ERROR, command.commandId(), List.of(e.getMessage())));
                    }
                }
            } else if (vault == null || !vault.isVaultOpen()) {
                sendOutput(new Output(OutputType.ERROR, command.commandId(), List.of("Vault is not open.")));
            } else {
                switch (commandType) {
                    case IS_OPEN ->
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId(), List.of(Boolean.toString(vault.isVaultOpen()))));
                    case CLOSE -> {
                        vault.closeVault();
                        sendOutput(new Output(OutputType.RESPONSE, command.commandId(), List.of("Vault closed.")));
                        shutdown.set(true);
                    }
                    case VERSION ->
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId(), List.of(vault.getVersion())));
                    case CHANGE_PASSWORD -> {
                        if (validNumberOfArguments(command, 2)) {
                            String oldPassword = args.get(0);
                            String newPassword = args.get(1);
                            Output output;
                            try {
                                vault.changeVaultPassword(oldPassword.toCharArray(), newPassword.toCharArray());
                                output = new Output(OutputType.RESPONSE, command.commandId(), List.of(Boolean.toString(true)));
                            } catch (Exception e) {
                                output = new Output(OutputType.ERROR, command.commandId(), List.of(Boolean.toString(false), e.getMessage()));
                            }
                            sendOutput(output);
                        }
                    }
                    case SELF_DESTRUCT -> {
                        if (validNumberOfArguments(command, 1)) {
                            String password = args.getFirst();
                            vault.selfDestruct(password.toCharArray());
                        }
                    }
                    case LOCKDOWN -> {
                        if (validNumberOfArguments(command, 1)) {
                            try {
                                long duration = Long.parseLong(args.getFirst());
                                vault.lockdownVault(duration);
                            } catch (Exception _) {
                                sendInvalidCommandInfo(command);
                            }
                        }
                    }
                    case SET_SELF_DESTRUCT -> {
                        if (validNumberOfArguments(command, 1)) {
                            try {
                                int tries = Integer.parseInt(args.getFirst());
                                vault.setSelfDestruct(tries);
                            } catch (Exception _) {
                                sendInvalidCommandInfo(command);
                            }
                        }
                    }
                    case GET_SELF_DESTRUCT_TRIES ->
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId(), List.of(Integer.toString(vault.getSelfDestructTries()))));
                    case DISABLE_SELF_DESTRUCT -> vault.disableSelfDestruct();
                    case IS_SELF_DESTRUCT_ENABLED ->
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId(), List.of(Boolean.toString(vault.isSelfDestructEnabled()))));
                    case PUT_FILE, PUT_DIRECTORY -> {
                        if (validNumberOfArguments(command, 2)) {
                            Path from = Path.of(args.getFirst());
                            Path to = Path.of(args.get(1));
                            if (commandType == CommandType.PUT_FILE) {
                                vault.putFile(from, to);
                            } else {
                                vault.putDirectory(from, to);
                            }
                        }
                    }
                    case GET_FILE, GET_DIRECTORY -> {
                        if (validNumberOfArguments(command, 2)) {
                            Path from = Path.of(args.getFirst());
                            Path to = Path.of(args.get(1));
                            if (commandType == CommandType.GET_FILE) {
                                vault.getFile(from, to);
                            } else {
                                vault.getDirectory(from, to);
                            }
                        }
                    }
                    case GET_FILES_LIST -> {
                        if (validNumberOfArguments(command, 1)) {
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId(), vault.getFilesList(Path.of(args.getFirst()))));
                        }
                    }
                    case CHANGE_FILE_NAME -> {
                        if (validNumberOfArguments(command, 2)) {
                            Path from = Path.of(args.getFirst());
                            String newName = args.get(1);
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId(), List.of(Boolean.toString(vault.changeFileName(from, newName)))));
                        }
                    }
                    case DELETE_FILE -> {
                        if (validNumberOfArguments(command, 1)) {
                            Path path = Path.of(args.getFirst());
                            vault.deleteFile(path);
                        }
                    }
                    case MAKE_DIRECTORY -> {
                        if (validNumberOfArguments(command, 1)) {
                            Path path = Path.of(args.getFirst());
                            vault.makeDirectory(path);
                        }
                    }
                    case DELETE_DIRECTORY -> {
                        if (validNumberOfArguments(command, 1)) {
                            Path path = Path.of(args.getFirst());
                            vault.deleteDirectory(path);
                        }
                    }
                    case ABORT_ALL_FILE_TRANSFERS -> vault.abortAllFileTransfers();
                    case RESPONSE -> {
                        if (validNumberOfArguments(command, 2)) {
                            try {
                                int responseId = Integer.parseInt(args.getFirst());
                                String response = args.get(1);
                                ResponseHandler responseHandler = responseHandlers.get(responseId);
                                if (responseHandler != null) {
                                    responseHandler.setResponse(response);
                                }
                            } catch (Exception _) {
                                sendInvalidCommandInfo(command);
                            }
                        }
                    }
                    case GET_NUMBER_OF_PENDING_FILE_TRANSFERS ->
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId(), List.of(Integer.toString(fileTransferMonitor.getNumberOfPendingFileTransfers()))));
                    case GET_NUMBER_OF_FAILED_FILE_TRANSFERS ->
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId(), List.of(Integer.toString(fileTransferMonitor.getNumberOfFailedFileTransfers()))));
                    case GET_FAILED_FILE_TRANSFERS_LIST ->
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId(), fileTransferMonitor.getFailedFileTransfersList()));
                    case GET_FILE_TRANSFER_PROGRESS ->
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId(), List.of(Double.toString(fileTransferMonitor.getFileTransferProgress()))));
                    case PUT_PASSWORD -> {
                        if (validNumberOfArguments(command, 2)) {
                            vault.putPassword(args.getFirst(), args.get(1));
                        }
                    }
                    case GET_PASSWORD -> {
                        if (validNumberOfArguments(command, 1)) {
                            String response = vault.getPassword(args.getFirst());
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId(), List.of(response)));
                        }
                    }
                    case DELETE_PASSWORD -> {
                        if (validNumberOfArguments(command, 1)) {
                            vault.deletePassword(args.getFirst());
                        }
                    }
                    case SEARCH_PASSWORD -> {
                        if (validNumberOfArguments(command, 1)) {
                            Set<String> result = vault.searchPassword(args.getFirst());
                            sendOutput(new Output(OutputType.ERROR, command.commandId(), result.stream().toList()));
                        }
                    }
                    case DELETE_ALL_PASSWORDS -> vault.clearAllStoredPasswords();
                    case PUT_API_KEY -> {
                        if (validNumberOfArguments(command, 2)) {
                            vault.putAPIKey(args.getFirst(), args.get(1));
                        }
                    }
                    case GET_API_KEY -> {
                        if (validNumberOfArguments(command, 1)) {
                            String response = vault.getAPIKey(args.getFirst());
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId(), List.of(response)));
                        }
                    }
                    case DELETE_API_KEY -> {
                        if (validNumberOfArguments(command, 1)) {
                            vault.deleteAPIKey(args.getFirst());
                        }
                    }
                    case SEARCH_API_KEY -> {
                        if (validNumberOfArguments(command, 1)) {
                            Set<String> result = vault.searchAPIKey(args.getFirst());
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId(), result.stream().toList()));
                        }
                    }
                    case DELETE_ALL_API_KEYS -> vault.clearAllStoredAPIKeys();
                    case GET_LOG -> {
                        if (validNumberOfArguments(command, 1)) {
                            try {
                                int count = Integer.parseInt(args.getFirst());
                                sendOutput(new Output(OutputType.RESPONSE, command.commandId(), List.of(vault.getLogger().getLogs(count))));
                            } catch (Exception e) {
                                sendInvalidCommandInfo(command);
                            }
                        }
                    }
                    case CLEAR_LOGS -> vault.clearLogs();
                }
            }
        } catch (Exception e) {
            sendOutput(new Output(OutputType.ERROR, command.commandId(), List.of(e.getMessage())));
        }
    }

    private static void sendInvalidCommandInfo(Command command) {
        sendOutput(new Output(OutputType.INVALID_COMMAND, command.commandId(), List.of("Invalid command.")));
    }

    private static synchronized void sendOutput(Output output) {
        try {
            String responseJSON = jsonHandler.writeValueAsString(output);
            String encrypted = encryptData(responseJSON);
            IO.println(encrypted);
        } catch (Exception _) {
        }
    }

    private static ResponseHandler registerResponseHandler(int id) {
        ResponseHandler responseHandler = new ResponseHandler();
        responseHandlers.put(id, responseHandler);
        return responseHandler;
    }

    @Override
    public void setFileTransferMonitor(FileTransferMonitor newFileTransferMonitor) {
        fileTransferMonitor = newFileTransferMonitor;
    }

    @Override
    public int askForResponse(String query, List<String> options) {
        int id = responseId.getAndIncrement();
        List<String> list = new LinkedList<>();
        list.add(Integer.toString(id));
        list.add(query);
        list.addAll(options);
        ResponseHandler responseHandler = registerResponseHandler(id);
        sendOutput(new Output(OutputType.RESPONSE, -1, list));
        String response = responseHandler.getResponse();
        int n = options.size();
        for (int i = 0; i < n; i++) {
            if (options.get(i).equals(response)) {
                return i;
            }
        }
        return 0;
    }

    @Override
    public void newUpdate(String update) {
        sendOutput(new Output(OutputType.UPDATE, 0, List.of(update)));
    }

    enum UsageCommand {
        VERSION,
        CHANGE_PASSWORD,
        SELF_DESTRUCT,
        LOCKDOWN,
        SET_SELF_DESTRUCT,
        GET_SELF_DESTRUCT_TRIES,
        DISABLE_SELF_DESTRUCT,
        IS_SELF_DESTRUCT_ENABLED,
        PUT_FILE,
        PUT_DIRECTORY,
        GET_FILE,
        GET_DIRECTORY,
        GET_FILES_LIST,
        CHANGE_FILE_NAME,
        DELETE_FILE,
        MAKE_DIRECTORY,
        DELETE_DIRECTORY,
        ABORT_ALL_FILE_TRANSFERS,
        PUT_PASSWORD,
        GET_PASSWORD,
        DELETE_PASSWORD,
        SEARCH_PASSWORD,
        DELETE_ALL_PASSWORDS,
        PUT_API_KEY,
        GET_API_KEY,
        DELETE_API_KEY,
        SEARCH_API_KEY,
        DELETE_ALL_API_KEYS,
        GET_NUMBER_OF_PENDING_FILE_TRANSFERS,
        GET_NUMBER_OF_FAILED_FILE_TRANSFERS,
        GET_FAILED_FILE_TRANSFERS_LIST,
        GET_FILE_TRANSFER_PROGRESS,
        GET_LOGS,
        CLEAR_LOGS,
    }
}

record Command(CommandType type, int commandId, List<String> args) {
}

record Output(OutputType type, int commandId, List<String> args) {
}

class ResponseHandler {
    private final CompletableFuture<String> response = new CompletableFuture<>();

    public String getResponse() {
        try {
            return response.get();
        } catch (Exception _) {
            return "";
        }
    }

    public void setResponse(String response) {
        this.response.complete(response);
    }
}