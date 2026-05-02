package com.securevault.core;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securevault.core.filehandlers.FileTransferMonitor;
import com.securevault.core.filehandlers.listeners.FileManagerUpdateListener;

import java.nio.file.Path;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class Main implements FileManagerUpdateListener {
    private static FileTransferMonitor fileTransferMonitor;
    private static final ObjectMapper jsonHandler = new ObjectMapper();
    private static final AtomicInteger responseId = new AtomicInteger(0);
    private static final ConcurrentHashMap<Integer, ResponseHandler> responseHandlers = new ConcurrentHashMap<>();
    private static Vault vault;

    static {
        jsonHandler.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    static void main(String[] args) throws Exception {
        IO.println(jsonHandler.writeValueAsString(CommandType.IS_SELF_DESTRUCT_ENABLED));
        String password = "WORLD";
        String password1 = "Hello";
        FileManagerUpdateListener fileManagerUpdateListener = new FileManagerUpdateListener() {
            @Override
            public void setFileTransferMonitor(FileTransferMonitor fileTransferMonitor) {
            }

            @Override
            public int askForResponse(String query, List<String> options) {
                return Integer.parseInt(IO.readln(query + "\nOptions:\n" + options));
            }

            @Override
            public void newUpdate(String update) {
                IO.println("Update:\n" + update);
            }
        };
        //Vault vault = new Vault(System.getProperty("user.dir"), true, password.toCharArray(), fileManagerUpdateListener);
        Vault vault = new Vault(System.getProperty("user.dir") + "/Secure Vault", false, password.toCharArray(), fileManagerUpdateListener);
        Logger logger = vault.getLogger();
        //vault.changeVaultPassword(password.toCharArray(), password1.toCharArray());
        String option;/*
        while (!(option = IO.readln("Enter the option:")).equals("E")) {
            try {
                switch (option) {
                    case "pf" -> vault.putFiles(Path.of(IO.readln("Path:")));
                    case "gf" -> vault.getFiles(Path.of(IO.readln("From:")), Path.of(IO.readln("To:")));
                    case "df" -> vault.deleteFile(Path.of(IO.readln("Path:")));
                    case "dd" -> vault.deleteDirectory(Path.of(IO.readln("Path:")));
                    case "gl" -> IO.println(vault.getFilesList());
                    case "cl" -> logger.clearLogs();
                    case "l" -> IO.println(logger.getLogs(200));
                    case "ab" -> vault.abortAllFileTransfers();
                }
            } catch (Exception e) {
                IO.println(e);
            }
        }*/
        vault.closeVault();
    }

    private static boolean validNumberOfArguments(Command command, int numberOfArguments) {
        if (command.args() == null || command.args().size() != numberOfArguments) {
            sendInvalidCommandInfo(command);
            return false;
        }
        return true;
    }

    private static void handleCommand(Command command) throws Exception {
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
                    case PUT_FILE -> {
                        if (validNumberOfArguments(command, 2)) {
                            Path from = Path.of(args.getFirst());
                            Path to = Path.of(args.get(1));
                            vault.putFiles(from, to);
                        }
                    }
                    case GET_FILE -> {
                        if (validNumberOfArguments(command, 2)) {
                            Path from = Path.of(args.getFirst());
                            Path to = Path.of(args.get(1));
                            vault.getFiles(from, to);
                        }
                    }
                    case GET_FILES_LIST ->
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId(), vault.getFilesList()));
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
                }
            }
        } catch (Exception e) {
            sendOutput(new Output(OutputType.ERROR, command.commandId(), List.of(e.getMessage())));
        }
    }

    private static void sendInvalidCommandInfo(Command command) {
        sendOutput(new Output(OutputType.INVALID, command.commandId(), List.of("Invalid command.")));
    }

    private static void sendOutput(Output output) {
        try {
            String responseJSON = jsonHandler.writeValueAsString(output);
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
        sendOutput(new Output(OutputType.RESPONSE, 0, list));
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
}

record Command(CommandType type, int commandId, List<String> args) {
}

record Output(OutputType type, int commandId, List<String> args) {
}

enum CommandType {
    INVALID,
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
    GET_FILE,
    GET_FILES_LIST,
    CHANGE_FILE_NAME,
    DELETE_FILE,
    DELETE_DIRECTORY,
    ABORT_ALL_FILE_TRANSFERS,
    RESPONSE,
    GET_NUMBER_OF_PENDING_FILE_TRANSFERS,
    GET_NUMBER_OF_FAILED_FILE_TRANSFERS,
    GET_FAILED_FILE_TRANSFERS_LIST,
    GET_FILE_TRANSFER_PROGRESS,
}

enum OutputType {
    ERROR,
    INVALID,
    RESPONSE,
    UPDATE,
}

class ResponseHandler {
    private final CompletableFuture<String> response = new CompletableFuture<>();

    ResponseHandler() {
    }

    public void setResponse(String response) {
        this.response.complete(response);
    }

    public String getResponse() {
        try {
            return this.response.get();
        } catch (Exception _) {
            return null;
        }
    }
}