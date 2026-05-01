package com.securevault.core;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securevault.core.filehandlers.FileTransferMonitor;
import com.securevault.core.filehandlers.listeners.FileManagerUpdateListener;

import java.nio.file.Path;
import java.util.List;

public class Main implements FileManagerUpdateListener {
    private static FileTransferMonitor fileTransferMonitor;
    private static final ObjectMapper jsonHandler = new ObjectMapper();
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
        String option;
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
        }
        vault.closeVault();
    }

    private static void handleCommand(Command command) throws Exception {
        CommandType commandType = command.type();
        List<String> args = command.args();
        if (commandType == CommandType.OPEN) {
        } else if (vault == null || !vault.isVaultOpen()) {
            sendOutput(new Output(OutputType.RESPONSE, commandType, List.of("Vault is not open.")));
        } else {
            switch (commandType) {
                case IS_OPEN ->
                        sendOutput(new Output(OutputType.RESPONSE, commandType, List.of(Boolean.toString(vault.isVaultOpen()))));
                case CLOSE -> {
                    vault.closeVault();
                    sendOutput(new Output(OutputType.RESPONSE, commandType, List.of("Vault closed.")));
                }
                case VERSION -> sendOutput(new Output(OutputType.RESPONSE, commandType, List.of(vault.getVersion())));
                case CHANGE_PASSWORD -> {
                    if (args.size() != 2) {
                        sendInvalidCommandInfo(command);
                    } else {
                        String oldPassword = args.get(0);
                        String newPassword = args.get(1);
                        Output output;
                        try {
                            vault.changeVaultPassword(oldPassword.toCharArray(), newPassword.toCharArray());
                            output = new Output(OutputType.RESPONSE, commandType, List.of(Boolean.toString(true)));
                        } catch (Exception e) {
                            output = new Output(OutputType.RESPONSE, commandType, List.of(Boolean.toString(false), e.getMessage()));
                        }
                        sendOutput(output);
                    }
                }
                case SELF_DESTRUCT -> {
                    if (args.size() != 1) {
                        sendInvalidCommandInfo(command);
                    } else {
                    }
                }
                case LOCKDOWN -> {
                }
                case SET_SELF_DESTRUCT -> {
                }
                case GET_SELF_DESTRUCT_TRIES -> {
                }
                case DISABLE_SELF_DESTRUCT -> {
                }
                case IS_SELF_DESTRUCT_ENABLED -> {
                }
                case PUT_FILE -> {
                }
                case GET_FILE -> {
                }
                case GET_FILES_LIST -> {
                }
                case CHANGE_FILE_NAME -> {
                }
                case DELETE_FILE -> {
                }
                case DELETE_DIRECTORY -> {
                }
                case ABORT_ALL_FILE_TRANSFERS -> {
                }
                case RESPONSE -> {
                }
                case GET_NUMBER_OF_PENDING_FILE_TRANSFERS -> {
                }
                case GET_NUMBER_OF_FAILED_FILE_TRANSFERS -> {
                }
                case GET_FAILED_FILE_TRANSFERS_LIST -> {
                }
                case GET_FILE_TRANSFER_PROGRESS -> {
                }
            }
        }
    }

    private static void sendInvalidCommandInfo(Command command) {
        sendOutput(new Output(OutputType.INVALID, command.type(), List.of("Invalid command.")));
    }

    private static void sendOutput(Output output) {
        try {
            String responseJSON = jsonHandler.writeValueAsString(output);
        } catch (Exception _) {
        }
    }

    @Override
    public void setFileTransferMonitor(FileTransferMonitor newFileTransferMonitor) {
        fileTransferMonitor = newFileTransferMonitor;
    }

    @Override
    public int askForResponse(String query, List<String> options) {
        return 0;
    }

    @Override
    public void newUpdate(String update) {
    }
}

record Command(CommandType type, List<String> args) {
}

record Output(OutputType type, CommandType commandType, List<String> args) {
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