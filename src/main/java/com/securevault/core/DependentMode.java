package com.securevault.core;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securevault.core.filehandlers.FileTransferMonitor;
import com.securevault.core.filehandlers.listeners.FileManagerListener;
import com.securevault.core.keyhandlers.KeyType;
import com.securevault.core.keyhandlers.WebsiteIdPair;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Path;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

enum OutputType {
    ERROR,
    INVALID_COMMAND,
    RESPONSE,
    QUERY,
    UPDATE_FILE_ADDED,
    UPDATE_FILE_TRANSFER_FAILED,
}

public class DependentMode implements FileManagerListener {
    private static final String ERROR_STRING = "ERROR;";
    private static final String IMMEDIATE_SHUTDOWN = "SHUTDOWN";
    private static final Semaphore lock = new Semaphore(1, true);
    private static final Base64.Encoder base64Encoder = Base64.getEncoder();
    private static final Base64.Decoder base64Decoder = Base64.getDecoder();
    private static final ObjectMapper jsonHandler = new ObjectMapper();
    private static final AtomicInteger responseId = new AtomicInteger(0);
    private static final AtomicBoolean shutdown = new AtomicBoolean(false);
    private static final ConcurrentHashMap<Integer, ResponseHandler> responseHandlers = new ConcurrentHashMap<>();
    private static final String OUTPUT_PARTITIONER = ";";
    private static int iterations;
    private static int keyLength;
    private static int tagLength;
    private static byte[] iv;
    private static SecretKeySpec secretKeySpec;
    private static Cipher encryptCipher;
    private static Cipher decryptCipher;
    private static FileTransferMonitor fileTransferMonitor;
    private static Vault vault;

    static {
        jsonHandler.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    private static void lock() {
        try {
            lock.acquire();
        } catch (Exception _) {
        }
    }

    private static void unlock() {
        lock.release();
    }

    private static void directlyPrintError(String message) {
        IO.println(ERROR_STRING + message);
    }

    public static void start(IPCSpec ipcSpec) {
        iterations = ipcSpec.iterations();
        keyLength = ipcSpec.keyLength();
        tagLength = ipcSpec.tagLength();
        iv = new byte[ipcSpec.ivLength()];
        for (int i = iv.length - 1; i >= 0; i--) {
            iv[i] = -128;
        }
        try {
            initHandles(ipcSpec);
        } catch (Exception e) {
            directlyPrintError(e.getMessage());
        }
    }

    private static void initHandles(IPCSpec ipcSpec) throws Exception {
        char[] password = new String(base64Decoder.decode(ipcSpec.password())).toCharArray();
        byte[] salt = base64Decoder.decode(ipcSpec.salt());
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(ipcSpec.secretKeyFactoryAlgorithm());
        KeySpec keySpec = new PBEKeySpec(password, salt, iterations, keyLength);
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        secretKeySpec = new SecretKeySpec(secretKey.getEncoded(), ipcSpec.secretKeySpecAlgorithm());
        encryptCipher = Cipher.getInstance(ipcSpec.cipherTransformation());
        decryptCipher = Cipher.getInstance(ipcSpec.cipherTransformation());
        new Thread(() -> {
            while (!shutdown.get()) {
                try {
                    String data = IO.readln();
                    if (data.equals(IMMEDIATE_SHUTDOWN)) {
                        if (vault != null && vault.isVaultOpen()) {
                            try {
                                vault.closeVault();
                            } catch (Exception _) {
                            }
                        }
                        shutdown.set(true);
                        continue;
                    }
                    String decryptedData = decryptData(data);
                    Command command = jsonHandler.readValue(decryptedData, Command.class);
                    handleCommand(command);
                } catch (Exception e) {
                    sendOutput(new Output(OutputType.ERROR, -1, List.of(e.toString())));
                }
            }
        }).start();
    }

    private static byte[] performCipher(Cipher cipher, int mode, SecretKeySpec secretKeySpec, byte[] iv, byte[] data) throws Exception {
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(tagLength, iv);
        cipher.init(mode, secretKeySpec, gcmParameterSpec);
        return cipher.doFinal(data);
    }

    private static void incrementIV() {
        int i = 0;
        while (iv[i] == 127) {
            iv[i] = -128;
            i++;
        }
        iv[i]++;
    }

    private static String encryptData(String data) throws Exception {
        lock();
        try {
            incrementIV();
            String ivBase64 = base64Encoder.encodeToString(iv);
            byte[] encryptedData = performCipher(encryptCipher, Cipher.ENCRYPT_MODE, secretKeySpec, iv, data.getBytes());
            return ivBase64 + OUTPUT_PARTITIONER + base64Encoder.encodeToString(encryptedData);
        } finally {
            unlock();
        }
    }

    private static String decryptData(String data) throws Exception {
        lock();
        try {
            String[] split = data.split(OUTPUT_PARTITIONER);
            byte[] iv = base64Decoder.decode(split[0]);
            byte[] decodedData = base64Decoder.decode(split[1]);
            return new String(performCipher(decryptCipher, Cipher.DECRYPT_MODE, secretKeySpec, iv, decodedData));
        } finally {
            unlock();
        }
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
            if (commandType == CommandType.TERMINATE) {
                if (vault != null) {
                    vault.closeVault();
                    sendOutput(new Output(OutputType.RESPONSE, command.commandId(), List.of("Vault closed.")));
                }
                shutdown.set(true);
            } else if (commandType == CommandType.OPEN) {
                if (vault != null && vault.isVaultOpen()) {
                    sendOutput(new Output(OutputType.ERROR, command.commandId(), List.of("Vault is already open.")));
                } else if (validNumberOfArguments(command, 3)) {
                    String path = args.get(0);
                    boolean create = Boolean.parseBoolean(args.get(1));
                    char[] password = args.get(2).toCharArray();
                    try {
                        vault = new Vault(path, create, password, new DependentMode(), false);
                        sendOutput(new Output(OutputType.RESPONSE, command.commandId(), List.of(Boolean.toString(true))));
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
                            vault.putFile(from, to);
                        }
                    }
                    case GET_FILE -> {
                        if (validNumberOfArguments(command, 2)) {
                            Path from = Path.of(args.getFirst());
                            Path to = Path.of(args.get(1));
                            vault.getFile(from, to);
                        }
                    }
                    case GET_FILES_LIST -> {
                        if (validNumberOfArguments(command, 1)) {
                            try {
                                Path path = Path.of(args.getFirst());
                                sendOutput(new Output(OutputType.RESPONSE, command.commandId(), vault.getFilesList(path)));
                            } catch (Exception e) {
                                sendInvalidCommandInfo(command);
                            }
                        }
                    }
                    case CHANGE_FILE_NAME -> {
                        sendOutput(new Output(OutputType.ERROR, command.commandId(), List.of("Feature not supported yet.")));/*
                        if (validNumberOfArguments(command, 2)) {
                            Path from = Path.of(args.getFirst());
                            String newName = args.get(1);
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId(), List.of(Boolean.toString(vault.changeFileName(from, newName)))));
                        }*/
                    }
                    case DELETE_FILE -> {
                        if (validNumberOfArguments(command, 1)) {
                            Path path = Path.of(args.getFirst());
                            vault.deleteFile(path);
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
                        if (validNumberOfArguments(command, 3)) {
                            WebsiteIdPair websiteIdPair = new WebsiteIdPair(args.getFirst(), args.get(1));
                            String value = args.get(2);
                            vault.addKey(websiteIdPair, value, KeyType.PASSWORD);
                        }
                    }
                    case GET_PASSWORD -> {
                        if (validNumberOfArguments(command, 2)) {
                            WebsiteIdPair websiteIdPair = new WebsiteIdPair(args.getFirst(), args.get(1));
                            String response = vault.getKeyValue(websiteIdPair, KeyType.PASSWORD);
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId(), List.of(response)));
                        }
                    }
                    case DELETE_PASSWORD -> {
                        if (validNumberOfArguments(command, 2)) {
                            WebsiteIdPair websiteIdPair = new WebsiteIdPair(args.getFirst(), args.get(1));
                            vault.deleteKey(websiteIdPair, KeyType.PASSWORD);
                        }
                    }
                    case SEARCH_PASSWORD -> {
                        if (validNumberOfArguments(command, 2)) {
                            WebsiteIdPair websiteIdPair = new WebsiteIdPair(args.getFirst(), args.get(1));
                            List<WebsiteIdPair> result = vault.searchKey(websiteIdPair, KeyType.PASSWORD);
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId(), result.stream().map(WebsiteIdPair::convertToJSON).toList()));
                        }
                    }
                    case DELETE_ALL_PASSWORDS -> vault.clearKeys(KeyType.PASSWORD);
                    case GET_ALL_PASSWORDS ->
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId, vault.getAllKeys(KeyType.PASSWORD).stream().map(WebsiteIdPair::convertToJSON).toList()));
                    case PUT_API_KEY -> {
                        if (validNumberOfArguments(command, 3)) {
                            WebsiteIdPair websiteIdPair = new WebsiteIdPair(args.getFirst(), args.get(1));
                            String value = args.get(2);
                            vault.addKey(websiteIdPair, value, KeyType.API_KEY);
                        }
                    }
                    case GET_API_KEY -> {
                        if (validNumberOfArguments(command, 2)) {
                            WebsiteIdPair websiteIdPair = new WebsiteIdPair(args.getFirst(), args.get(1));
                            String response = vault.getKeyValue(websiteIdPair, KeyType.API_KEY);
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId(), List.of(response)));
                        }
                    }
                    case DELETE_API_KEY -> {
                        if (validNumberOfArguments(command, 2)) {
                            WebsiteIdPair websiteIdPair = new WebsiteIdPair(args.getFirst(), args.get(1));
                            vault.deleteKey(websiteIdPair, KeyType.API_KEY);
                        }
                    }
                    case SEARCH_API_KEY -> {
                        if (validNumberOfArguments(command, 2)) {
                            WebsiteIdPair websiteIdPair = new WebsiteIdPair(args.getFirst(), args.get(1));
                            List<WebsiteIdPair> result = vault.searchKey(websiteIdPair, KeyType.API_KEY);
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId(), result.stream().map(WebsiteIdPair::convertToJSON).toList()));
                        }
                    }
                    case DELETE_ALL_API_KEYS -> vault.clearKeys(KeyType.API_KEY);
                    case GET_ALL_API_KEYS ->
                            sendOutput(new Output(OutputType.RESPONSE, command.commandId, vault.getAllKeys(KeyType.API_KEY).stream().map(WebsiteIdPair::convertToJSON).toList()));
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
        } catch (Exception y) {
            directlyPrintError(y.getMessage());
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
    public String askForResponse(String query, List<String> options) {
        int id = responseId.getAndIncrement();
        List<String> list = new LinkedList<>();
        list.add(Integer.toString(id));
        list.add(query);
        list.addAll(options);
        ResponseHandler responseHandler = registerResponseHandler(id);
        sendOutput(new Output(OutputType.QUERY, -1, list));
        return responseHandler.getResponse();
    }

    @Override
    public void fileAdded(String fileName) {
        sendOutput(new Output(OutputType.UPDATE_FILE_ADDED, 0, List.of(fileName)));
    }

    @Override
    public void fileTransferFailed(String filePath) {
        sendOutput(new Output(OutputType.UPDATE_FILE_TRANSFER_FAILED, 0, List.of(filePath)));
    }

    record Command(CommandType type, int commandId, List<String> args) {
    }

    record Output(OutputType type, int commandId, List<String> args) {
    }

    static class ResponseHandler {
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
}

