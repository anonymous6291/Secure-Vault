package com.securevault;

import com.securevault.filehandlers.FileTransferMonitor;
import com.securevault.filehandlers.listeners.FileManagerUpdateListener;

import java.nio.file.Path;
import java.util.List;

public class Main {
    static void main() throws Exception {
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
                    case "cl" -> Logger.clearLogs();
                    case "l" -> IO.println(Logger.getLogs(200));
                }
            } catch (Exception e) {
                IO.println(e);
            }
        }
        vault.closeVault();
    }
}
