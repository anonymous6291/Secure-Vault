package com.securevault;

public class Main {
    static void main() throws Exception {
        String password = "WORLD";
        String password1 = "Hello";
        //Vault vault = new Vault(System.getProperty("user.dir"), true, password.toCharArray());
        Vault vault = new Vault(System.getProperty("user.dir") + "/Secure Vault", false, password.toCharArray());
        //Logger.clearLogs();
        //vault.changeVaultKey(password.toCharArray(), password1.toCharArray());
        IO.println("Logs :\n" + Logger.getLogs(100));
        vault.closeVault();
    }
}
