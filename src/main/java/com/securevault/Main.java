package com.securevault;

public class Main {
    static void main() throws Exception{
        String password = "Hello";
        //try (Vault vault = new Vault(System.getProperty("user.dir"), true, password.toCharArray())) {
        try (Vault vault = new Vault(System.getProperty("user.dir") + "/Secure Vault/vault.zip", false, password.toCharArray())) {
            //ConfigurationManager configurationManager = new ConfigurationManager(null, true, null);
            //IO.println(CipherManager.getCipher("Hello".toCharArray(), new byte[]{1, 2, 3, 4, 5}, new byte[]{1, 2, 3, 4, 5, 65, 9}, true));
            //Logger.clearLogs();
            IO.println("Logs :\n" + Logger.getLogs(100));
            vault.closeVault();
        } catch (Exception e) {
            throw e;
        }
        //ObjectMapper objectMapper = new ObjectMapper();
        //hello h = objectMapper.readValue("{\"id\":\"9\"}", hello.class);
        //IO.println(h.id);
        //IO.println(objectMapper.writeValueAsString(h));
    }

   /* static class hello {
        private int id;

        public void setId(int id) {
            this.id = id;
        }

        public int getId() {
            return id;
        }
    }*/
}
