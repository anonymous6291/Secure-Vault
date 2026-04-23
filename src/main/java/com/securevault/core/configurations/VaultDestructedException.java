package com.securevault.core.configurations;

class VaultDestructedException extends RuntimeException {
    VaultDestructedException() {
        super("Vault is destructed.");
    }
}
