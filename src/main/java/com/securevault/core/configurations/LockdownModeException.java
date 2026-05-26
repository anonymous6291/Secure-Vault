package com.securevault.core.configurations;

class LockdownModeException extends RuntimeException {
    LockdownModeException(String message) {
        super(message);
    }
}
