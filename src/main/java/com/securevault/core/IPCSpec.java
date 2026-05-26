package com.securevault.core;

public record IPCSpec(int iterations, int keyLength, int tagLength, int ivLength, String password, String salt) {
}
