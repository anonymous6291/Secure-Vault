package com.securevault.core.filehandlers;

import java.nio.file.Path;

public class FileData {
    private final String maskedName;
    private String originalName;
    private String filePath;

    public FileData(String originalName, String maskedName, String filePath) {
        this.originalName = originalName;
        this.maskedName = maskedName;
        this.filePath = filePath;
    }

    public String getOriginalName() {
        return originalName;
    }

    public void setOriginalName(String newOriginalName) {
        this.originalName = newOriginalName;
    }

    public String getMaskedName() {
        return maskedName;
    }

    public Path getFilePath() {
        return Path.of(filePath);
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public Path getOriginalFilePath() {
        return Path.of(filePath, originalName);
    }

    public Path getMaskedFilePath() {
        return Path.of(filePath, maskedName);
    }
}
