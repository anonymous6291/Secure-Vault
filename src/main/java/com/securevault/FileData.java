package com.securevault;

public class FileData {
    private String originalName;
    private final String maskedName;
    private final long fileLength;
    private String filePath;

    FileData(String originalName, String maskedName, long fileLength, String filePath) {
        this.originalName = originalName;
        this.maskedName = maskedName;
        this.fileLength = fileLength;
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

    public long getFileLength() {
        return fileLength;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }
}
