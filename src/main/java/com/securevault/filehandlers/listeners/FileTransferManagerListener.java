package com.securevault.filehandlers.listeners;

import com.securevault.filehandlers.FileTransferData;

public interface FileTransferManagerListener {
    void fileTransferCompleted(FileTransferData fileTransferData);

    void fileTransferFailed(FileTransferData fileTransferData);
}