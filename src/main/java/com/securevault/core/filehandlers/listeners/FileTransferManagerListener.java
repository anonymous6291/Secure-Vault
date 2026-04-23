package com.securevault.core.filehandlers.listeners;

import com.securevault.core.filehandlers.FileTransferData;

public interface FileTransferManagerListener {
    void fileTransferCompleted(FileTransferData fileTransferData);

    void fileTransferFailed(FileTransferData fileTransferData);
}