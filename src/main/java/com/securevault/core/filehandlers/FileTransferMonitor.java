package com.securevault.core.filehandlers;

import java.util.List;

public interface FileTransferMonitor {
    int getNumberOfPendingFileTransfers();

    int getNumberOfFailedFileTransfers();

    List<String> getFailedFileTransfersList();

    double getFileTransferProgress();
}