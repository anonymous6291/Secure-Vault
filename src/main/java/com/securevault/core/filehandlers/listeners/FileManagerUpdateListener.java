package com.securevault.core.filehandlers.listeners;

import com.securevault.core.filehandlers.FileTransferMonitor;

import java.util.List;

public interface FileManagerUpdateListener {

    void setFileTransferMonitor(FileTransferMonitor fileTransferMonitor);

    String askForResponse(String query, List<String> options);

    void newUpdate(String update);
}
