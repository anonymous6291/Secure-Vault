package com.securevault.core.filehandlers;

import java.nio.file.Path;
import java.util.Map;

public record FileTransferData(Path from, Path to, FileTransferMode mode, Map<String, String> notes) {
}
