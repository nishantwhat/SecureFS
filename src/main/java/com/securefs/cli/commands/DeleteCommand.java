package com.securefs.cli.commands;

import com.securefs.core.model.DeletionResult;
import com.securefs.factory.SecureFileSystemFactory;
import com.securefs.service.SecureDeletionService;

import java.nio.file.Path;

/**
 * Handles the "delete" CLI command.
 * Always prints the confidence level result — especially for SSD.
 */
public class DeleteCommand {

    public void execute(String filePath, String modeName) {
        SecureDeletionService.DeletionMode mode;
        try {
            mode = SecureDeletionService.DeletionMode.valueOf(modeName.toUpperCase());
        } catch (IllegalArgumentException e) {
            System.err.println("Error: Unknown mode '" + modeName + "'. " +
                               "Valid options: SECURE, NORMAL");
            System.exit(1);
            return;
        }

        if (mode == SecureDeletionService.DeletionMode.NORMAL) {
            System.err.println("Warning: NORMAL mode does not overwrite file contents. " +
                               "Data may be recoverable with forensic tools.");
        }

        SecureDeletionService service = SecureFileSystemFactory.createDeletionService();

        try {
            DeletionResult result = service.deleteFile(Path.of(filePath), mode);
            System.out.println("Deleted:    " + filePath);
            System.out.println("Confidence: " + result.getConfidence());
            System.out.println("Note:       " + result.getExplanation());
        } catch (Exception e) {
            System.err.println("Deletion failed: " + e.getMessage());
            System.exit(3);
        }
    }
}