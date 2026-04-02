package com.securefs.cli.commands;

import com.securefs.factory.SecureFileSystemFactory;
import com.securefs.service.FileEncryptionService;

import java.io.Console;
import java.nio.file.Path;

/**
 * Handles the "decrypt" CLI command.
 *
 * Note: no --profile argument here. The profile is embedded in
 * the encrypted file and read automatically. The user provides
 * only the input file, output path, and password.
 */
public class DecryptCommand {

    public void execute(String inputPath, String outputPath) {
        Console console = System.console();
        if (console == null) {
            System.err.println("Error: No interactive terminal available.");
            System.exit(1);
            return;
        }

        char[] password = console.readPassword("Enter password: ");
        if (password == null || password.length == 0) {
            System.err.println("Error: Password cannot be empty.");
            System.exit(1);
            return;
        }

        FileEncryptionService service = SecureFileSystemFactory.createEncryptionService();

        try {
            service.decryptFile(
                Path.of(inputPath),
                Path.of(outputPath),
                password
            );
            System.out.println("Decryption successful.");
            System.out.println("Output: " + outputPath);
        } catch (Exception e) {
            System.err.println("Decryption failed: " + e.getMessage());
            System.exit(2);
        }
    }
}