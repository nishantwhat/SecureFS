package com.securefs.cli.commands;

import com.securefs.factory.SecureFileSystemFactory;
import com.securefs.profile.SecurityProfile;
import com.securefs.service.FileEncryptionService;
import com.securefs.core.model.EncryptionResult;

import java.io.Console;
import java.nio.file.Path;

/**
 * Handles the "encrypt" CLI command.
 *
 * Responsibilities of this class:
 * - Read and validate arguments
 * - Prompt for password securely
 * - Delegate to FileEncryptionService
 * - Print the result or error
 *
 * This class contains ZERO cryptographic logic.
 * All security operations happen in the service and engine layers.
 */
public class EncryptCommand {

    /**
     * Executes the encrypt command.
     *
     * @param inputPath   path to the file to encrypt
     * @param outputPath  path for the encrypted output
     * @param profileName name of the security profile (STANDARD, HIGH, PARANOID)
     */
    public void execute(String inputPath, String outputPath, String profileName) {
        SecurityProfile profile;
        try {
            profile = SecurityProfile.valueOf(profileName.toUpperCase());
        } catch (IllegalArgumentException e) {
            System.err.println("Error: Unknown profile '" + profileName + "'. " +
                               "Valid options: STANDARD, HIGH, PARANOID");
            System.exit(1);
            return;
        }

        // Prompt for password using Console, which does not echo characters.
        // IMPORTANT: We never accept passwords as CLI arguments.
        // CLI arguments are visible in shell history and process listings.
        Console console = System.console();
        if (console == null) {
            System.err.println("Error: No interactive terminal available. " +
                               "Cannot securely prompt for password.");
            System.exit(1);
            return;
        }

        char[] password = console.readPassword("Enter password: ");
        if (password == null || password.length == 0) {
            System.err.println("Error: Password cannot be empty.");
            System.exit(1);
            return;
        }

        System.out.println("Encrypting with profile: " + profile.name());
        System.out.println(profile.getDescription());

        FileEncryptionService service = SecureFileSystemFactory.createEncryptionService();

        try {
            EncryptionResult result = service.encryptFile(
                Path.of(inputPath),
                Path.of(outputPath),
                password,
                profile
            );
            System.out.println("Encryption successful.");
            System.out.println("Output:    " + result.getOutputPath());
            System.out.println("Profile:   " + result.getProfileName());
            System.out.println("Algorithm: " + result.getAlgorithmIdentifier());
        } catch (Exception e) {
            System.err.println("Encryption failed: " + e.getMessage());
            System.exit(2);
        }
    }
}