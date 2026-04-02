package com.securefs.cli.commands;

import com.securefs.factory.SecureFileSystemFactory;
import com.securefs.profile.HashAlgorithm;
import com.securefs.service.FileHashService;

import java.nio.file.Path;

/**
 * Handles the "verify" CLI command.
 * Compares a file's actual digest against an expected value.
 * Exits with code 0 on match, 2 on mismatch.
 */
public class VerifyCommand {

    public void execute(String filePath, String expectedHex, String algorithmName) {
        HashAlgorithm algorithm;
        try {
            algorithm = HashAlgorithm.valueOf(algorithmName.toUpperCase());
        } catch (IllegalArgumentException e) {
            System.err.println("Error: Unknown algorithm '" + algorithmName + "'.");
            System.exit(1);
            return;
        }

        FileHashService service = SecureFileSystemFactory.createHashService(algorithm);

        try {
            boolean matches = service.verifyFile(Path.of(filePath), expectedHex);
            if (matches) {
                System.out.println("VERIFIED: Digest matches.");
                System.out.println("file:     " + filePath);
                System.out.println("digest:   " + expectedHex);
            } else {
                System.err.println("FAILED: Digest does not match.");
                System.err.println("file:     " + filePath);
                System.err.println("expected: " + expectedHex);
                System.exit(2);
            }
        } catch (Exception e) {
            System.err.println("Verification failed: " + e.getMessage());
            System.exit(3);
        }
    }
}