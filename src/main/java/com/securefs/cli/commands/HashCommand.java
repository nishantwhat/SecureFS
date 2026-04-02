package com.securefs.cli.commands;

import com.securefs.core.model.HashResult;
import com.securefs.factory.SecureFileSystemFactory;
import com.securefs.profile.HashAlgorithm;
import com.securefs.service.FileHashService;

import java.nio.file.Path;

/**
 * Handles the "hash" CLI command.
 * Prints the digest of a file to standard output.
 */
public class HashCommand {

    public void execute(String filePath, String algorithmName) {
        HashAlgorithm algorithm;
        try {
            algorithm = HashAlgorithm.valueOf(algorithmName.toUpperCase());
        } catch (IllegalArgumentException e) {
            System.err.println("Error: Unknown algorithm '" + algorithmName + "'. " +
                               "Valid options: SHA256, SHA3_256");
            System.exit(1);
            return;
        }

        FileHashService service = SecureFileSystemFactory.createHashService(algorithm);

        try {
            HashResult result = service.hashFile(Path.of(filePath));
            System.out.println("file:      " + filePath);
            System.out.println("algorithm: " + result.getAlgorithmName());
            System.out.println("digest:    " + result.getDigestHex());
            System.out.printf ("bytes:     %,d%n", result.getBytesProcessed());
        } catch (Exception e) {
            System.err.println("Hashing failed: " + e.getMessage());
            System.exit(3);
        }
    }
}