package com.securefs.core.model;

import java.nio.file.Path;

/**
 * Carries the result of a file encryption operation.
 *
 * The salt is included here so callers (e.g., a future UI)
 * can display or log it for audit purposes without needing
 * to parse the output file.
 *
 * The salt is NOT secret — it is stored in the encrypted file.
 */
public final class EncryptionResult {

    private final Path outputPath;
    private final String profileName;
    private final String algorithmIdentifier;

    public EncryptionResult(Path outputPath, String profileName, String algorithmIdentifier) {
        this.outputPath = outputPath;
        this.profileName = profileName;
        this.algorithmIdentifier = algorithmIdentifier;
    }

    public Path getOutputPath() {
        return outputPath;
    }

    public String getProfileName() {
        return profileName;
    }

    public String getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }
}