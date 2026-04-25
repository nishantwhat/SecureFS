package com.securefs.factory;

import com.securefs.crypto.AesGcmEncryptionStrategy;
import com.securefs.crypto.Pbkdf2KeyDerivationService;
import com.securefs.deletion.OverwriteDeletionStrategy;
import com.securefs.hash.Sha256HashingStrategy;
import com.securefs.hash.Sha3256HashingStrategy;
import com.securefs.profile.HashAlgorithm;
import com.securefs.service.FileEncryptionService;
import com.securefs.service.FileHashService;
import com.securefs.service.SecureDeletionService;

import java.security.SecureRandom;

/**
 * Builds fully wired service instances with correct dependencies.
 *
 * This is the only place in the system where concrete implementations
 * are instantiated and connected. All other code depends on interfaces.
 *
 * WHY A FACTORY?
 * Without this, every caller would need to know about
 * AesGcmEncryptionStrategy, Pbkdf2KeyDerivationService, etc.
 * The factory hides those details. A caller asks for an
 * "encryption service" and gets a ready-to-use instance.
 *
 * UI INTEGRATION NOTE:
 * A future UI creates services by calling these factory methods.
 * No cryptographic class names appear in the UI code.
 */
public class SecureFileSystemFactory {

    // Shared SecureRandom — safe to reuse across calls.
    // SecureRandom is thread-safe and expensive to initialize.
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Creates a FileEncryptionService wired with AES-256-GCM and PBKDF2.
     *
     * @return a ready-to-use FileEncryptionService
     */
    public static FileEncryptionService createEncryptionService() {
        return new FileEncryptionService(
            new AesGcmEncryptionStrategy(),
            new Pbkdf2KeyDerivationService(),
            SECURE_RANDOM
        );
    }

    /**
     * Creates a FileHashService using the algorithm matching the given HashAlgorithm.
     *
     * @param algorithm the hashing algorithm to use
     * @return a ready-to-use FileHashService
     */
    public static FileHashService createHashService(HashAlgorithm algorithm) {
        return switch (algorithm) {
            case SHA256 -> new FileHashService(new Sha256HashingStrategy());
            case SHA3_256 -> new FileHashService(new Sha3256HashingStrategy());
        };
    }

    /**
     * Creates a SecureDeletionService wired with the overwrite strategy.
     *
     * @return a ready-to-use SecureDeletionService
     */
    public static SecureDeletionService createDeletionService() {
        return new SecureDeletionService(
            new OverwriteDeletionStrategy(),
            new com.securefs.deletion.SmartDeletionStrategy()
        );
    }
}