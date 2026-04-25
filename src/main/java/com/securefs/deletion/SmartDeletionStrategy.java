package com.securefs.deletion;

import com.securefs.core.exception.DeletionException;
import com.securefs.core.interfaces.SecureDeletionStrategy;
import com.securefs.core.model.DeletionResult;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.UUID;

/**
 * SMART deletion strategy:
 *
 * Steps:
 * 1. Rename file to random UUID (metadata obfuscation)
 * 2. Truncate file to 0 (pre-zeroization / structure destruction)
 * 3. Re-expand to original length
 * 4. Overwrite with random bytes
 * 5. Delete
 *
 * This improves resistance against:
 * - filename-based forensic recovery
 * - structure-based recovery tools
 *
 * DOES NOT solve SSD wear-leveling limitations.
 */
public class SmartDeletionStrategy implements SecureDeletionStrategy {

    private static final int BUFFER_SIZE = 8192;
    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public DeletionResult delete(Path target) throws DeletionException {

        validate(target);

        Path randomized = renameToRandom(target);

        long originalLength = getFileLength(randomized);

        overwriteWithPreZeroization(randomized, originalLength);

        deleteFile(randomized);

        return buildResult();
    }

    private void validate(Path target) throws DeletionException {
        if (!Files.exists(target)) {
            throw new DeletionException("File does not exist: " + target);
        }
        if (!Files.isRegularFile(target)) {
            throw new DeletionException("Target is not a regular file: " + target);
        }
    }

    private Path renameToRandom(Path target) throws DeletionException {
        try {
            Path randomized = target.resolveSibling(UUID.randomUUID().toString());

            try {
                return Files.move(target, randomized, StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException e) {
                // Fallback if atomic move not supported
                return Files.move(target, randomized);
            }

        } catch (IOException e) {
            throw new DeletionException("Failed to rename file for smart deletion: " + target, e);
        }
    }

    private long getFileLength(Path file) throws DeletionException {
        try {
            return Files.size(file);
        } catch (IOException e) {
            throw new DeletionException("Failed to read file size: " + file, e);
        }
    }

    private void overwriteWithPreZeroization(Path file, long originalLength)
            throws DeletionException {

        try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "rws")) {

            // Step 1: truncate (pre-zeroization)
            raf.setLength(0);

            // Step 2: re-expand
            raf.setLength(originalLength);
            raf.seek(0);

            // Step 3: overwrite with random bytes
            byte[] buffer = new byte[BUFFER_SIZE];
            long remaining = originalLength;

            while (remaining > 0) {
                secureRandom.nextBytes(buffer);
                int toWrite = (int) Math.min(BUFFER_SIZE, remaining);
                raf.write(buffer, 0, toWrite);
                remaining -= toWrite;
            }

        } catch (IOException e) {
            throw new DeletionException("Failed during smart overwrite: " + file, e);
        }
    }

    private void deleteFile(Path file) throws DeletionException {
        try {
            Files.delete(file);
        } catch (IOException e) {
            throw new DeletionException("File overwritten but could not be deleted: " + file, e);
        }
    }

    private DeletionResult buildResult() {
        return new DeletionResult(
            true,
            DeletionResult.Confidence.UNKNOWN,
            "Smart deletion applied: filename randomized, file truncated, overwritten, and deleted. " +
            "On HDD: strong protection. On SSD: wear leveling may retain data. " +
            "For guaranteed SSD erasure, use full-disk encryption (NIST SP 800-88 Rev 1)."
        );
    }
}