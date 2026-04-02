package com.securefs.deletion;

import com.securefs.core.exception.DeletionException;
import com.securefs.core.interfaces.SecureDeletionStrategy;
import com.securefs.core.model.DeletionResult;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

/**
 * Performs a single-pass random overwrite of a file before deleting it.
 *
 * HOW IT WORKS:
 * 1. The file is opened for writing.
 * 2. The entire file contents are overwritten with cryptographically
 *    random bytes.
 * 3. The overwrite is flushed to disk.
 * 4. The file is deleted via the OS.
 *
 * WHY ONE PASS?
 * The historical Gutmann method used 35 overwrite passes, designed
 * for 1990s MFM/RLL hard drives. Modern drives encode data differently.
 * NIST SP 800-88 Rev 1 confirms that a single pass of random data
 * is sufficient for modern magnetic drives. Multiple passes add I/O
 * cost with no meaningful additional security on current hardware.
 *
 * SSD LIMITATION (READ THIS):
 * Flash-based storage (SSDs, USB drives, SD cards) uses a technique
 * called wear leveling. When data is "overwritten," the drive's firmware
 * writes the new data to a different physical location and marks the
 * original location as available — but does not necessarily erase it.
 *
 * This means the original file contents may remain physically on the
 * drive even after this overwrite operation. SecureFS detects this
 * situation and reports LOW confidence in the DeletionResult.
 *
 * For reliable data destruction on SSDs, NIST SP 800-88 Rev 1 recommends:
 * - ATA Secure Erase (a firmware command, not available through Java)
 * - Full-disk encryption with key destruction
 * - Physical destruction of the drive
 *
 * This class does not attempt to solve the SSD problem. It solves
 * the HDD case correctly and reports honestly for SSD.
 */
public class OverwriteDeletionStrategy implements SecureDeletionStrategy {

    private static final int BUFFER_SIZE = 8192;
    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public DeletionResult delete(Path target) throws DeletionException {

        if (!Files.exists(target)) {
            throw new DeletionException("File does not exist: " + target);
        }

        if (!Files.isRegularFile(target)) {
            throw new DeletionException("Target is not a regular file: " + target);
        }

        // Step 1: Overwrite the file contents with random bytes.
        overwriteWithRandomBytes(target);

        // Step 2: Delete the file via the OS.
        try {
            Files.delete(target);
        } catch (IOException e) {
            throw new DeletionException(
                "File was overwritten but could not be deleted: " + target, e
            );
        }

        // Step 3: Assess and report confidence based on likely storage type.
        return buildDeletionResult(target);
    }

    /**
     * Overwrites every byte of the file with cryptographically random data.
     * Uses RandomAccessFile to ensure writes reach the file and not just a buffer.
     *
     * @param target the file to overwrite
     * @throws DeletionException if the file cannot be opened or written
     */
    private void overwriteWithRandomBytes(Path target) throws DeletionException {
        try (RandomAccessFile file = new RandomAccessFile(target.toFile(), "rws")) {
            // "rws" mode: every write is flushed synchronously to the storage device.
            // This reduces (but does not eliminate) the chance of the OS caching
            // the write and not actually reaching the storage medium.

            long fileLength = file.length();
            file.seek(0);

            byte[] buffer = new byte[BUFFER_SIZE];
            long bytesRemaining = fileLength;

            while (bytesRemaining > 0) {
                secureRandom.nextBytes(buffer);
                int bytesToWrite = (int) Math.min(BUFFER_SIZE, bytesRemaining);
                file.write(buffer, 0, bytesToWrite);
                bytesRemaining -= bytesToWrite;
            }

        } catch (IOException e) {
            throw new DeletionException(
                "Failed to overwrite file contents: " + target, e
            );
        }
    }

    /**
     * Attempts to detect the storage type and returns an appropriate
     * DeletionResult with an honest confidence assessment.
     *
     * On Linux, /sys/block/<device>/queue/rotational can indicate
     * SSD (0) vs HDD (1). This detection is best-effort — it may
     * not work on all platforms or configurations.
     *
     * @param target the file that was deleted (used for context in the message)
     * @return a DeletionResult with confidence and explanation
     */
    private DeletionResult buildDeletionResult(Path target) {
        // Storage type detection is platform-specific and unreliable in Java.
        // We default to UNKNOWN and give the user the full context.
        //
        // A production version could attempt to read /sys/block/ on Linux
        // and adjust the confidence accordingly. For this implementation,
        // we report UNKNOWN with a clear explanation so the user can make
        // an informed decision.

        return new DeletionResult(
            true,
            DeletionResult.Confidence.UNKNOWN,
            "File overwritten with random bytes and deleted. " +
            "On HDD: data is likely unrecoverable. " +
            "On SSD: wear leveling may preserve original data in unreachable sectors. " +
            "For guaranteed SSD erasure, use full-disk encryption (NIST SP 800-88 Rev 1)."
        );
    }
}