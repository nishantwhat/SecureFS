package com.securefs.core.interfaces;

import com.securefs.core.exception.DeletionException;
import com.securefs.core.model.DeletionResult;

import java.nio.file.Path;

/**
 * Defines the contract for secure file deletion strategies.
 *
 * The current implementation performs a single-pass random overwrite.
 * This interface allows for alternative strategies (e.g., multi-pass,
 * or platform-specific secure erase commands) to be added later.
 */
public interface SecureDeletionStrategy {

    /**
     * Deletes the target file, optionally overwriting its contents first.
     *
     * @param target path to the file to be deleted
     * @return DeletionResult describing what was done and the confidence level
     * @throws DeletionException if the file cannot be read, overwritten, or deleted
     */
    DeletionResult delete(Path target) throws DeletionException;
}