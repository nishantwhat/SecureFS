package com.securefs.service;

import com.securefs.core.exception.DeletionException;
import com.securefs.core.interfaces.SecureDeletionStrategy;
import com.securefs.core.model.DeletionResult;

import java.nio.file.Path;

/**
 * Provides the secure and normal file deletion operations.
 *
 * The service layer sits between the CLI and the deletion strategy.
 * The CLI calls this service. The service decides whether to use the
 * secure overwrite strategy or a plain OS delete based on the mode.
 */
public class SecureDeletionService {

    /**
     * Controls whether deletion uses overwrite or plain OS delete.
     */
    public enum DeletionMode {
        /** Overwrites file contents before deletion. Effective on HDD. */
        SECURE,
        /** Issues a plain OS delete call with no overwriting. Fast but recoverable. */
        NORMAL,
        /** Change the file name to something random*/
        /** Empty the file instantly*/
        /**  Fill it with random junk*/
        /** Delete it*/
        SMART
    }
    private final SecureDeletionStrategy secureStrategy;
    private final SecureDeletionStrategy smartStrategy;

    public SecureDeletionService(
            SecureDeletionStrategy secureStrategy,
            SecureDeletionStrategy smartStrategy
    ) {
        this.secureStrategy = secureStrategy;
        this.smartStrategy = smartStrategy;
    }
    // private final SecureDeletionStrategy secureDeletionStrategy;

    // public SecureDeletionService(SecureDeletionStrategy secureDeletionStrategy) {
    //     this.secureDeletionStrategy = secureDeletionStrategy;
    // }

    /**
     * Deletes a file using the specified mode.
     *
     * SECURE mode: overwrites with random bytes, then deletes.
     * NORMAL mode: plain OS delete. Data may be recoverable.
     *
     * @param target the file to delete
     * @param mode   the deletion mode
     * @return DeletionResult with outcome and confidence level
     * @throws DeletionException if deletion fails
     */
    public DeletionResult deleteFile(Path target, DeletionMode mode) throws DeletionException {
        return switch (mode) {
            case SECURE -> secureStrategy.delete(target);
            case SMART -> smartStrategy.delete(target);
            case NORMAL -> normalDelete(target);
        };
    }

    private DeletionResult normalDelete(Path target) throws DeletionException {
        try {
            java.nio.file.Files.delete(target);
            return new DeletionResult(
                true,
                DeletionResult.Confidence.LOW,
                "File deleted using OS delete. No overwrite performed. " +
                "Data may be recoverable with forensic tools."
            );
        } catch (java.io.IOException e) {
            throw new DeletionException("Could not delete file: " + target, e);
        }
    }
}